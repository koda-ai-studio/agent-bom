"""MCP runtime proxy — intercept JSON-RPC between client and server.

A stdio proxy that sits between an MCP client (Claude Desktop, Cursor, etc.)
and an MCP server. It intercepts all JSON-RPC messages, logs tool call
invocations, compares actual usage against declared capabilities, and
optionally enforces security policy in real-time.

Usage:
    agent-bom proxy --no-isolate [--policy policy.json] [--log audit.jsonl] -- npx @mcp/server-filesystem /tmp
    agent-bom proxy --sandbox-image ghcr.io/acme/mcp-runtime@sha256:<digest> -- npx @mcp/server-filesystem /tmp"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
import uuid
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Mapping, Optional

import httpx

from agent_bom import proxy_audit as _proxy_audit
from agent_bom import proxy_policy as _proxy_policy
from agent_bom.agent_identity import check_identity
from agent_bom.async_stdin import create_async_stdin_reader, read_async_stdin_line
from agent_bom.langfuse_otel import set_langfuse_runtime_attributes
from agent_bom.proxy_sandbox import SandboxConfig
from agent_bom.proxy_scanner import ScanConfig, load_scan_config, scan_jsonrpc_response, scan_tool_call
from agent_bom.runtime import injection_protection as _injection_protection
from agent_bom.runtime import proxy_relay as _proxy_relay
from agent_bom.runtime import proxy_session as _proxy_session
from agent_bom.runtime.proxy_messages import (
    _MAX_MESSAGE_BYTES,
    _extract_jsonrpc_trace_meta,
    _proxy_request_headers,
    _stitch_jsonrpc_trace_meta,
    is_tools_call,
    make_error_response,
    parse_jsonrpc,
    policy_subject_from_message,
    undeclared_tool_block_reason,
)
from agent_bom.runtime.proxy_policy_cache import _gateway_policy_cache_path
from agent_bom.runtime.proxy_setup import (
    _build_audit_delivery,
    _execution_posture,
    _fire_webhook,
    _generate_proxy_source_id,
    _load_proxy_policy,
    _prepare_server_command,
    _record_relay_errors,
    _reject_tool_call,
    _response_scan_alerts,
    _start_sandbox_timeout,
)
from agent_bom.runtime.proxy_tracing import _PROXY_TRACER as _PROXY_TRACER
from agent_bom.runtime.proxy_tracing import proxy_span
from agent_bom.runtime.proxy_upstream import UpstreamResponseRejectedError, build_proxy_upstream, upstream_error_message
from agent_bom.runtime.trace_metadata import inject_jsonrpc_trace_meta as _inject_jsonrpc_trace_meta
from agent_bom.security import sanitize_text, sanitize_url

logger = logging.getLogger("agent_bom.proxy")
__all__ = ["_gateway_evaluator", "_safe_compile", "_safe_regex_match", "_safe_regex_search", "_truncate_args",
    "AuditDeliveryController", "AuditDeliveryPaths", "AuditDeliveryState", "AuditSpilloverStore", "audit_delivery_paths",
    "compute_response_hmac", "resolve_rate_limit_threshold"]  # fmt: skip


ProxyMetrics = _proxy_audit.ProxyMetrics


ProxyMetricsServer = _proxy_audit.ProxyMetricsServer


ReplayDetector = _proxy_audit.ReplayDetector


RotatingAuditLog = _proxy_audit.RotatingAuditLog


AuditDeliveryController = _proxy_audit.AuditDeliveryController


AuditDeliveryPaths = _proxy_audit.AuditDeliveryPaths


AuditDeliveryState = _proxy_audit.AuditDeliveryState


AuditSpilloverStore = _proxy_audit.AuditSpilloverStore


audit_delivery_paths = _proxy_audit.audit_delivery_paths


_truncate_args = _proxy_audit._truncate_args


compute_payload_hash = _proxy_audit.compute_payload_hash


compute_response_hmac = _proxy_audit.compute_response_hmac


log_tool_call = _proxy_audit.log_tool_call


summarize_runtime_alerts = _proxy_audit.summarize_runtime_alerts


write_audit_record = _proxy_audit.write_audit_record


_safe_compile = _proxy_policy._safe_compile


_safe_regex_match = _proxy_policy._safe_regex_match


_safe_regex_search = _proxy_policy._safe_regex_search


check_policy = _proxy_policy.check_policy


resolve_rate_limit_threshold = _proxy_policy.resolve_rate_limit_threshold


_gateway_evaluator = None  # type: ignore[var-annotated]


def set_gateway_evaluator(fn) -> None:  # noqa: ANN001
    """Register a gateway evaluator for runtime enforcement.

    The callable signature must be
    ``(agent_name: str, tool_name: str, arguments: dict) -> (allowed, reason)``
    where *allowed* is a bool.
    """
    global _gateway_evaluator
    _gateway_evaluator = fn


_firewall_evaluator = None  # type: ignore[var-annotated]


_firewall_target_id: str | None = None


def set_firewall_evaluator(fn, *, target_id: str | None = None) -> None:  # noqa: ANN001
    """Register an async inter-agent firewall evaluator.

    The callable signature must be
    ``async (source_agent: str, target_agent: str, source_roles: frozenset[str],
              target_roles: frozenset[str]) -> FirewallEvaluation``.

    `target_id` is the agent identity this proxy is wrapping (the *target*
    side of the source -> target firewall pair). When set, the proxy uses
    it for every firewall lookup; when unset, the firewall is not consulted.
    """
    global _firewall_evaluator
    global _firewall_target_id
    _firewall_evaluator = fn
    _firewall_target_id = target_id


def clear_firewall_evaluator() -> None:
    """Test/teardown helper — drop the registered evaluator."""
    global _firewall_evaluator
    global _firewall_target_id
    _firewall_evaluator = None
    _firewall_target_id = None


def _firewall_target_for_proxy() -> str | None:
    return _firewall_target_id


async def _maybe_block_on_firewall(
    *,
    source_agent: str,
    target_agent: str,
    tool_name: str,
    arguments: dict,
    log_file,  # noqa: ANN001 — proxy uses an open file handle / RotatingAuditLog
    payload_sha256: str | None,
    message_id,  # noqa: ANN001 — JSON-RPC id can be int / str / None
    tenant_id: str | None,
    metrics=None,  # noqa: ANN001 — ProxyMetrics; SSE proxy path doesn't track metrics
) -> str | None:
    """Run the registered firewall evaluator for source -> target.

    Returns:
        - the reason string when the call should be blocked (caller emits the
          JSON-RPC error response so this helper stays decision-only),
        - None when the call may proceed.

    On exception inside the evaluator the proxy fails open here. The
    `FirewallClient` already encodes the gateway fail-mode (open / closed)
    internally, so unexpected raises here are out-of-policy errors.
    """

    from agent_bom.firewall import FirewallDecision

    if _firewall_evaluator is None:
        return None
    try:
        evaluation = await _firewall_evaluator(source_agent, target_agent, frozenset(), frozenset())
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "firewall evaluator raised; allowing call (source=%s, target=%s): %s",
            source_agent,
            target_agent,
            sanitize_text(exc),
        )
        return None

    effective = evaluation.effective_decision
    if effective == FirewallDecision.ALLOW:
        return None

    matched = evaluation.matched_rule
    rule_desc = (
        f"{matched.source} -> {matched.target} ({matched.decision.value})" + (f" · {matched.description}" if matched.description else "")
        if matched is not None
        else "default"
    )

    if effective == FirewallDecision.WARN:
        if metrics is not None:
            metrics.record_blocked("firewall_warn")
        if log_file:
            log_tool_call(
                log_file,
                tool_name,
                arguments,
                "warn",
                f"firewall warn: {source_agent} -> {target_agent} [{rule_desc}]",
                payload_sha256=payload_sha256 or "",
                message_id=message_id,
                agent_id=source_agent,
                tenant_id=tenant_id or "default",
            )
        return None

    # DENY
    reason = f"firewall: {source_agent} -> {target_agent} blocked [{rule_desc}]"
    if metrics is not None:
        metrics.record_blocked("firewall")
    if log_file:
        log_tool_call(
            log_file,
            tool_name,
            arguments,
            "blocked",
            reason,
            payload_sha256=payload_sha256 or "",
            message_id=message_id,
            agent_id=source_agent,
            tenant_id=tenant_id or "default",
        )
    return reason


def _build_firewall_client(
    target_id: Optional[str],
    gateway_url: Optional[str],
    gateway_token: Optional[str],
    local_policy_path: Optional[str],
    cache_ttl_seconds: float,
    fail_mode: str,
):  # noqa: ANN201
    """Create and register the inter-agent firewall client; None when not configured.

    Active when a target id is set together with a gateway URL or a local
    policy file. The client is cache-first; the gateway is consulted on cache
    miss / TTL expiry.
    """
    if not (target_id and (gateway_url or local_policy_path)):
        return None
    from agent_bom.firewall import FirewallPolicyError, load_firewall_policy_file
    from agent_bom.firewall_client import FirewallClient, FirewallFailMode

    local_policy = None
    if local_policy_path:
        try:
            local_policy = load_firewall_policy_file(Path(local_policy_path))
        except FirewallPolicyError as exc:
            logger.error("invalid firewall policy at %s: %s", local_policy_path, sanitize_text(exc))
            raise SystemExit(1) from exc
    try:
        fw_fail_mode = FirewallFailMode(fail_mode)
    except ValueError as exc:
        raise SystemExit(f"invalid --firewall-fail-mode {fail_mode!r}") from exc
    firewall_client = FirewallClient(
        gateway_url=gateway_url,
        bearer_token=gateway_token,
        cache_ttl_seconds=max(0.0, cache_ttl_seconds),
        fail_mode=fw_fail_mode,
        local_policy=local_policy,
    )

    async def _firewall_evaluator_fn(source, target, source_roles, target_roles):
        return await firewall_client.decision(
            source_agent=source,
            target_agent=target,
            source_roles=source_roles,
            target_roles=target_roles,
        )

    set_firewall_evaluator(_firewall_evaluator_fn, target_id=target_id)
    return firewall_client


@dataclass(frozen=True)
class _SseCall:
    """One policy-gated JSON-RPC request read from the SSE proxy's client."""

    msg: dict
    tool_name: str
    arguments: dict
    is_tool_call: bool
    trace_meta: dict
    msg_id: Any
    payload_sha256: str
    agent_id: Any


def _load_sse_policy(policy_path: Optional[str]) -> Optional[dict]:
    """Return the runtime policy (empty when unset), or None when it cannot be loaded."""
    if not policy_path:
        return {}
    try:
        from agent_bom.security import SecurityError, validate_json_file

        return validate_json_file(Path(policy_path))
    except (json.JSONDecodeError, OSError, SecurityError) as exc:
        logger.error("Failed to load policy from %s: %s", policy_path, sanitize_text(exc))
        return None


def _write_stdout_message(payload: dict) -> None:
    sys.stdout.buffer.write((json.dumps(payload) + "\n").encode())
    sys.stdout.buffer.flush()


class _SseProxySession:
    """Gate client JSON-RPC from stdin, forward allowed requests, inspect responses."""

    def __init__(self, url: str, policy: dict, log_file: Any, *, block_undeclared: bool, alert_webhook: Optional[str]) -> None:
        from agent_bom.runtime.detectors import ArgumentAnalyzer, SequenceAnalyzer

        self.url = url
        self.base_url = url.rstrip("/")
        self.policy = policy
        self.log_file = log_file
        self.block_undeclared = block_undeclared
        self.alert_webhook = alert_webhook
        self.arg_analyzer = ArgumentAnalyzer()
        self.seq_analyzer = SequenceAnalyzer()
        self.replay_detector = ReplayDetector()
        self.scan_config = load_scan_config(policy) if policy else ScanConfig()
        self.tenant_id = (os.environ.get("AGENT_BOM_TENANT_ID") or "default").strip() or "default"
        self.declared_tools: set[str] = set()
        self.call_counter = 0
        self.upstream: Any = None
        self._catalog_attempted = False

    def _handle_alerts(self, alerts) -> None:  # noqa: ANN001
        for alert in alerts:
            alert_dict = alert.to_dict()
            logger.warning("Runtime alert: %s", sanitize_text(alert_dict.get("message", "runtime alert")))
            if self.log_file:
                write_audit_record(self.log_file, alert_dict)
                self.log_file.flush()
            if self.alert_webhook:
                _fire_webhook(self.alert_webhook, alert_dict)

    def _scan_response(self, response: dict, subject: str) -> dict:
        safe_response, findings = scan_jsonrpc_response(response, self.scan_config)
        self._handle_alerts(_response_scan_alerts(findings, subject))
        return safe_response

    def _reject(self, call: _SseCall, reason: str) -> None:
        _reject_tool_call(
            self.log_file,
            call.tool_name,
            call.arguments,
            reason,
            payload_sha256=call.payload_sha256,
            message_id=call.msg_id,
            agent_id=call.agent_id,
            tenant_id=self.tenant_id,
        )

    async def run(self, upstream: Any) -> None:
        self.upstream = upstream
        if upstream.discover_at_start:
            await self._discover_tools()
        reader = await create_async_stdin_reader()
        while True:
            try:
                line = await asyncio.wait_for(read_async_stdin_line(reader), timeout=120.0)
            except asyncio.TimeoutError:
                logger.debug("SSE proxy: client readline timed out")
                break
            if not line:
                break
            await self._handle_line(line)

    async def _discover_tools(self) -> None:
        self._catalog_attempted = True
        try:
            with proxy_span("proxy.sse_tools_list") as span:
                if span is not None:
                    span.set_attribute("agent_bom.proxy.upstream_url", sanitize_url(self.base_url) or "")
                catalog = await self.upstream.tool_catalog(_proxy_request_headers())
                self.declared_tools = set(catalog.names)
                if span is not None:
                    span.set_attribute("agent_bom.proxy.declared_tool_count", len(self.declared_tools))
            if not catalog.complete:
                logger.warning("SSE proxy: tools/list pagination incomplete; %d tools declared so far", len(self.declared_tools))
            logger.info("SSE proxy: discovered %d declared tools", len(self.declared_tools))
        except Exception as exc:  # noqa: BLE001
            logger.warning("SSE proxy: could not fetch tools/list from %s: %s", sanitize_url(self.url), sanitize_text(exc))

    async def _handle_line(self, line: bytes) -> None:
        if len(line) > _MAX_MESSAGE_BYTES:
            logger.warning("SSE proxy: oversized message from client (%d bytes) — dropped", len(line))
            return
        line_str = line.decode("utf-8", errors="replace")
        msg = parse_jsonrpc(line_str)
        policy_subject = policy_subject_from_message(msg) if msg else None
        if not msg or not policy_subject:
            await self._pass_through(msg, line_str)
            return
        tool_name, arguments = policy_subject
        is_tool_call = is_tools_call(msg)
        if is_tool_call and not self._catalog_attempted:
            await self._discover_tools()
        trace_meta = _extract_jsonrpc_trace_meta(msg)
        msg_id = msg.get("id")
        p_hash = compute_payload_hash(msg)
        agent_id, identity_block_reason = check_identity(msg, self.policy)
        call = _SseCall(msg, tool_name, arguments, is_tool_call, trace_meta, msg_id, p_hash, agent_id)
        await self._gate_and_forward(call, identity_block_reason)

    async def _pass_through(self, msg: Optional[dict], line_str: str) -> None:
        """Forward non-gated messages (initialize, notifications, ...) unchanged."""
        payload: Any = msg
        try:
            payload = msg or json.loads(line_str)
            response = await self.upstream.pass_through(payload, _proxy_request_headers())
            if response is not None:
                _write_stdout_message(self._scan_response(response, str((msg or {}).get("method", "unknown"))))
        except Exception as exc:  # noqa: BLE001
            logger.debug("SSE proxy: pass-through failed: %s", sanitize_text(exc))
            if self.upstream.reports_pass_through_errors and isinstance(payload, dict) and "id" in payload and "method" in payload:
                _write_stdout_message(make_error_response(payload["id"], -32603, upstream_error_message(exc)))

    async def _gate_and_forward(self, call: _SseCall, identity_block_reason: Any) -> None:
        reason = self._admission_block_reason(call, identity_block_reason)
        if reason is not None:
            self._reject(call, reason)
            return
        if await self._firewall_blocked(call):
            return
        reason = self._analysis_block_reason(call)
        if reason is not None:
            self._reject(call, reason)
            return
        if self.log_file:
            log_tool_call(
                self.log_file,
                call.tool_name,
                call.arguments,
                "allowed",
                payload_sha256=call.payload_sha256,
                message_id=call.msg_id,
                agent_id=call.agent_id,
                tenant_id=self.tenant_id,
            )  # type: ignore[arg-type]
        self.call_counter += 1
        response_data = await self._forward(call)
        if response_data is not None:
            self._emit_inspected_response(call, response_data)

    def _admission_block_reason(self, call: _SseCall, identity_block_reason: Any) -> Optional[str]:
        """Identity, replay, undeclared-tool and policy gates, in that order; None when admitted."""
        if identity_block_reason:
            return identity_block_reason
        if self.replay_detector.check(call.msg):
            return "Replayed payload detected"
        undeclared_reason = undeclared_tool_block_reason(self.block_undeclared and call.is_tool_call, self.declared_tools, call.tool_name)
        if undeclared_reason:
            return undeclared_reason
        if self.policy:
            allowed, reason = check_policy(self.policy, call.tool_name, call.arguments)
            if not allowed:
                return reason
        return None

    async def _firewall_blocked(self, call: _SseCall) -> bool:
        # Same inter-agent firewall hook as the stdio path; the SSE proxy carries no ProxyMetrics.
        fw_target_id = _firewall_target_for_proxy()
        if _firewall_evaluator is None or not fw_target_id:
            return False
        fw_outcome = await _maybe_block_on_firewall(
            source_agent=call.agent_id or "unknown",
            target_agent=fw_target_id,
            tool_name=call.tool_name,
            arguments=call.arguments,
            log_file=self.log_file,
            payload_sha256=call.payload_sha256,
            message_id=call.msg_id,
            tenant_id=self.tenant_id,
        )
        if fw_outcome is None:
            return False
        _write_stdout_message(make_error_response(call.msg_id, -32600, fw_outcome))
        return True

    def _analysis_block_reason(self, call: _SseCall) -> Optional[str]:
        """Argument, sequence and inline-content analysis; a reason only when the scanner enforces a block."""
        self._handle_alerts(self.arg_analyzer.check(call.tool_name, call.arguments))
        self._handle_alerts(self.seq_analyzer.record(call.tool_name))
        if not self.scan_config.enabled:
            return None
        from agent_bom.runtime.detectors import Alert, AlertSeverity

        s_results = scan_tool_call(call.tool_name, call.arguments, self.scan_config)
        for sr in s_results:
            alert = Alert(
                detector=f"scanner:{sr.scanner}",
                severity=AlertSeverity.CRITICAL
                if sr.severity == "critical"
                else (AlertSeverity.HIGH if sr.severity == "high" else AlertSeverity.MEDIUM),
                message=f"Inline scan: {sr.scanner}/{sr.rule_id} in tool '{call.tool_name}'",
                details={"rule_id": sr.rule_id, "excerpt": sr.excerpt, "confidence": sr.confidence},
            )
            self._handle_alerts([alert])
        if self.scan_config.mode == "enforce" and any(sr.blocked for sr in s_results):
            first = next(sr for sr in s_results if sr.blocked)
            return f"Blocked by inline scanner: {first.scanner}/{first.rule_id}"
        return None

    async def _forward(self, call: _SseCall) -> Optional[dict]:
        """POST the gated request upstream (Streamable HTTP, or /tools/call and /message in compat mode)."""
        meta = call.trace_meta
        try:
            span_name = "proxy.sse_tools_call" if call.is_tool_call else "proxy.sse_gated_message"
            with proxy_span(span_name) as span:
                if span is not None:
                    self._annotate_forward_span(span, call)
                forwarded_message = _inject_jsonrpc_trace_meta(
                    call.msg, traceparent=meta.get("traceparent"), tracestate=meta.get("tracestate"), baggage=meta.get("baggage")
                )
                headers = _proxy_request_headers(
                    traceparent=meta.get("traceparent"), tracestate=meta.get("tracestate"), baggage=meta.get("baggage")
                )
                return await self.upstream.forward(forwarded_message, headers, is_tool_call=call.is_tool_call)
        except (httpx.HTTPStatusError, UpstreamResponseRejectedError) as exc:
            logger.warning("SSE proxy: upstream failed for %s: %s", call.tool_name, sanitize_text(exc))
            _write_stdout_message(make_error_response(call.msg_id, -32603, upstream_error_message(exc)))
        except Exception as exc:  # noqa: BLE001
            logger.warning("SSE proxy: connection error for %s: %s", call.tool_name, sanitize_text(exc))
            _write_stdout_message(make_error_response(call.msg_id, -32603, "Upstream connection error"))
        return None

    def _annotate_forward_span(self, span: Any, call: _SseCall) -> None:
        method = call.msg.get("method", "unknown")
        span.set_attribute("agent_bom.proxy.subject", call.tool_name)
        span.set_attribute("agent_bom.proxy.method", method)
        span.set_attribute("agent_bom.proxy.call_counter", self.call_counter)
        set_langfuse_runtime_attributes(
            span,
            surface="proxy",
            tenant_id=self.tenant_id,
            method=str(method),
            tool_name=call.tool_name,
            decision="allowed",
            agent_id=call.agent_id,
            trace_id=str(call.trace_meta.get("trace_id") or ""),
            arguments=call.arguments,
        )

    def _emit_inspected_response(self, call: _SseCall, response_data: dict) -> None:
        resp_text = json.dumps(response_data.get("result", response_data))
        from agent_bom.runtime.detectors import CredentialLeakDetector, ResponseInspector

        self._handle_alerts(CredentialLeakDetector().check(call.tool_name, resp_text))
        self._handle_alerts(ResponseInspector().check(call.tool_name, resp_text))
        response_data = self._scan_response(response_data, call.tool_name)
        _write_stdout_message(_stitch_jsonrpc_trace_meta(response_data, call.trace_meta))


async def _proxy_sse_server(
    url: str,
    policy_path: Optional[str] = None,
    log_path: Optional[str] = None,
    block_undeclared: bool = False,
    alert_webhook: Optional[str] = None,
    compat_endpoints: bool = False,
) -> int:
    """Proxy a remote MCP server through the protection engine.

    Connects to a remote MCP server instead of spawning a subprocess.
    Messages received on stdin pass the protection engine and are POSTed to
    the server's Streamable HTTP endpoint (``url``) with the server-issued
    ``Mcp-Session-Id``; bounded JSON or SSE answers are written to stdout.

    Args:
        url: Remote MCP endpoint (the base URL with ``compat_endpoints``).
        policy_path: Optional path to a runtime policy JSON file.
        log_path: Optional path to audit JSONL log.
        block_undeclared: Block tools not in initial tools/list.
        alert_webhook: Optional webhook URL for alert notifications.
        compat_endpoints: Use legacy /tools/list, /tools/call and /message.

    Returns:
        0 on clean shutdown, 1 on connection or policy load error.
    """
    policy = _load_sse_policy(policy_path)
    if policy is None or not _injection_protection.sse_policy_supported(policy, logger):
        return 1
    log_file = RotatingAuditLog(log_path) if log_path else None
    session = _SseProxySession(url, policy, log_file, block_undeclared=block_undeclared, alert_webhook=alert_webhook)
    try:
        async with httpx.AsyncClient(timeout=30) as client, build_proxy_upstream(client, url, compat_endpoints) as upstream:
            await session.run(upstream)
    finally:
        if log_file:
            log_file.close()
    return 0


async def _reap_server(process: asyncio.subprocess.Process, *, grace_seconds: float = 1.0) -> None:
    """Allow the child watcher to observe normal exit before signaling a server.

    Stream EOF can precede the watcher callback. Signaling during that window
    races Python 3.11's waitpid ownership and can replace the real status with
    255 (CPython issue 87744). Unresponsive servers still receive TERM/KILL.
    """
    try:
        await asyncio.wait_for(process.wait(), timeout=grace_seconds)
        return
    except asyncio.TimeoutError:
        pass
    if process.returncode is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass  # The watcher still owns collecting the exit status.
    try:
        await asyncio.wait_for(process.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass  # the process already exited
        await process.wait()


async def run_proxy(
    server_cmd: list[str],
    policy_path: Optional[str] = None,
    log_path: Optional[str] = None,
    block_undeclared: bool = False,
    detect_credentials: bool = False,
    detect_visual_leaks: bool = False,
    rate_limit_threshold: int = 0,
    log_only: bool = False,
    alert_webhook: Optional[str] = None,
    metrics_port: int = 8422,
    metrics_token: Optional[str] = None,
    control_plane_url: Optional[str] = None,
    control_plane_token: Optional[str] = None,
    policy_refresh_seconds: int = 30,
    audit_push_interval: int = 10,
    response_signing_key: Optional[str] = None,
    sandbox_config: SandboxConfig | None = None,
    firewall_gateway_url: Optional[str] = None,
    firewall_gateway_token: Optional[str] = None,
    firewall_local_policy_path: Optional[str] = None,
    firewall_target_id: Optional[str] = None,
    firewall_cache_ttl_seconds: float = 60.0,
    firewall_fail_mode: str = "open",
    injection_mode: Optional[str] = None,
) -> int:
    """Main proxy loop. Spawns server subprocess, relays JSON-RPC.

    Args:
        server_cmd: Command to spawn the MCP server.
        policy_path: Path to policy JSON file.
        log_path: Path to audit JSONL log.
        block_undeclared: Block tools not in initial tools/list.
        detect_credentials: Enable credential leak detection in responses.
        detect_visual_leaks: OCR-scan image tool responses (requires the ``visual`` extra
            and tesseract on PATH; fails closed at startup without the OCR runtime).
        rate_limit_threshold: Max calls per tool per 60s (0 = disabled).
        log_only: Log alerts without blocking (advisory mode).
        alert_webhook: Optional webhook URL for runtime alert notifications.
        injection_mode: ``alert`` (default) or ``enforce``; a policy-file ``injection_mode: enforce`` also enforces.
        metrics_token: Optional bearer token for Prometheus /metrics endpoint.
        control_plane_url, control_plane_token: Optional control-plane URL and bearer/API token (policy pull, audit push).
        sandbox_config: Optional container isolation posture for stdio MCP servers.

    Returns the server process exit code.
    """
    policy: dict = _load_proxy_policy(policy_path)
    injection_mode = _injection_protection.resolve_injection_mode(injection_mode, policy, log_only=log_only)
    log_file = RotatingAuditLog(log_path) if log_path else None  # 0o600, symlink-refusing, rotates at 100 MB
    metrics, status_strip_active = _proxy_session.start_metrics(sys.modules[__name__])
    metrics_server = ProxyMetricsServer(metrics, port=metrics_port, token=metrics_token)
    await metrics_server.start()
    detectors = _proxy_session.build_detectors(
        sys.modules[__name__],
        policy,
        detect_credentials=detect_credentials,
        detect_visual_leaks=detect_visual_leaks,
        rate_limit_threshold=rate_limit_threshold,
    )
    options = _proxy_session.RelayOptions(
        block_undeclared=block_undeclared,
        log_only=log_only,
        rate_limit_threshold=rate_limit_threshold,
        alert_webhook=alert_webhook,
        response_signing_key=response_signing_key,
        policy_refresh_seconds=policy_refresh_seconds,
        injection_mode=injection_mode,
    )
    session = _compose_session(policy, log_file, metrics, detectors, options, control_plane_url, control_plane_token, audit_push_interval)
    await session.connect_control_plane()
    firewall_client = _build_firewall_client(
        firewall_target_id,
        firewall_gateway_url,
        firewall_gateway_token,
        firewall_local_policy_path,
        firewall_cache_ttl_seconds,
        firewall_fail_mode,
    )
    teardown = _SessionTeardown(status_strip_active, metrics_server, firewall_client)
    return await _supervise_session(session, server_cmd, sandbox_config, teardown)


def _compose_session(
    policy: dict,
    log_file: RotatingAuditLog | None,
    metrics: ProxyMetrics,
    detectors: _proxy_session.RuntimeDetectors,
    options: _proxy_session.RelayOptions,
    control_plane_url: str | None,
    control_plane_token: str | None,
    audit_push_interval: int,
) -> _proxy_session.ProxySession:
    scan_config = load_scan_config(policy) if policy else ScanConfig()
    source_id = _generate_proxy_source_id()
    session_id = str(uuid.uuid4())
    tenant_id = (os.environ.get("AGENT_BOM_TENANT_ID") or "default").strip() or "default"
    cache_path = _gateway_policy_cache_path()
    cache_max_age_seconds = max(60, int(os.environ.get("AGENT_BOM_PROXY_POLICY_CACHE_MAX_AGE_SECONDS", "3600")))
    audit = _build_audit_delivery(control_plane_url, tenant_id, source_id, audit_push_interval)
    control = _proxy_session.ControlPlane(
        url=control_plane_url,
        token=control_plane_token,
        tenant_id=tenant_id,
        source_id=source_id,
        session_id=session_id,
        cache_path=cache_path,
        cache_max_age_seconds=cache_max_age_seconds,
    )
    return _proxy_session.ProxySession(
        host=sys.modules[__name__],
        policy=policy,
        log_file=log_file,
        metrics=metrics,
        detectors=detectors,
        scan_config=scan_config,
        options=options,
        control=control,
        audit=audit,
    )


@dataclass
class _SessionTeardown:
    status_strip_active: bool
    metrics_server: ProxyMetricsServer
    firewall_client: Any
    tasks: tuple[asyncio.Task | None, ...] = ()


@dataclass
class _ShutdownRequest:
    """SIGTERM cancels the owning task once so the relay unwinds through teardown."""

    owner_task: asyncio.Task | None
    signal_number: int = 0

    def request(self) -> None:
        if not self.signal_number and self.owner_task is not None:
            self.signal_number = signal.SIGTERM
            self.owner_task.cancel()


async def _supervise_session(
    session: _proxy_session.ProxySession,
    server_cmd: list[str],
    sandbox_config: SandboxConfig | None,
    teardown: _SessionTeardown,
) -> int:
    """Spawn the server, run both relays until either side closes, then tear down."""
    log_file = session.log_file
    server_cmd, sandbox_evidence = _prepare_server_command(server_cmd, sandbox_config, log_file)
    process = await asyncio.create_subprocess_exec(
        *server_cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=_MAX_MESSAGE_BYTES + 1,
    )
    session.process = process
    sandbox_timeout_task = _start_sandbox_timeout(process, sandbox_config, sandbox_evidence, log_file)
    refresh_task = asyncio.create_task(session.policy_refresh_loop()) if session.control.url else None
    audit_task = asyncio.create_task(session.audit_push_loop()) if session.control.url else None
    teardown.tasks = (audit_task, refresh_task, sandbox_timeout_task)

    loop = asyncio.get_running_loop()
    shutdown = _ShutdownRequest(asyncio.current_task())
    previous_sigterm = signal.getsignal(signal.SIGTERM)
    signal_installed = False
    try:
        loop.add_signal_handler(signal.SIGTERM, shutdown.request)
        signal_installed = True
    except (NotImplementedError, RuntimeError, ValueError):
        pass  # Non-POSIX platforms and embedded non-main-thread event loops.

    try:
        results = await asyncio.gather(
            _proxy_relay.relay_client_to_server(session),
            _proxy_relay.relay_server_to_client(session),
            _proxy_relay.forward_stderr(session),
            return_exceptions=True,
        )
        _record_relay_errors(list(results), session.metrics, log_file)
    except asyncio.CancelledError:
        if not shutdown.signal_number:
            raise
    finally:
        # Reap first: slow audit delivery must not orphan an upstream on TERM.
        try:
            await _reap_server(process)
        finally:
            if signal_installed:
                loop.remove_signal_handler(signal.SIGTERM)
                signal.signal(signal.SIGTERM, previous_sigterm)
        await _close_session(session, sandbox_evidence, teardown)

    return 128 + shutdown.signal_number if shutdown.signal_number else process.returncode or 0


async def _close_session(session: _proxy_session.ProxySession, sandbox_evidence: Mapping[str, object], teardown: _SessionTeardown) -> None:
    """Write the run summary, drain audit delivery, and release every runtime hook."""
    if teardown.status_strip_active:
        sys.stderr.write("\n")
        sys.stderr.flush()
    session.catalog_refresh.close()
    summary = session.metrics.summary()
    summary.update(summarize_runtime_alerts(session.runtime_alerts))
    summary["execution_posture"] = _execution_posture(sandbox_evidence)
    for task in teardown.tasks:
        if task:
            task.cancel()
    if session.control.url:
        await session.flush_audit_buffer(summary=summary)
    if session.log_file:
        write_audit_record(session.log_file, summary)
        session.log_file.close()
    await teardown.metrics_server.stop()
    set_gateway_evaluator(None)
    clear_firewall_evaluator()
    if teardown.firewall_client is not None:
        await teardown.firewall_client.aclose()


_EXPORTS = {
    "_PROXY_POLICY_CACHE_SIGNING_ENV_VAR": "agent_bom.runtime.proxy_policy_cache",
    "_proxy_policy_cache_signing_pem": "agent_bom.runtime.proxy_policy_cache",
    "_read_bounded_line": "agent_bom.runtime.proxy_messages",
    "_POLICY_GATED_METHODS": "agent_bom.runtime.proxy_messages",
    "is_tools_list_response": "agent_bom.runtime.proxy_messages",
    "extract_tool_name": "agent_bom.runtime.proxy_messages",
    "extract_tool_arguments": "agent_bom.runtime.proxy_messages",
    "extract_declared_tools": "agent_bom.runtime.proxy_messages",
    "sandbox_posture_warning": "agent_bom.runtime.proxy_setup",
    "_command_name_for_validation": "agent_bom.runtime.proxy_setup",
    "_sanitize_for_log": "agent_bom.runtime.proxy_messages",
    "_proxy_audit_delivery_paths": "agent_bom.runtime.proxy_setup",
    "_control_plane_headers": "agent_bom.runtime.proxy_policy_cache",
    "_gateway_policy_cache_signature_path": "agent_bom.runtime.proxy_policy_cache",
    "_GatewayPolicyCacheSigner": "agent_bom.runtime.proxy_policy_cache",
    "_gateway_policy_cache_signer": "agent_bom.runtime.proxy_policy_cache",
    "_gateway_policy_cache_signer_error": "agent_bom.runtime.proxy_policy_cache",
    "_load_gateway_policy_cache_signer": "agent_bom.runtime.proxy_policy_cache",
    "_reset_gateway_policy_cache_signer_for_tests": "agent_bom.runtime.proxy_policy_cache",
    "_canonicalize_gateway_policy_cache": "agent_bom.runtime.proxy_policy_cache",
    "_load_cached_gateway_policies": "agent_bom.runtime.proxy_policy_cache",
    "_persist_gateway_policies_cache": "agent_bom.runtime.proxy_policy_cache",
    "_fetch_enabled_gateway_policies": "agent_bom.runtime.proxy_policy_cache",
    "_resolve_control_plane_rate_limit_threshold": "agent_bom.runtime.proxy_policy_cache",
    "_push_proxy_audit_batch": "agent_bom.runtime.proxy_setup",
    "_WEBHOOK_TASKS": "agent_bom.runtime.proxy_setup",
    "_send_webhook": "agent_bom.runtime.proxy_setup",
    "_write_client_error": "agent_bom.runtime.proxy_setup",
    "_ProxyAuditDelivery": "agent_bom.runtime.proxy_setup",
}


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value
