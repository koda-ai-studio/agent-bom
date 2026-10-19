"""Proxy session setup, sandbox launch and audit delivery."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import platform
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, Optional

from agent_bom.core.settings import env_raw
from agent_bom.proxy_audit import AuditDeliveryController as AuditDeliveryController
from agent_bom.proxy_audit import AuditDeliveryPaths as AuditDeliveryPaths
from agent_bom.proxy_audit import AuditDeliveryState as AuditDeliveryState
from agent_bom.proxy_audit import AuditSpilloverStore as AuditSpilloverStore
from agent_bom.proxy_audit import ProxyMetrics as ProxyMetrics
from agent_bom.proxy_audit import audit_delivery_paths as audit_delivery_paths
from agent_bom.proxy_audit import log_tool_call as log_tool_call
from agent_bom.proxy_audit import write_audit_record as write_audit_record
from agent_bom.proxy_sandbox import SandboxConfig, build_sandboxed_command
from agent_bom.runtime.proxy_messages import make_error_response
from agent_bom.runtime.proxy_policy_cache import _control_plane_headers
from agent_bom.runtime.proxy_tracing import proxy_span
from agent_bom.security import redact_secret_url, require_recognized_launcher, sanitize_sensitive_payload, sanitize_text, validate_arguments
from agent_bom.storage import state_home

logger = logging.getLogger("agent_bom.proxy")


def sandbox_posture_warning(sandbox_evidence: Mapping[str, object]) -> str | None:
    """Return an operator-visible warning when proxy isolation is not active."""
    if sandbox_evidence.get("enabled"):
        return None
    return (
        "agent-bom proxy warning: sandbox isolation is disabled; the MCP server "
        "runs as the current host user. Remove --no-isolate or set "
        "AGENT_BOM_MCP_SANDBOX=1 to run the server in a restricted container."
    )


def _command_name_for_validation(command: str, sandbox_evidence: Mapping[str, object]) -> str:
    """Validate sandbox-generated container runtimes by name, not resolved path."""
    if sandbox_evidence.get("enabled") and sandbox_evidence.get("mode") in {"wrap_command_in_image", "harden_existing_container"}:
        return Path(command).name
    return command


def _generate_proxy_source_id() -> str:
    hostname = platform.node() or "unknown"
    return hashlib.sha256(hostname.encode()).hexdigest()[:12]


def _proxy_audit_delivery_paths(
    control_plane_url: str,
    tenant_id: str,
    source_id: str,
) -> AuditDeliveryPaths:
    """Resolve restart-stable, secret-free proxy audit backlog paths."""

    state_dir = state_home.state_dir()
    identity = "\x00".join((control_plane_url.rstrip("/"), tenant_id, source_id))
    return audit_delivery_paths(state_dir, surface="proxy", identity=identity)


async def _push_proxy_audit_batch(
    base_url: str,
    token: str | None,
    source_id: str,
    session_id: str,
    alerts: list[dict],
    summary: dict | None = None,
) -> bool:
    from agent_bom.http_client import create_client

    if not alerts and summary is None:
        return True
    url = base_url.rstrip("/") + "/v1/proxy/audit"
    payload = {
        "source_id": source_id,
        "session_id": session_id,
        "alerts": alerts,
        "summary": summary,
    }
    span_cm = proxy_span("proxy.push_audit_batch")
    with span_cm as span:
        if span is not None:
            span.set_attribute("agent_bom.proxy.audit_alert_count", len(alerts))
            span.set_attribute("agent_bom.proxy.audit_has_summary", summary is not None)
        async with create_client(timeout=15.0) as client:
            response = await client.post(url, json=payload, headers=_control_plane_headers(token))
    response.raise_for_status()
    return True


_WEBHOOK_TASKS: set[asyncio.Task] = set()


def _fire_webhook(url: str, payload: dict) -> None:
    """Dispatch an alert webhook without letting the task be GC'd mid-flight."""
    task = asyncio.ensure_future(_send_webhook(url, payload))
    _WEBHOOK_TASKS.add(task)
    task.add_done_callback(_WEBHOOK_TASKS.discard)


async def _send_webhook(url: str, payload: dict) -> None:
    """Fire-and-forget POST to an alert webhook URL.

    Validates the URL before sending to prevent SSRF via --alert-webhook.
    """
    from agent_bom.security import SecurityError, validate_url

    try:
        validate_url(url)
    except SecurityError as e:
        logger.warning("Webhook URL rejected: %s", sanitize_text(e))
        return

    try:
        import httpx

        async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)) as client:
            await client.post(url, json=sanitize_sensitive_payload(payload, max_str_len=3_000))
    except Exception:  # noqa: BLE001
        logger.debug("Failed to send webhook to %s", redact_secret_url(url))


def _response_scan_alerts(findings, subject: str):
    """Convert shared response detections to transport-specific alert sinks."""
    from agent_bom.runtime.detectors import Alert, AlertSeverity

    return [
        Alert(
            detector=f"scanner:{finding.scanner}",
            severity=AlertSeverity.CRITICAL
            if finding.severity == "critical"
            else (AlertSeverity.HIGH if finding.severity == "high" else AlertSeverity.MEDIUM),
            message=f"Inline scan (response): {finding.scanner}/{finding.rule_id} from '{subject}'",
            details={"rule_id": finding.rule_id, "excerpt": finding.excerpt, "confidence": finding.confidence},
        )
        for finding in findings
    ]


def _write_client_error(request_id: int | str | None, reason: str) -> None:
    """Answer a rejected request directly on the client's stdout."""
    error_resp = make_error_response(request_id, -32600, reason)
    sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
    sys.stdout.buffer.flush()


def _reject_tool_call(
    log_file,  # noqa: ANN001
    tool_name: str,
    arguments: dict,
    reason: str,
    *,
    payload_sha256: str,
    message_id: int | str | None,
    agent_id: str,
    tenant_id: str,
) -> None:
    """Audit a blocked policy-gated call, then answer the client with an error."""
    if log_file:
        log_tool_call(
            log_file,
            tool_name,
            arguments,
            "blocked",
            reason,
            payload_sha256=payload_sha256,
            message_id=message_id,
            agent_id=agent_id,
            tenant_id=tenant_id,
        )
    _write_client_error(message_id, reason)


def _execution_posture(sandbox_evidence: Mapping[str, object]) -> dict[str, object]:
    return {
        "mode": "container_isolated" if sandbox_evidence.get("enabled") else "observation_only",
        "sandbox_evidence": sandbox_evidence,
    }


def _load_proxy_policy(policy_path: Optional[str]) -> dict:
    """Load the local policy file (path-validated, 10 MB-capped JSON) or exit 1."""
    if not policy_path:
        return {}
    try:
        from agent_bom.security import SecurityError, validate_json_file

        return validate_json_file(Path(policy_path))
    except (json.JSONDecodeError, OSError, SecurityError) as exc:
        logger.error("Failed to load policy from %s: %s", policy_path, sanitize_text(exc))
        raise SystemExit(1) from exc


@dataclass
class _ProxyAuditDelivery:
    max_buffer_bytes: int
    max_spillover_bytes: int
    spill_path: Path
    dlq_path: Path
    controller: AuditDeliveryController
    spillover: AuditSpilloverStore
    state: AuditDeliveryState


def _build_audit_delivery(
    control_plane_url: Optional[str],
    tenant_id: str,
    source_id: str,
    audit_push_interval: int,
) -> _ProxyAuditDelivery:
    """Resolve bounded audit buffer/spillover/DLQ settings and delivery backoff."""
    max_buffer_bytes = max(64 * 1024, int(env_raw("AGENT_BOM_PROXY_AUDIT_BUFFER_MAX_BYTES", "1048576")))
    max_spillover_bytes = max(
        max_buffer_bytes,
        int(env_raw("AGENT_BOM_PROXY_AUDIT_SPILLOVER_MAX_BYTES", str(max_buffer_bytes * 8))),
    )
    stable_paths = _proxy_audit_delivery_paths(control_plane_url or "local", tenant_id, source_id)
    spill_path = Path(env_raw("AGENT_BOM_PROXY_AUDIT_SPILLOVER_PATH", str(stable_paths.spill_path)))
    dlq_path = Path(env_raw("AGENT_BOM_PROXY_AUDIT_DLQ_PATH", str(stable_paths.dlq_path)))
    base_interval = max(audit_push_interval, 5)
    controller = AuditDeliveryController(
        base_interval_seconds=base_interval,
        max_backoff_seconds=max(
            base_interval,
            int(env_raw("AGENT_BOM_PROXY_AUDIT_PUSH_BACKOFF_MAX_SECONDS", "300")),
        ),
        breaker_failure_threshold=max(
            1,
            int(env_raw("AGENT_BOM_PROXY_AUDIT_CIRCUIT_BREAKER_THRESHOLD", "3")),
        ),
        breaker_cooldown_seconds=max(
            base_interval,
            int(env_raw("AGENT_BOM_PROXY_AUDIT_CIRCUIT_BREAKER_COOLDOWN_SECONDS", "60")),
        ),
    )
    spillover = AuditSpilloverStore(spill_path=spill_path, dlq_path=dlq_path, max_spillover_bytes=max_spillover_bytes)
    return _ProxyAuditDelivery(
        max_buffer_bytes=max_buffer_bytes,
        max_spillover_bytes=max_spillover_bytes,
        spill_path=spill_path,
        dlq_path=dlq_path,
        controller=controller,
        spillover=spillover,
        state=AuditDeliveryState(controller=controller, store=spillover),
    )


def _prepare_server_command(
    server_cmd: list[str],
    sandbox_config: SandboxConfig | None,
    log_file,  # noqa: ANN001
) -> tuple[list[str], dict[str, object]]:
    """Apply sandbox wrapping, launch-hygiene checks and the posture audit record."""
    sandbox_evidence: dict[str, object] = {"enabled": False}
    if sandbox_config and sandbox_config.enabled:
        server_cmd, sandbox_evidence = build_sandboxed_command(server_cmd, sandbox_config)
        logger.info(
            "MCP server isolation enabled using %s (%s)",
            sandbox_evidence.get("runtime"),
            sandbox_evidence.get("mode"),
        )
    elif sandbox_config:
        sandbox_evidence = sandbox_config.evidence()

    if warning := sandbox_posture_warning(sandbox_evidence):
        # Single emission via the logger: the default handler already writes
        # to stderr, and the `mcp_execution_posture` audit event carries the
        # same detail in machine-readable form.
        logger.warning(warning)

    # Launch-hygiene checks on the effective server command before spawning.
    # These catch typos and shell-interpolation configs; they are NOT the
    # isolation boundary — that is the container sandbox wired above.
    require_recognized_launcher(_command_name_for_validation(server_cmd[0], sandbox_evidence))
    if len(server_cmd) > 1:
        validate_arguments(list(server_cmd[1:]))

    if log_file:
        write_audit_record(
            log_file,
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "type": "mcp_execution_posture",
                "execution_posture": _execution_posture(sandbox_evidence),
            },
        )
    return server_cmd, sandbox_evidence


def _start_sandbox_timeout(
    process: asyncio.subprocess.Process,
    sandbox_config: SandboxConfig | None,
    sandbox_evidence: dict[str, object],
    log_file,  # noqa: ANN001
) -> asyncio.Task | None:
    """Terminate the sandboxed server once its configured timeout elapses."""
    if not (sandbox_config and sandbox_config.enabled and sandbox_config.timeout_seconds):
        return None
    timeout_seconds = sandbox_config.timeout_seconds

    async def _sandbox_timeout_watchdog() -> None:
        await asyncio.sleep(timeout_seconds or 0)
        if process.returncode is None:
            logger.error("MCP sandbox timeout reached after %s seconds; terminating server", timeout_seconds)
            if log_file:
                write_audit_record(
                    log_file,
                    {
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "type": "mcp_sandbox_timeout",
                        "timeout_seconds": timeout_seconds,
                        "execution_posture": {
                            "mode": "container_isolated",
                            "sandbox_evidence": sandbox_evidence,
                        },
                    },
                )
            process.terminate()

    return asyncio.create_task(_sandbox_timeout_watchdog())


def _record_relay_errors(results: list, metrics: ProxyMetrics, log_file) -> None:  # noqa: ANN001
    """Count and audit unexpected relay-task failures (pipe teardown is expected)."""
    for result in results:
        if isinstance(result, Exception) and not isinstance(result, (BrokenPipeError, ConnectionResetError, asyncio.CancelledError)):
            metrics.relay_errors += 1
            logger.warning("Relay task exited with unexpected error: %s", sanitize_text(result))
            if log_file:
                err_entry = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "type": "relay_error",
                    "error": str(result),
                    "error_type": type(result).__name__,
                }
                write_audit_record(log_file, err_entry)
