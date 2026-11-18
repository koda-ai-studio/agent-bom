"""Multi-MCP gateway server (`agent-bom gateway serve`).

One FastAPI service that fronts N upstream MCP servers, applies policy
inline on every JSON-RPC request, and logs every call into the audit
trail. Laptops point at one URL (``/mcp/{server-name}``) instead of
configuring a proxy per MCP.

Design doc: docs/design/MULTI_MCP_GATEWAY.md.

MVP scope:
  * Request/response relay over HTTP (POST). Streamable-HTTP transport
    with bidirectional streaming is a v2 addition — the MVP handles
    the dominant request/response case where the client expects one
    response per request.
  * Policy evaluation via ``agent_bom.proxy.check_policy`` (reused —
    no new policy engine).
  * Audit events emitted via a caller-supplied sink; in-cluster deploys
    point it at ``/v1/proxy/audit``.
  * Pooled upstream HTTP relay with per-upstream circuit breakers.
  * Per-upstream static header / bearer / OAuth2 auth injection from
    ``UpstreamRegistry``.

Non-goals for MVP (see design doc):
  * stdio upstreams (per-MCP ``agent-bom proxy`` wrapper still handles these)
  * SSE long-poll / Streamable HTTP streaming
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
from functools import partial
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from agent_bom.api.gateway_app_audit import audit_unavailable_response, bind_authenticated_audit_tenant, register_audit_handler
from agent_bom.api.gateway_app_firewall import register_firewall_route
from agent_bom.api.gateway_app_health import (
    register_health_routes,
    register_metrics_route,
)
from agent_bom.api.gateway_auth import _api_key_allows_gateway_relay as _api_key_allows_gateway_relay
from agent_bom.api.gateway_auth import _authenticate_gateway_request as _authenticate_gateway_request
from agent_bom.api.gateway_auth import _enforce_gateway_anonymous_agents_posture as _enforce_gateway_anonymous_agents_posture
from agent_bom.api.gateway_auth import _enforce_gateway_auth_posture as _enforce_gateway_auth_posture
from agent_bom.api.gateway_auth import _env_flag_enabled as _env_flag_enabled
from agent_bom.api.gateway_auth import _extract_request_token as _extract_request_token
from agent_bom.api.gateway_auth import _gateway_allows_anonymous_agents as _gateway_allows_anonymous_agents
from agent_bom.api.gateway_auth import _gateway_requires_auth as _gateway_requires_auth
from agent_bom.api.gateway_auth import _is_loopback_host as _is_loopback_host
from agent_bom.api.gateway_auth import _parse_gateway_token_expiry as _parse_gateway_token_expiry
from agent_bom.api.gateway_auth import _request_has_expected_token as _request_has_expected_token
from agent_bom.api.gateway_auth import _role_allows_gateway_relay as _role_allows_gateway_relay
from agent_bom.api.gateway_auth import _validate_runtime_profile_posture as _validate_runtime_profile_posture
from agent_bom.api.gateway_context import create_gateway_http_app
from agent_bom.api.gateway_policy import _CONDITIONAL_ACCESS_EVAL_FAILED as _CONDITIONAL_ACCESS_EVAL_FAILED
from agent_bom.api.gateway_policy import _DRIFT_INCIDENT_LOOKUP_CAP as _DRIFT_INCIDENT_LOOKUP_CAP
from agent_bom.api.gateway_policy import _agent_cost_anomaly as _agent_cost_anomaly
from agent_bom.api.gateway_policy import _agent_identity_revoked as _agent_identity_revoked
from agent_bom.api.gateway_policy import _conditional_access_fail_closed as _conditional_access_fail_closed
from agent_bom.api.gateway_policy import _DriftLookup as _DriftLookup
from agent_bom.api.gateway_policy import _evaluate_control_plane_bundle as _evaluate_control_plane_bundle
from agent_bom.api.gateway_policy import _fleet_containment_reason as _fleet_containment_reason
from agent_bom.api.gateway_policy import _open_drift_violates_tool as _open_drift_violates_tool
from agent_bom.api.gateway_policy import _warn_on_quarantined_agents as _warn_on_quarantined_agents
from agent_bom.api.gateway_rate_limit import _build_gateway_rate_limit_store as _build_gateway_rate_limit_store
from agent_bom.api.gateway_rate_limit import _gateway_configured_replicas as _gateway_configured_replicas
from agent_bom.api.gateway_rate_limit import _gateway_rate_limit_runtime_status as _gateway_rate_limit_runtime_status
from agent_bom.api.gateway_rate_limit import _gateway_shared_rate_limit_required as _gateway_shared_rate_limit_required
from agent_bom.api.gateway_rate_limit import _rate_limit_bucket_component as _rate_limit_bucket_component
from agent_bom.api.gateway_relay_context import RelayRuntime
from agent_bom.api.gateway_relay_context import _emit_gateway_governance_event as _emit_gateway_governance_event
from agent_bom.api.gateway_relay_context import _message_tool_label as _message_tool_label
from agent_bom.api.gateway_relay_context import _public_gateway_block_reason as _public_gateway_block_reason
from agent_bom.api.gateway_relay_context import _public_gateway_error as _public_gateway_error
from agent_bom.api.gateway_relay_context import _redact_obj_pii as _redact_obj_pii
from agent_bom.api.gateway_relay_pipeline import run_relay
from agent_bom.api.gateway_request import _read_bounded_gateway_body as _read_bounded_gateway_body
from agent_bom.api.gateway_request import _request_client_id as _request_client_id
from agent_bom.api.gateway_request import _request_context_attributes as _request_context_attributes
from agent_bom.api.gateway_request import _request_cost_center as _request_cost_center
from agent_bom.api.gateway_request import _request_device_id as _request_device_id
from agent_bom.api.gateway_request import _request_environment as _request_environment
from agent_bom.api.gateway_request import _request_groups as _request_groups
from agent_bom.api.gateway_request import _request_risk_score as _request_risk_score
from agent_bom.api.gateway_request import _request_source_ip as _request_source_ip
from agent_bom.api.gateway_request import _sanitize_for_log as _sanitize_for_log
from agent_bom.api.gateway_request import _strip_gateway_identity_metadata as _strip_gateway_identity_metadata
from agent_bom.api.oidc_discovery_shim import build_oidc_discovery_shim_router
from agent_bom.api.tracing import get_tracer
from agent_bom.proxy import parse_jsonrpc
from agent_bom.proxy_policy import (
    DecisionContext,
    GatewayDecision,
    build_policy_ocsf_event,
    deliver_policy_webhook,
    resolve_fail_mode,
)
from agent_bom.proxy_scanner import ScanConfig, scan_jsonrpc_response
from agent_bom.runtime.gateway_application_lifecycle import build_policy_reloaders, build_runtime_facts, gateway_lifespan
from agent_bom.runtime.gateway_audit import ControlPlaneAuditSink as ControlPlaneAuditSink
from agent_bom.runtime.gateway_audit import build_control_plane_audit_sink as build_control_plane_audit_sink
from agent_bom.runtime.gateway_audit_local import LocalGatewayAuditSink as LocalGatewayAuditSink
from agent_bom.runtime.gateway_audit_local import UnavailableGatewayAuditSink
from agent_bom.runtime.gateway_audit_local import build_local_gateway_audit_sink as build_local_gateway_audit_sink
from agent_bom.runtime.gateway_contracts import AuditSink as AuditSink
from agent_bom.runtime.gateway_contracts import GatewayAuditDeliveryUnavailableError as GatewayAuditDeliveryUnavailableError
from agent_bom.runtime.gateway_contracts import GatewayAuditSender as GatewayAuditSender
from agent_bom.runtime.gateway_contracts import UpstreamCaller as UpstreamCaller
from agent_bom.runtime.gateway_policy_reload import _load_policy_file as _load_policy_file
from agent_bom.runtime.gateway_relay import GatewayCircuitBreaker as GatewayCircuitBreaker
from agent_bom.runtime.gateway_relay import GatewayCircuitOpenError as GatewayCircuitOpenError
from agent_bom.runtime.gateway_relay import GatewayUpstreamRelay as GatewayUpstreamRelay
from agent_bom.runtime.gateway_relay import _default_upstream_caller as _default_upstream_caller
from agent_bom.runtime.gateway_relay import _post_upstream_jsonrpc as _post_upstream_jsonrpc
from agent_bom.runtime.gateway_relay_contract import MAX_GATEWAY_RELAY_MESSAGE_BYTES
from agent_bom.runtime.gateway_settings import GatewaySettings as GatewaySettings
from agent_bom.runtime.gateway_settings import validate_gateway_startup_settings
from agent_bom.runtime.graph_reachability import ReachabilityMap, load_reachability_map
from agent_bom.runtime.trace_metadata import inject_jsonrpc_trace_meta
from agent_bom.security import sanitize_text

logger = logging.getLogger(__name__)
_GATEWAY_TRACER = get_tracer("agent_bom.gateway")
_MAX_GATEWAY_MESSAGE_BYTES = MAX_GATEWAY_RELAY_MESSAGE_BYTES


# Lazy singleton so disabled deploys don't pay the import cost of the visual detector (Pillow/pytesseract). Built on first use when
# ``enable_visual_leak_detection`` is True.
_visual_detector_singleton: Any = None
_visual_detector_lock = threading.Lock()


def _get_visual_leak_detector() -> Any:
    global _visual_detector_singleton
    if _visual_detector_singleton is None:
        with _visual_detector_lock:
            if _visual_detector_singleton is None:
                from agent_bom.runtime.visual_leak_detector import VisualLeakDetector

                _visual_detector_singleton = VisualLeakDetector()
    return _visual_detector_singleton


def _gateway_dlp_config(settings: GatewaySettings) -> ScanConfig:
    """Build the inline-scanner config for the gateway DLP pass."""
    return ScanConfig(
        enabled=settings.dlp_enabled,
        mode=settings.dlp_mode if settings.dlp_mode in ("audit", "enforce") else "audit",
        scanners=list(settings.dlp_scanners),
        pii_action=settings.dlp_pii_action if settings.dlp_pii_action in ("redact", "block") else "redact",
    )


async def _emit_policy_interop_event(
    settings: GatewaySettings,
    *,
    decision: GatewayDecision,
    reason: str,
    ctx: DecisionContext,
    policy_source: str,
) -> None:
    """Emit a normalized OCSF event for a DENY/QUARANTINE and POST it to the
    configured SIEM/SOAR webhook (best-effort).

    Determinism: the event id derives from the decision inputs (it doubles as
    the webhook idempotency key), so a retried delivery never double-records
    downstream. Webhook failures are bounded-retry + drop-with-warning inside
    ``deliver_policy_webhook`` and run off the event loop, so they never block
    or crash the relay.
    """
    if decision == GatewayDecision.ALLOW:
        return
    # Only build/emit when a webhook target is configured. The OCSF event is an interop artifact for SIEM/SOAR; it deliberately does NOT fan
    # into the audit_sink so the existing audit-event stream (and its counts) are unchanged when no webhook is set — the default no-op
    # posture.
    webhook_url = settings.policy_webhook_url
    if webhook_url is None:
        webhook_url = os.environ.get("AGENT_BOM_POLICY_WEBHOOK_URL", "")
    if not (webhook_url or "").strip():
        return
    try:
        event = build_policy_ocsf_event(decision=decision, reason=reason, ctx=ctx, policy_source=policy_source)
    except Exception as exc:  # noqa: BLE001
        logger.warning("gateway OCSF event build failed: %s", sanitize_text(_sanitize_for_log(exc)))
        return
    try:
        await asyncio.to_thread(
            deliver_policy_webhook,
            event,
            url=settings.policy_webhook_url,
            token=settings.policy_webhook_token,
        )
    except Exception as exc:  # noqa: BLE001 — webhook must never break the relay
        logger.warning("gateway policy webhook dispatch error (event dropped, relay unaffected): %s", sanitize_text(_sanitize_for_log(exc)))


def _inject_jsonrpc_trace_meta(
    message: dict[str, Any],
    *,
    traceparent: str | None,
    tracestate: str | None,
    baggage: str | None,
) -> dict[str, Any]:
    """Preserve the gateway's explicit trace arguments at its compatibility entry."""
    return inject_jsonrpc_trace_meta(message, traceparent=traceparent, tracestate=tracestate, baggage=baggage)


def _prepare_gateway_settings(settings: GatewaySettings) -> str:
    validate_gateway_startup_settings(settings)
    if settings.bearer_token:
        settings._bearer_token_deadline = _parse_gateway_token_expiry(settings.bearer_token_expires_at)
    if settings.audit_sink is None:
        try:
            settings.audit_sink = build_local_gateway_audit_sink()
        except Exception as exc:  # noqa: BLE001 - relay remains fail-closed below
            logger.error("Gateway local audit initialization failed (error_type=%s)", type(exc).__name__)
            settings.audit_sink = UnavailableGatewayAuditSink()
    if settings.enable_visual_leak_detection and settings.require_visual_leak_detection_ready:
        from agent_bom.runtime.visual_leak_detector import require_visual_leak_runtime

        require_visual_leak_runtime()
    _enforce_gateway_auth_posture(settings)
    _enforce_gateway_anonymous_agents_posture(settings)
    _warn_on_quarantined_agents(settings)
    return _validate_runtime_profile_posture(settings)


def _gateway_reachability(settings: GatewaySettings) -> ReachabilityMap:
    reachability_map: ReachabilityMap = load_reachability_map(settings.graph_reachability_path)
    if settings.graph_reachability_path is not None:
        logger.info(
            "gateway graph-reachability facts loaded from %s: %d agent(s), mode=%s",
            _sanitize_for_log(settings.graph_reachability_path),
            len(reachability_map.by_agent),
            _sanitize_for_log(settings.graph_reachability_enforcement_mode),
        )

    return reachability_map


def create_gateway_app(settings: GatewaySettings) -> FastAPI:
    """Compose the gateway from independently tested lifecycle and route builders."""
    runtime_profile_mode = _prepare_gateway_settings(settings)
    managed_upstream_relay = GatewayUpstreamRelay(settings) if settings.upstream_caller is None else None
    upstream_caller = settings.upstream_caller or managed_upstream_relay
    assert upstream_caller is not None
    rate_limit_store = _build_gateway_rate_limit_store(settings)
    resolved_fail_mode = resolve_fail_mode(settings.fail_mode)
    fail_closed = resolved_fail_mode == "closed"
    if fail_closed:
        logger.info("gateway policy engine starting in fail-CLOSED mode: unloadable policy or evaluation errors will DENY")
    policy_reload, firewall_reload = build_policy_reloaders(settings, _load_policy_file, _sanitize_for_log)
    reachability_map = _gateway_reachability(settings)
    runtime_facts_poller, runtime_facts_configured, runtime_facts_config_error = build_runtime_facts(settings)
    lifespan = gateway_lifespan(settings, policy_reload, firewall_reload, runtime_facts_poller, managed_upstream_relay)
    app = create_gateway_http_app(settings, lifespan)
    register_audit_handler(app)
    if settings.oidc_discovery_shim is not None:
        app.include_router(build_oidc_discovery_shim_router(settings.oidc_discovery_shim))
    dlp_config = _gateway_dlp_config(settings)
    register_health_routes(app, settings, policy_reload, firewall_reload, managed_upstream_relay, resolved_fail_mode)

    register_firewall_route(app, settings, firewall_reload, fail_closed)
    register_metrics_route(app, settings)

    relay_runtime = RelayRuntime(
        settings=settings,
        policy_reload=policy_reload,
        firewall_reload=firewall_reload,
        fail_closed=fail_closed,
        runtime_profile_mode=runtime_profile_mode,
        rate_limit_store=rate_limit_store,
        reachability_map=reachability_map,
        runtime_facts_poller=runtime_facts_poller,
        runtime_facts_configured=runtime_facts_configured,
        runtime_facts_config_error=runtime_facts_config_error,
        dlp_config=dlp_config,
        upstream_caller=upstream_caller,
        audit_unavailable=audit_unavailable_response,
        bind_audit_tenant=partial(bind_authenticated_audit_tenant, settings),
        emit_policy_interop=_emit_policy_interop_event,
        # Late-bound so patching _get_visual_leak_detector reaches a running gateway.
        visual_detector=lambda: _get_visual_leak_detector(),
        response_scanner=scan_jsonrpc_response,
        tracer=_GATEWAY_TRACER,
    )

    @app.post("/mcp/{server_name}")
    async def relay(server_name: str, request: Request) -> JSONResponse:
        """Route an MCP JSON-RPC request to the named upstream after policy + audit."""
        return await run_relay(relay_runtime, server_name, request)

    return app


# Re-export the parser for easier test authoring / CLI glue.
__all__ = ["AuditSink", "ControlPlaneAuditSink", "GatewayAuditDeliveryUnavailableError", "GatewayAuditSender",
    "GatewayCircuitBreaker", "GatewayCircuitOpenError", "GatewaySettings", "GatewayUpstreamRelay", "LocalGatewayAuditSink",
    "UpstreamCaller", "_CONDITIONAL_ACCESS_EVAL_FAILED", "_DRIFT_INCIDENT_LOOKUP_CAP", "_DriftLookup",
    "_MAX_GATEWAY_MESSAGE_BYTES", "_agent_cost_anomaly", "_agent_identity_revoked", "_api_key_allows_gateway_relay",
    "_authenticate_gateway_request", "_build_gateway_rate_limit_store", "_conditional_access_fail_closed",
    "_default_upstream_caller", "_emit_gateway_governance_event",
    "_enforce_gateway_anonymous_agents_posture", "_enforce_gateway_auth_posture", "_env_flag_enabled",
    "_evaluate_control_plane_bundle", "_extract_request_token", "_fleet_containment_reason",
    "_gateway_allows_anonymous_agents", "_gateway_configured_replicas", "_gateway_rate_limit_runtime_status",
    "_gateway_requires_auth", "_gateway_shared_rate_limit_required", "_is_loopback_host", "_load_policy_file",
    "_message_tool_label", "_open_drift_violates_tool", "_parse_gateway_token_expiry", "_post_upstream_jsonrpc",
    "_public_gateway_block_reason", "_public_gateway_error", "_rate_limit_bucket_component", "_read_bounded_gateway_body",
    "_redact_obj_pii", "_request_client_id", "_request_context_attributes", "_request_cost_center", "_request_device_id",
    "_request_environment", "_request_groups", "_request_has_expected_token", "_request_risk_score", "_request_source_ip",
    "_role_allows_gateway_relay", "_sanitize_for_log", "_strip_gateway_identity_metadata",
    "_validate_runtime_profile_posture", "_warn_on_quarantined_agents", "build_control_plane_audit_sink",
    "build_local_gateway_audit_sink", "create_gateway_app", "parse_jsonrpc"]  # fmt: skip
