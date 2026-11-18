"""Gateway HTTP routes with explicit per-application dependencies."""

from __future__ import annotations

from functools import partial
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from agent_bom.api.gateway_auth import _gateway_requires_auth, authenticate_gateway_request_off_loop
from agent_bom.api.gateway_rate_limit import _gateway_rate_limit_runtime_status
from agent_bom.firewall import AgentFirewallPolicy
from agent_bom.proxy_policy import summarize_policy_bundle
from agent_bom.runtime.fail_mode import gateway_fail_mode_matrix
from agent_bom.runtime.gateway_policy_reload import GatewayPolicyReloader
from agent_bom.runtime.gateway_relay import GatewayUpstreamRelay
from agent_bom.runtime.gateway_settings import GatewaySettings


async def policy_health(settings: GatewaySettings, policy_reload: GatewayPolicyReloader, firewall_reload: GatewayPolicyReloader):
    async with policy_reload.lock:
        policy_summary = summarize_policy_bundle(policy_reload.state.policy)
        policy_runtime = {
            "source": policy_reload.state.source,
            "source_kind": "file" if settings.policy_path else "inline",
            "reload_enabled": bool(settings.policy_path and settings.policy_reload_interval_seconds > 0),
            "reload_interval_seconds": settings.policy_reload_interval_seconds,
            "last_loaded_at": policy_reload.state.last_loaded_at,
            "last_error": policy_reload.state.last_error,
            **policy_summary,
        }
    async with firewall_reload.lock:
        firewall_policy: AgentFirewallPolicy = firewall_reload.state.policy
        firewall_runtime = {
            "source": firewall_reload.state.source,
            "source_kind": "file" if settings.firewall_policy_path else "default-allow",
            "reload_enabled": bool(settings.firewall_policy_path and settings.firewall_policy_reload_interval_seconds > 0),
            "reload_interval_seconds": settings.firewall_policy_reload_interval_seconds,
            "last_loaded_at": firewall_reload.state.last_loaded_at,
            "last_error": firewall_reload.state.last_error,
            "load_failed": bool(firewall_reload.state.load_failed),
            "rule_count": len(firewall_policy.rules),
            "default_decision": firewall_policy.default_decision.value,
            "enforcement_mode": firewall_policy.enforcement_mode.value,
            "tenant_id": firewall_policy.tenant_id,
        }
    return policy_runtime, firewall_runtime


async def gateway_health(
    settings: GatewaySettings,
    policy_reload: GatewayPolicyReloader,
    firewall_reload: GatewayPolicyReloader,
    managed_upstream_relay: GatewayUpstreamRelay | None,
    resolved_fail_mode: str,
) -> dict[str, Any]:
    policy_runtime, firewall_runtime = await policy_health(settings, policy_reload, firewall_reload)
    health: dict[str, Any] = {
        "status": "ok",
        "upstreams": settings.registry.names(),
        "auth": {"incoming_token_required": _gateway_requires_auth(settings)},
        "upstream_runtime": {
            "pooled_http_client": managed_upstream_relay is not None,
            "circuit_breaker_enabled": managed_upstream_relay is not None,
            "failure_threshold": settings.upstream_failure_threshold,
            "cooldown_seconds": settings.upstream_circuit_cooldown_seconds,
            "max_connections": settings.upstream_http_max_connections,
            "max_keepalive_connections": settings.upstream_http_max_keepalive_connections,
        },
        "rate_limit_runtime": _gateway_rate_limit_runtime_status(settings),
        "policy_runtime": policy_runtime,
        "firewall_runtime": firewall_runtime,
        "broker_runtime": {
            "oauth_as_enabled": False,
            "oidc_discovery_shim_enabled": settings.oidc_discovery_shim is not None,
            "a2a_mutual_auth_enforcement_mode": settings.a2a_mutual_auth_enforcement_mode,
            "tool_scope_mapped_tools": len(settings.tool_scope_map),
            "dlp_enabled": settings.dlp_enabled,
            "dlp_mode": settings.dlp_mode if settings.dlp_enabled else "disabled",
        },
        # Honest fail-open/fail-closed posture per enforcement subsystem
        # (docs/RUNTIME_FAIL_MODES.md). Resolved once at app build; the
        # matrix itself is static documentation-as-data from agent_bom.runtime.fail_mode.
        "fail_mode_runtime": {
            "policy_fail_mode": resolved_fail_mode,
            "subsystems": gateway_fail_mode_matrix(resolved_fail_mode),
        },
    }
    if settings.enable_visual_leak_detection:
        from agent_bom.runtime.visual_leak_detector import visual_leak_runtime_health

        health["visual_leak_detection"] = {
            **visual_leak_runtime_health(),
            "required": settings.require_visual_leak_detection_ready,
        }
    audit_health = getattr(settings.audit_sink, "health", None)
    if callable(audit_health):
        audit_delivery_health = audit_health()
        health["audit_delivery"] = audit_delivery_health
        if audit_delivery_health["status"] != "healthy":
            health["status"] = "degraded"
    return health


async def gateway_ready(health_provider) -> JSONResponse:
    """Report whether configured durable audit delivery can accept work."""

    health = await health_provider()
    audit_delivery = health.get("audit_delivery")
    ready = not isinstance(audit_delivery, dict) or (
        bool(audit_delivery.get("durable"))
        and bool(audit_delivery.get("accepting_events"))
        and bool(audit_delivery.get("backlog_observable"))
    )
    return JSONResponse(status_code=200 if ready else 503, content={"ready": ready, **health})


def register_health_routes(
    app: FastAPI,
    settings: GatewaySettings,
    policy_reload: GatewayPolicyReloader,
    firewall_reload: GatewayPolicyReloader,
    managed_upstream_relay: GatewayUpstreamRelay | None,
    resolved_fail_mode: str,
) -> None:
    health = partial(gateway_health, settings, policy_reload, firewall_reload, managed_upstream_relay, resolved_fail_mode)

    @app.get("/healthz")
    async def healthz() -> dict[str, Any]:
        return await health()

    @app.get("/readyz")
    async def readyz() -> JSONResponse:
        """Report whether configured durable audit delivery can accept work."""
        return await gateway_ready(health)


async def gateway_metrics(settings: GatewaySettings, request: Request) -> Response:
    # Prometheus text-exposition format must be plain text, not JSON. Previous JSONResponse wrapped the body in quotes + escaped
    # newlines, which breaks every Prometheus scraper. Serve as `Response` with the exposition media type so scrapers parse it.
    #
    # scraping endpoints carry decision counters and tenant tags — gate them with the same bearer/API-key check that protects
    # /mcp/{server} when incoming auth is configured.
    tenant_id, auth_method = await authenticate_gateway_request_off_loop(request, settings)
    if auth_method != "none":
        request.state.tenant_id = tenant_id
        request.state.auth_method = auth_method
    from agent_bom.api.metrics import render_prometheus_lines

    body = "\n".join(render_prometheus_lines()) + "\n"
    return Response(content=body, media_type="text/plain; version=0.0.4; charset=utf-8")


def register_metrics_route(app: FastAPI, settings: GatewaySettings) -> None:
    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        return await gateway_metrics(settings, request)
