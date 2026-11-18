"""Gateway HTTP routes with explicit per-application dependencies."""

from __future__ import annotations

import json
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from agent_bom.api.gateway_app_audit import bind_authenticated_audit_tenant
from agent_bom.api.gateway_auth import authenticate_gateway_request_off_loop
from agent_bom.firewall import AgentFirewallPolicy, FirewallDecision, FirewallEvaluation
from agent_bom.firewall import evaluate as evaluate_firewall_policy
from agent_bom.runtime.gateway_policy_reload import GatewayPolicyReloader
from agent_bom.runtime.gateway_settings import GatewaySettings


async def parse_firewall_payload(request: Request):
    try:
        payload = await request.json()
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"invalid JSON body: {exc.msg}") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="firewall check body must be a JSON object")

    source_agent = payload.get("source_agent")
    target_agent = payload.get("target_agent")
    if not isinstance(source_agent, str) or not source_agent.strip():
        raise HTTPException(status_code=400, detail="'source_agent' is required")
    if not isinstance(target_agent, str) or not target_agent.strip():
        raise HTTPException(status_code=400, detail="'target_agent' is required")

    raw_source_roles = payload.get("source_roles") or []
    raw_target_roles = payload.get("target_roles") or []
    if not isinstance(raw_source_roles, list) or not all(isinstance(r, str) for r in raw_source_roles):
        raise HTTPException(status_code=400, detail="'source_roles' must be a list of strings")
    if not isinstance(raw_target_roles, list) or not all(isinstance(r, str) for r in raw_target_roles):
        raise HTTPException(status_code=400, detail="'target_roles' must be a list of strings")

    return source_agent, target_agent, raw_source_roles, raw_target_roles


def firewall_response(
    source_agent: str,
    target_agent: str,
    raw_source_roles: list[str],
    raw_target_roles: list[str],
    result: FirewallEvaluation,
    policy: AgentFirewallPolicy,
    policy_source: str,
    policy_loaded_at: Any,
    tenant_id: str,
) -> dict[str, Any]:
    return {
        "source_agent": source_agent,
        "target_agent": target_agent,
        "source_roles": list(raw_source_roles),
        "target_roles": list(raw_target_roles),
        "decision": result.decision.value,
        "effective_decision": result.effective_decision.value,
        "matched_rule": (
            {
                "source": result.matched_rule.source,
                "target": result.matched_rule.target,
                "decision": result.matched_rule.decision.value,
                "description": result.matched_rule.description,
            }
            if result.matched_rule is not None
            else None
        ),
        "policy": {
            "source": policy_source,
            "loaded_at": policy_loaded_at,
            "default_decision": policy.default_decision.value,
            "enforcement_mode": policy.enforcement_mode.value,
            "tenant_id": tenant_id,
        },
    }


async def firewall_check(
    settings: GatewaySettings, firewall_reload: GatewayPolicyReloader, fail_closed: bool, request: Request
) -> JSONResponse:
    """Authenticate, evaluate the inter-agent firewall, then durably audit denies."""
    # gateway --bearer-token (or API-key store) must gate the firewall-check endpoint, not just /mcp/{server}. Otherwise the policy
    # evaluator is reachable unauthenticated on shared deployments and leaks every rule via the matched_rule field.
    tenant_id, auth_method = await authenticate_gateway_request_off_loop(request, settings)
    if auth_method != "none":
        request.state.tenant_id = tenant_id
        request.state.auth_method = auth_method
    await bind_authenticated_audit_tenant(settings, request, tenant_id, auth_method)
    source_agent, target_agent, raw_source_roles, raw_target_roles = await parse_firewall_payload(request)
    async with firewall_reload.lock:
        policy: AgentFirewallPolicy = firewall_reload.state.policy
        policy_source = firewall_reload.state.source
        policy_loaded_at = firewall_reload.state.last_loaded_at
        policy_load_failed = bool(firewall_reload.state.load_failed)
    if policy.tenant_id is not None and policy.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="firewall policy is not bound to the authenticated tenant")
    if fail_closed and policy_load_failed and settings.firewall_policy_path is not None:
        result = FirewallEvaluation(
            decision=FirewallDecision.DENY,
            matched_rule=None,
            effective_decision=FirewallDecision.DENY,
        )
    else:
        result = evaluate_firewall_policy(
            policy,
            source_agent=source_agent,
            target_agent=target_agent,
            source_roles=set(raw_source_roles),
            target_roles=set(raw_target_roles),
        )

    response_payload = firewall_response(
        source_agent, target_agent, raw_source_roles, raw_target_roles, result, policy, policy_source, policy_loaded_at, tenant_id
    )

    # Audit fan-out: emit on any non-allow effective decision so denies
    # and warns flow into the existing /v1/proxy/audit HMAC-chained relay.
    if result.effective_decision != FirewallDecision.ALLOW and settings.audit_sink is not None:
        await settings.audit_sink(
            {
                "action": "gateway.firewall_decision",
                "decision": result.decision.value,
                "effective_decision": result.effective_decision.value,
                "source_agent": source_agent,
                "target_agent": target_agent,
                "source_roles": list(raw_source_roles),
                "target_roles": list(raw_target_roles),
                "matched_rule": response_payload["matched_rule"],
                "tenant_id": tenant_id,
                "enforcement_mode": policy.enforcement_mode.value,
                "timestamp": time.time(),
            }
        )

    return JSONResponse(response_payload)


def register_firewall_route(app: FastAPI, settings: GatewaySettings, firewall_reload: GatewayPolicyReloader, fail_closed: bool) -> None:
    @app.post("/v1/firewall/check", name="firewall_check")
    async def firewall_check_endpoint(request: Request) -> JSONResponse:
        """Evaluate the inter-agent firewall policy for a source -> target pair.

        Body shape (#982 PR 2):
            {
              "source_agent": "cursor",
              "target_agent": "snowflake-cli",
              "source_roles": ["trusted"],          # optional
              "target_roles": ["data-plane"]        # optional
            }

        Returns the matched decision plus the *effective* decision (with
        dry-run mode applied). On any non-allow effective decision, an audit
        event is emitted to the configured audit_sink so denies and warns
        flow into the existing /v1/proxy/audit relay.
        """
        return await firewall_check(settings, firewall_reload, fail_closed, request)
