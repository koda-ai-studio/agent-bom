"""Build gateway policy reloaders and own their application lifespan."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Mapping
from contextlib import asynccontextmanager
from functools import partial
from typing import Any

from fastapi import FastAPI

from agent_bom.firewall import AgentFirewallPolicy, load_firewall_policy_file
from agent_bom.runtime.correlation_facts import RUNTIME_FACTS_CACHE_INVALIDATING_ERRORS, RuntimeFactsBundleError, RuntimeFactsPoller
from agent_bom.runtime.gateway_audit import GatewayAuditSinkBase
from agent_bom.runtime.gateway_policy_reload import GatewayPolicyReloader, GatewayPolicyState
from agent_bom.runtime.gateway_relay import GatewayUpstreamRelay
from agent_bom.runtime.gateway_settings import GatewaySettings

logger = logging.getLogger("agent_bom.gateway_server")


def build_policy_reloaders(
    settings: GatewaySettings, load_policy: Callable, sanitize_log: Callable[[Any], str]
) -> tuple[GatewayPolicyReloader, GatewayPolicyReloader]:
    policy_reload = GatewayPolicyReloader(
        state=GatewayPolicyState(
            policy=dict(settings.policy),
            source=str(settings.policy_path) if settings.policy_path else "inline",
            load_failed=settings.policy_path is not None,
        ),
        path=lambda: settings.policy_path,
        interval=lambda: settings.policy_reload_interval_seconds,
        load=load_policy,
        logger=logger,
        log_prefix="gateway policy",
        sanitize_log=sanitize_log,
    )

    # The firewall rotates independently and invalidates a failed reload; method policy retains its last successfully loaded version.
    firewall_reload = GatewayPolicyReloader(
        state=GatewayPolicyState(
            policy=AgentFirewallPolicy(),
            source=str(settings.firewall_policy_path) if settings.firewall_policy_path else "default-allow",
            load_failed=settings.firewall_policy_path is not None,
        ),
        path=lambda: settings.firewall_policy_path,
        interval=lambda: settings.firewall_policy_reload_interval_seconds,
        load=load_firewall_policy_file,
        logger=logger,
        log_prefix="gateway firewall policy",
        sanitize_log=sanitize_log,
        invalidate_on_error=True,
    )
    return policy_reload, firewall_reload


async def fetch_runtime_facts_url(settings: GatewaySettings) -> Mapping[str, Any]:
    import httpx

    headers: dict[str, str] = {"Accept": "application/json"}
    if settings.graph_reachability_bundle_bearer_token:
        headers["Authorization"] = f"Bearer {settings.graph_reachability_bundle_bearer_token}"
    async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)) as client:
        response = await client.get(settings.graph_reachability_bundle_url, headers=headers)
        if response.status_code == 409:
            try:
                failure_payload = response.json()
            except (TypeError, ValueError):
                failure_payload = None
            failure_code = str(failure_payload.get("detail") or "") if isinstance(failure_payload, Mapping) else ""
            if failure_code in RUNTIME_FACTS_CACHE_INVALIDATING_ERRORS:
                raise RuntimeFactsBundleError(failure_code)
        response.raise_for_status()
        if len(response.content) > 8 * 1024 * 1024:
            raise ValueError("bundle_response_too_large")
        payload = response.json()
    if not isinstance(payload, Mapping):
        raise ValueError("malformed_bundle_response")
    return payload


def build_runtime_facts(settings: GatewaySettings) -> tuple[RuntimeFactsPoller | None, bool, str]:
    runtime_facts_configured = bool(settings.graph_reachability_bundle_fetcher or settings.graph_reachability_bundle_url.strip())
    runtime_facts_config_error = ""
    runtime_facts_poller: RuntimeFactsPoller | None = None
    if runtime_facts_configured and settings.graph_reachability_enforcement_mode != "off":
        if settings.graph_reachability_bundle_signing_key is None:
            runtime_facts_config_error = "missing_signing_key"
        elif not settings.graph_reachability_bundle_tenant_id.strip():
            runtime_facts_config_error = "missing_tenant_id"
        else:
            runtime_facts_poller = RuntimeFactsPoller(
                fetch=settings.graph_reachability_bundle_fetcher or partial(fetch_runtime_facts_url, settings),
                signing_key=settings.graph_reachability_bundle_signing_key,
                tenant_id=settings.graph_reachability_bundle_tenant_id,
            )

    return runtime_facts_poller, runtime_facts_configured, runtime_facts_config_error


def gateway_lifespan(
    settings: GatewaySettings,
    policy_reload: GatewayPolicyReloader,
    firewall_reload: GatewayPolicyReloader,
    runtime_facts_poller: RuntimeFactsPoller | None,
    managed_upstream_relay: GatewayUpstreamRelay | None,
):
    reload_task: asyncio.Task[None] | None = None
    firewall_reload_task: asyncio.Task[None] | None = None
    runtime_facts_task: asyncio.Task[None] | None = None

    async def _runtime_facts_refresh_loop() -> None:
        assert runtime_facts_poller is not None
        while True:
            await asyncio.sleep(max(settings.graph_reachability_bundle_poll_interval_seconds, 0.1))
            await runtime_facts_poller.refresh()

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        nonlocal reload_task
        nonlocal firewall_reload_task
        nonlocal runtime_facts_task
        try:
            if isinstance(settings.audit_sink, GatewayAuditSinkBase):
                await settings.audit_sink.start()
            if settings.policy_path is not None:
                await policy_reload.reload(force=True)
                if settings.policy_reload_interval_seconds > 0:
                    reload_task = asyncio.create_task(policy_reload.run())
            if settings.firewall_policy_path is not None:
                await firewall_reload.reload(force=True)
                if settings.firewall_policy_reload_interval_seconds > 0:
                    firewall_reload_task = asyncio.create_task(firewall_reload.run())
            if runtime_facts_poller is not None:
                await runtime_facts_poller.refresh()
                if settings.graph_reachability_bundle_poll_interval_seconds > 0:
                    runtime_facts_task = asyncio.create_task(_runtime_facts_refresh_loop())
            yield
        finally:
            if managed_upstream_relay is not None:
                await managed_upstream_relay.aclose()
            await cancel_gateway_tasks(reload_task, firewall_reload_task, runtime_facts_task)
            reload_task = None
            firewall_reload_task = None
            runtime_facts_task = None
            if isinstance(settings.audit_sink, GatewayAuditSinkBase):
                await settings.audit_sink.aclose()

    return _lifespan


async def cancel_gateway_tasks(*tasks: asyncio.Task[None] | None) -> None:
    for task in tasks:
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass  # expected: the task was just cancelled
