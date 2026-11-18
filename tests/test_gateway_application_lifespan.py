"""Extracted lifecycle preserves startup order and closes background resources."""

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from agent_bom.gateway_upstreams import UpstreamRegistry
from agent_bom.runtime.gateway_application_lifecycle import gateway_lifespan
from agent_bom.runtime.gateway_audit import GatewayAuditSinkBase
from agent_bom.runtime.gateway_settings import GatewaySettings


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_startup", [False, True])
async def test_lifecycle_cleans_up_on_normal_exit_and_failed_initial_policy(fail_startup):
    events = []
    stopped = []

    async def start():
        events.append("audit-start")

    async def close_audit():
        events.append("audit-close")

    async def close_relay():
        events.append("relay-close")

    async def reload_policy(*, force):
        assert force is True
        events.append("policy-load")
        if fail_startup:
            raise ValueError("fixture policy failure")

    async def reload_firewall(*, force):
        assert force is True
        events.append("firewall-load")

    async def refresh():
        events.append("facts-refresh")

    async def wait(name):
        try:
            await asyncio.Event().wait()
        finally:
            stopped.append(name)

    sink = AsyncMock(spec=GatewayAuditSinkBase)
    sink.start.side_effect = start
    sink.aclose.side_effect = close_audit
    settings = GatewaySettings(
        registry=UpstreamRegistry([]),
        policy={},
        audit_sink=sink,
        policy_path=Path("policy.json"),
        policy_reload_interval_seconds=1,
        firewall_policy_path=Path("firewall.json"),
        firewall_policy_reload_interval_seconds=1,
        graph_reachability_bundle_poll_interval_seconds=1,
    )
    policy = SimpleNamespace(reload=reload_policy, run=lambda: wait("policy"))
    firewall = SimpleNamespace(reload=reload_firewall, run=lambda: wait("firewall"))
    facts = SimpleNamespace(refresh=refresh)
    lifespan = gateway_lifespan(settings, policy, firewall, facts, SimpleNamespace(aclose=close_relay))
    if fail_startup:
        with pytest.raises(ValueError, match="fixture policy failure"):
            async with lifespan(None):
                pytest.fail("failed startup must not serve requests")
        assert events == ["audit-start", "policy-load", "relay-close", "audit-close"]
        assert stopped == []
    else:
        async with lifespan(None):
            await asyncio.sleep(0)
            assert events == ["audit-start", "policy-load", "firewall-load", "facts-refresh"]
        assert events[-2:] == ["relay-close", "audit-close"]
        assert stopped == ["policy", "firewall"]
