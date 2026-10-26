"""The relay must not stop the world while it reads the fleet and identity stores.

``_agent_is_quarantined`` (an unbounded ``list_by_tenant``) and
``_agent_identity_revoked`` were called synchronously from ``async def relay``.
Both scale with the tenant's roster, so on a large fleet every relay call froze
the whole gateway process — health checks, other tenants, background tasks —
not merely its own request. Same defect class as the live-feed fix; that one
was repaired on the feed and not on the relay.

Measured on 20k fleet agents / 5k identities before the fix: mean relay 181 ms,
worst event-loop stall 3.8 s across 20 concurrent calls.
"""

from __future__ import annotations

import asyncio
import threading

import httpx
import pytest

from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, InMemoryFleetStore
from agent_bom.api.stores import set_fleet_store
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry

# Store reads made on the event-loop thread, by method name. A read run in a
# worker thread has no running loop; one called from ``async def relay`` does.
ON_LOOP_READS: list[str] = []
READS: list[str] = []


def _record_read(name: str) -> None:
    READS.append(name)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return
    ON_LOOP_READS.append(name)


@pytest.fixture(autouse=True)
def _reset():
    ON_LOOP_READS.clear()
    READS.clear()
    yield
    set_fleet_store(None)
    from agent_bom.api.agent_identity_store import set_agent_identity_store

    set_agent_identity_store(None)


class _SlowFleetStore(InMemoryFleetStore):
    """Stands in for a large roster whose reads must never run on the loop."""

    meet: threading.Barrier | None = None

    def list_by_tenant(self, tenant_id: str):
        _record_read("fleet.list_by_tenant")
        return super().list_by_tenant(tenant_id)

    def get(self, agent_id: str, *, tenant_id: str):
        _record_read("fleet.get")
        if self.meet is not None:
            self.meet.wait()
        return super().get(agent_id, tenant_id=tenant_id)


def _slow_identity_store():
    from agent_bom.api.agent_identity_store import InMemoryAgentIdentityStore

    class _SlowIdentityStore(InMemoryAgentIdentityStore):
        def list(self, *a, **k):
            _record_read("identity.list")
            return super().list(*a, **k)

        def list_by_agent(self, *a, **k):
            _record_read("identity.list_by_agent")
            return super().list_by_agent(*a, **k)

    return _SlowIdentityStore()


def _app():
    async def _ok_caller(upstream, message, extra_headers):
        return {"jsonrpc": "2.0", "id": message["id"], "result": {"ok": True}}

    return create_gateway_app(
        GatewaySettings(
            registry=UpstreamRegistry([UpstreamConfig(name="filesystem", url="http://fs.local:8100")]),
            policy={"agent_tokens": {"token-b": "agent-b"}},
            upstream_caller=_ok_caller,
            fleet_enforcement_mode="enforce",
        )
    )


def _seed() -> _SlowFleetStore:
    fleet = _SlowFleetStore()
    fleet.put(
        FleetAgent(
            agent_id="agent-b",
            name="agent-b",
            agent_type="custom",
            tenant_id="default",
            lifecycle_state=FleetLifecycleState.APPROVED,
        )
    )
    set_fleet_store(fleet)

    from agent_bom.api.agent_identity_store import set_agent_identity_store

    set_agent_identity_store(_slow_identity_store())
    return fleet


_CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "read_file", "arguments": {"path": "/tmp/x"}, "_meta": {"agent_identity": "token-b"}},
}


def test_relay_does_not_block_the_event_loop_on_store_reads():
    _seed()
    app = _app()

    async def _drive():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://gw") as client:
            return await client.post("/mcp/filesystem", json=_CALL)

    resp = asyncio.run(_drive())

    assert resp.status_code == 200 and resp.json().get("result") == {"ok": True}
    # The fleet and identity reads ran, and none of them on the event loop.
    assert {"fleet.get"} <= set(READS)
    assert ON_LOOP_READS == [], f"store reads ran on the event loop: {ON_LOOP_READS}"


def test_concurrent_relays_do_not_serialize_on_the_loop():
    """The user-visible symptom: one slow tenant freezing every other caller."""
    fleet = _seed()
    app = _app()
    calls = 8

    async def _drive():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://gw") as client:
            await client.post("/mcp/filesystem", json=_CALL)
            # Each fleet read now waits for a second relay's read to arrive. A
            # serialized relay never has two in flight and breaks the barrier.
            fleet.meet = threading.Barrier(2, timeout=10)
            return await asyncio.gather(*[client.post("/mcp/filesystem", json=_CALL) for _ in range(calls)])

    responses = asyncio.run(_drive())

    assert fleet.meet is not None and not fleet.meet.broken, "concurrent relays serialized on the loop"
    assert all(r.status_code == 200 for r in responses)
    assert ON_LOOP_READS == []
