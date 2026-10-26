"""Legacy fleet backfills rewrite only the row they read, never the same agent id in another tenant."""

from __future__ import annotations

from agent_bom.api.fleet_models import FleetAgent
from agent_bom.api.fleet_store import SQLiteFleetStore


def _agent(tenant: str, name: str, fingerprint: str) -> FleetAgent:
    return FleetAgent(agent_id="shared-agent", name=name, agent_type="claude-code", tenant_id=tenant, device_fingerprint=fingerprint)


def test_backfills_stay_inside_each_tenant(tmp_path) -> None:
    store = SQLiteFleetStore(str(tmp_path / "fleet.db"))
    store.put(_agent("tenant-a", "laptop-a", "fp-a"))
    store.put(_agent("tenant-b", "laptop-b", "fp-b"))
    store._conn.execute("UPDATE fleet_agents SET canonical_id = '', device_fingerprint = ''")
    store._conn.commit()

    store._backfill_canonical_ids()
    store._backfill_device_fingerprints()

    a = store.get("shared-agent", tenant_id="tenant-a")
    b = store.get("shared-agent", tenant_id="tenant-b")
    assert (a.name, a.device_fingerprint, a.tenant_id) == ("laptop-a", "fp-a", "tenant-a")
    assert (b.name, b.device_fingerprint, b.tenant_id) == ("laptop-b", "fp-b", "tenant-b")
    columns = dict(store._conn.execute("SELECT tenant_id, device_fingerprint FROM fleet_agents").fetchall())
    assert columns == {"tenant-a": "fp-a", "tenant-b": "fp-b"}
