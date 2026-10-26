"""The legacy agent_id backfill stays inside each tenant when two tenants share an identity id."""

from __future__ import annotations

import json

from agent_bom.api.identity_local_store import SQLiteAgentIdentityStore


def test_backfill_never_copies_one_tenants_agent_id_onto_another(tmp_path) -> None:
    store = SQLiteAgentIdentityStore(str(tmp_path / "identities.db"))
    conn = store._conn
    for tenant, agent in (("tenant-a", "agent-a"), ("tenant-b", "agent-b")):
        conn.execute(
            "INSERT INTO agent_identities (identity_id, tenant_id, token_hash, status, issued_at, agent_id, data) "
            "VALUES (?, ?, ?, 'active', '2026-10-25T00:00:00Z', '', ?)",
            ("shared-id", tenant, f"hash-{tenant}", json.dumps({"agent_id": agent})),
        )
    conn.commit()

    store._backfill_agent_ids()

    rows = dict(conn.execute("SELECT tenant_id, agent_id FROM agent_identities WHERE identity_id = 'shared-id'").fetchall())
    assert rows == {"tenant-a": "agent-a", "tenant-b": "agent-b"}
