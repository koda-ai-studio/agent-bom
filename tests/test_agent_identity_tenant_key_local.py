"""SQLite and in-memory identity stores key rows by (tenant_id, identity_id), as Postgres does."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, replace

import pytest

from agent_bom.api.agent_identity_store import AgentIdentity, InMemoryAgentIdentityStore, SQLiteAgentIdentityStore


def _identity(tenant_id: str, identity_id: str = "id-1", *, status: str = "active") -> AgentIdentity:
    return AgentIdentity(
        identity_id=identity_id,
        agent_id=f"agent-{tenant_id}",
        tenant_id=tenant_id,
        token_hash=f"hash-{tenant_id}-{identity_id}",
        token_prefix="abid",
        role="agent",
        blueprint_id="",
        status=status,
        issued_at=f"2026-10-2{len(tenant_id) % 10}T00:00:00+00:00",
        expires_at="2027-10-24T00:00:00+00:00",
    )


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    return InMemoryAgentIdentityStore() if request.param == "memory" else SQLiteAgentIdentityStore(str(tmp_path / "identity.db"))


def test_a_second_tenant_with_the_same_identity_id_does_not_overwrite_the_first(store):
    store.put(_identity("tenant-a"))
    store.put(_identity("tenant-b", status="revoked"))

    mine = store.get("id-1", tenant_id="tenant-a")
    assert mine is not None and mine.tenant_id == "tenant-a" and mine.status == "active"
    theirs = store.get("id-1", tenant_id="tenant-b")
    assert theirs is not None and theirs.tenant_id == "tenant-b" and theirs.status == "revoked"
    assert [i.tenant_id for i in store.list("tenant-a", include_inactive=True)] == ["tenant-a"]
    assert [i.tenant_id for i in store.list("tenant-b", include_inactive=True)] == ["tenant-b"]
    assert store.count("tenant-a", include_inactive=True) == 1
    assert store.list_by_agent("tenant-a", "agent-tenant-b") == []
    assert store.get_by_token_hash("hash-tenant-a-id-1").tenant_id == "tenant-a"
    assert store.get_by_token_hash("hash-tenant-b-id-1").tenant_id == "tenant-b"
    assert sorted(i.tenant_id for i in store.iter_all_identities()) == ["tenant-a", "tenant-b"]


def test_an_upsert_updates_only_its_own_tenants_row(store):
    store.put(_identity("tenant-a"))
    store.put(_identity("tenant-b"))
    store.put(replace(_identity("tenant-a"), status="revoked"))
    assert store.get("id-1", tenant_id="tenant-a").status == "revoked"
    assert store.get("id-1", tenant_id="tenant-b").status == "active"


def test_a_token_hash_stays_globally_unique(store):
    store.put(_identity("tenant-a"))
    stolen = replace(_identity("tenant-b", "id-2"), token_hash="hash-tenant-a-id-1")
    with pytest.raises((sqlite3.IntegrityError, ValueError)):
        store.put(stolen)
    assert store.get("id-1", tenant_id="tenant-a") is not None
    assert store.get_by_token_hash("hash-tenant-a-id-1").tenant_id == "tenant-a"
    assert store.get("id-2", tenant_id="tenant-b") is None


def test_a_reissued_token_hash_no_longer_resolves_the_old_one(store):
    store.put(_identity("tenant-a"))
    store.put(replace(_identity("tenant-a"), token_hash="hash-new"))
    assert store.get_by_token_hash("hash-tenant-a-id-1") is None
    assert store.get_by_token_hash("hash-new").tenant_id == "tenant-a"


_LEGACY_SCHEMA = """
CREATE TABLE agent_identities (
    identity_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    issued_at TEXT NOT NULL,
    agent_id TEXT NOT NULL DEFAULT '',
    data TEXT NOT NULL
)
"""


def _primary_key(path: str) -> list[str]:
    with sqlite3.connect(path) as conn:
        rows = conn.execute("PRAGMA table_info(agent_identities)").fetchall()
    return [row[1] for row in sorted((row for row in rows if row[5]), key=lambda row: row[5])]


def test_a_pre_change_database_migrates_keeping_every_row(tmp_path):
    path = str(tmp_path / "legacy.db")
    legacy = [_identity("tenant-a"), _identity("tenant-b", "id-2", status="revoked")]
    with sqlite3.connect(path) as conn:
        conn.execute(_LEGACY_SCHEMA)
        conn.executemany(
            "INSERT INTO agent_identities (identity_id, tenant_id, token_hash, status, issued_at, agent_id, data) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(i.identity_id, i.tenant_id, i.token_hash, i.status, i.issued_at, i.agent_id, json.dumps(asdict(i))) for i in legacy],
        )
    assert _primary_key(path) == ["identity_id"]

    store = SQLiteAgentIdentityStore(path)
    assert _primary_key(path) == ["tenant_id", "identity_id"]
    assert store.get("id-1", tenant_id="tenant-a") == legacy[0]
    assert store.get("id-2", tenant_id="tenant-b") == legacy[1]
    assert store.get_by_token_hash("hash-tenant-b-id-2") == legacy[1]
    store.put(_identity("tenant-b"))
    assert store.get("id-1", tenant_id="tenant-a") == legacy[0]

    SQLiteAgentIdentityStore(path)
    assert _primary_key(path) == ["tenant_id", "identity_id"]
    assert len(SQLiteAgentIdentityStore(path).iter_all_identities()) == 3
    with sqlite3.connect(path) as conn:
        indexes = {row[1] for row in conn.execute("PRAGMA index_list(agent_identities)").fetchall()}
        version = conn.execute("SELECT version FROM control_plane_schema_versions WHERE component = 'agent_identities'").fetchone()
    assert {"idx_agent_identities_tenant", "idx_agent_identities_agent"} <= indexes
    assert version == (3,)


def test_a_fresh_database_starts_tenant_keyed(tmp_path):
    path = str(tmp_path / "fresh.db")
    SQLiteAgentIdentityStore(path)
    assert _primary_key(path) == ["tenant_id", "identity_id"]
