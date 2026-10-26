"""Minted API keys survive a restart when the API runs on a SQLite database."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.sqlite_key_store import SQLiteKeyStore


@pytest.fixture
def db(tmp_path):
    return str(tmp_path / "control-plane.db")


def test_minted_key_authenticates_after_restart(db):
    raw, key = create_api_key("ci", Role.ANALYST, tenant_id="tenant-a", scopes=["scan:read"], owner="ops@example.test")
    SQLiteKeyStore(db).add(key)

    restarted = SQLiteKeyStore(db)
    resolved = restarted.verify(raw)
    assert resolved is not None
    assert (resolved.key_id, resolved.tenant_id, resolved.role, resolved.scopes) == (key.key_id, "tenant-a", Role.ANALYST, ["scan:read"])
    assert resolved.expires_at == key.expires_at
    assert resolved.principal_id == "ops@example.test"
    assert restarted.has_keys()
    assert restarted.verify(raw[:-1] + ("x" if raw[-1] != "x" else "y")) is None


def test_only_hashes_are_stored(db):
    import sqlite3

    raw, key = create_api_key("ci", Role.VIEWER, tenant_id="tenant-a")
    SQLiteKeyStore(db).add(key)
    with sqlite3.connect(db) as conn:
        dump = "\n".join(conn.iterdump())
    assert raw not in dump
    assert key.key_hash in dump


def test_provisioned_invitation_key_survives_restart(db):
    raw, key = create_api_key("invited-owner", Role.ADMIN, tenant_id="tenant-new", scopes=["*"])
    SQLiteKeyStore(db).provision_tenant_key(key, team_name="Example Org")
    assert SQLiteKeyStore(db).verify(raw).tenant_id == "tenant-new"
    with pytest.raises(Exception):
        SQLiteKeyStore(db).provision_tenant_key(key, team_name="Example Org")


def test_keys_are_tenant_isolated(db):
    store = SQLiteKeyStore(db)
    raw_a, key_a = create_api_key("a", Role.ADMIN, tenant_id="tenant-a", principal_id="shared-user")
    raw_b, key_b = create_api_key("b", Role.ADMIN, tenant_id="tenant-b", principal_id="shared-user")
    store.add(key_a)
    store.add(key_b)

    assert [k.key_id for k in store.list_keys(tenant_id="tenant-a")] == [key_a.key_id]
    assert [k.key_id for k in store.list_keys(tenant_id="tenant-b")] == [key_b.key_id]
    assert store.verify(raw_a).tenant_id == "tenant-a"
    assert store.verify(raw_b).tenant_id == "tenant-b"

    assert store.revoke_by_principal_id("shared-user", tenant_id="tenant-a") == [key_a.key_id]
    restarted = SQLiteKeyStore(db)
    assert restarted.verify(raw_a) is None
    assert restarted.verify(raw_b) is not None

    assert restarted.delete_tenant("tenant-b") == 1
    assert restarted.list_keys(tenant_id="tenant-b") == []
    assert [k.key_id for k in restarted.list_keys(tenant_id="tenant-a")] == [key_a.key_id]


def test_revoke_and_rotation_state_persist(db):
    store = SQLiteKeyStore(db)
    raw_old, old = create_api_key("old", Role.ADMIN, tenant_id="tenant-a")
    raw_new, new = create_api_key("new", Role.ADMIN, tenant_id="tenant-a")
    store.add(old)
    store.add(new)
    overlap_until = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    assert store.mark_rotating(old.key_id, replacement_key_id=new.key_id, overlap_until=overlap_until)

    restarted = SQLiteKeyStore(db)
    rotated = restarted.get(old.key_id)
    assert (rotated.replacement_key_id, rotated.rotation_overlap_until) == (new.key_id, overlap_until)
    assert restarted.verify(raw_old) is not None

    assert restarted.remove(new.key_id)
    assert not restarted.remove(new.key_id)
    assert SQLiteKeyStore(db).verify(raw_new) is None
    assert SQLiteKeyStore(db).get(new.key_id).lifecycle_state() == "revoked"


def test_get_key_store_uses_sqlite_when_the_api_has_a_database(monkeypatch, db):
    from agent_bom.api import auth

    original = get_key_store()
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    try:
        monkeypatch.setenv("AGENT_BOM_DB", db)
        monkeypatch.setattr(auth, "_key_store", None)
        assert isinstance(get_key_store(), SQLiteKeyStore)
        assert auth.key_store_is_durable(get_key_store())

        monkeypatch.delenv("AGENT_BOM_DB")
        monkeypatch.setattr(auth, "_key_store", None)
        assert isinstance(get_key_store(), KeyStore)
        assert not auth.key_store_is_durable(get_key_store())
    finally:
        set_key_store(original)


@pytest.mark.parametrize("durable", [True, False])
def test_key_mint_response_reports_durability(monkeypatch, db, durable):
    from starlette.testclient import TestClient

    from agent_bom.api import server as api_server

    store = SQLiteKeyStore(db) if durable else KeyStore()
    raw_admin, admin = create_api_key("admin", Role.ADMIN, tenant_id="default", scopes=["*"])
    store.add(admin)
    original = get_key_store()
    set_key_store(store)
    try:
        client = TestClient(api_server.app)
        headers = {"Authorization": f"Bearer {raw_admin}"}
        created = client.post("/v1/auth/keys", json={"name": "ci", "role": "viewer", "scopes": ["*"]}, headers=headers)
        assert created.status_code == 201, created.text
        body = created.json()
        assert body["durable"] is durable
        if durable:
            assert "warning" not in body
        else:
            assert "restart" in body["warning"]

        rotated = client.post(f"/v1/auth/keys/{body['key_id']}/rotate", json={}, headers=headers)
        assert rotated.status_code == 201, rotated.text
        assert rotated.json()["durable"] is durable
    finally:
        set_key_store(original)
