"""Operator-configured API keys never expire, seed idempotently and retire when removed from config."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from agent_bom.api import server as api_server
from agent_bom.api.auth import KeyStore, get_key_store, set_key_store

ADMIN_KEY = "operator-admin-secret-0001"
VIEWER_KEY = "operator-viewer-secret-0002"
RUNTIME_KEY = "operator-runtime-secret-0003"


@pytest.fixture(autouse=True)
def _short_ttl(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS", "60")
    monkeypatch.setenv("AGENT_BOM_API_KEY_MAX_TTL_SECONDS", "60")
    original = get_key_store()
    yield
    set_key_store(original)
    api_server._env_api_keys_seeded = False
    api_server._runtime_api_key_seeded = False


def _boot(monkeypatch, store, keys: str | None, runtime_key: str | None = None):
    """Simulate one process start against ``store``."""
    from agent_bom.api import api_key_record

    monkeypatch.setattr(api_key_record, "_active_operator_key_ids", {})
    set_key_store(store)
    api_server._env_api_keys_seeded = False
    api_server._runtime_api_key_seeded = False
    if keys is None:
        monkeypatch.delenv("AGENT_BOM_API_KEYS", raising=False)
    else:
        monkeypatch.setenv("AGENT_BOM_API_KEYS", keys)
    api_server._seed_api_key_store_from_env()
    api_server._seed_runtime_api_key(runtime_key)


def _store_factories():
    def memory(_tmp_path):
        return KeyStore()

    def sqlite(tmp_path):
        from agent_bom.api.sqlite_key_store import SQLiteKeyStore

        return SQLiteKeyStore(str(tmp_path / "keys.db"))

    return [pytest.param(memory, id="memory"), pytest.param(sqlite, id="sqlite")]


@pytest.mark.parametrize("factory", _store_factories())
def test_env_and_runtime_keys_do_not_expire_under_a_short_ttl(monkeypatch, tmp_path, factory):
    store = factory(tmp_path)
    _boot(monkeypatch, store, f"{ADMIN_KEY}:admin", runtime_key=RUNTIME_KEY)

    later = datetime.now(timezone.utc) + timedelta(days=400)
    for raw in (ADMIN_KEY, RUNTIME_KEY):
        key = store.verify(raw)
        assert key is not None
        assert key.expires_at is None
        assert key.is_usable(now=later)
        assert key.tenant_id == "default"


@pytest.mark.parametrize("factory", _store_factories())
def test_repeated_boots_keep_one_row_per_configured_key(monkeypatch, tmp_path, factory):
    first = factory(tmp_path)
    _boot(monkeypatch, first, f"{ADMIN_KEY}:admin,{VIEWER_KEY}:viewer", runtime_key=RUNTIME_KEY)
    store = first
    for _ in range(3):
        store = first if isinstance(first, KeyStore) else factory(tmp_path)
        _boot(monkeypatch, store, f"{ADMIN_KEY}:admin,{VIEWER_KEY}:viewer", runtime_key=RUNTIME_KEY)

    keys = store.list_keys(tenant_id="default")
    assert sorted(key.name for key in keys) == ["env:admin:1", "env:viewer:2", "runtime:admin"]
    assert store.verify(ADMIN_KEY).role.value == "admin"
    assert store.verify(VIEWER_KEY).role.value == "viewer"


@pytest.mark.parametrize("factory", _store_factories())
def test_key_removed_from_config_stops_working_on_next_boot(monkeypatch, tmp_path, factory):
    store = factory(tmp_path)
    _boot(monkeypatch, store, f"{ADMIN_KEY}:admin,{VIEWER_KEY}:viewer", runtime_key=RUNTIME_KEY)
    assert store.verify(VIEWER_KEY) is not None

    store = store if isinstance(store, KeyStore) else factory(tmp_path)
    _boot(monkeypatch, store, f"{ADMIN_KEY}:admin", runtime_key=None)
    assert store.verify(ADMIN_KEY) is not None
    assert store.verify(VIEWER_KEY) is None
    assert store.verify(RUNTIME_KEY) is None

    store = store if isinstance(store, KeyStore) else factory(tmp_path)
    _boot(monkeypatch, store, None)
    assert store.verify(ADMIN_KEY) is None


def test_rotating_a_configured_key_retires_the_previous_value(monkeypatch, tmp_path):
    from agent_bom.api.sqlite_key_store import SQLiteKeyStore

    path = str(tmp_path / "keys.db")
    _boot(monkeypatch, SQLiteKeyStore(path), f"{ADMIN_KEY}:admin")
    store = SQLiteKeyStore(path)
    _boot(monkeypatch, store, "operator-admin-secret-9999:admin")
    assert store.verify(ADMIN_KEY) is None
    assert store.verify("operator-admin-secret-9999") is not None
    assert len(store.list_keys(tenant_id="default")) == 1


def test_minted_keys_still_use_the_ttl_policy():
    from agent_bom.api.auth import Role, create_api_key

    _, key = create_api_key("ci", Role.VIEWER)
    assert key.expires_at is not None
    assert not key.key_id.startswith("operator-")


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="AGENT_BOM_POSTGRES_URL not set")
def test_postgres_repeated_boots_keep_one_row_and_retire_removed_keys(monkeypatch):
    from agent_bom.api.postgres_access import PostgresKeyStore
    from agent_bom.api.postgres_common import _maintenance_connection, bypass_tenant_rls, reset_pool

    def purge() -> None:
        with bypass_tenant_rls(), _maintenance_connection() as conn:
            conn.execute("DELETE FROM api_keys WHERE key_id LIKE 'operator-%'")
            conn.commit()

    def operator_rows() -> list[tuple[str, bool, str | None]]:
        with bypass_tenant_rls(), _maintenance_connection() as conn:
            return conn.execute(
                "SELECT key_id, revoked, expires_at FROM api_keys WHERE key_id LIKE 'operator-%' ORDER BY key_id"
            ).fetchall()

    reset_pool()
    purge()
    try:
        for _ in range(3):
            _boot(monkeypatch, PostgresKeyStore(), f"{ADMIN_KEY}:admin,{VIEWER_KEY}:viewer")
        assert operator_rows() == [("operator-env-1", False, None), ("operator-env-2", False, None)]

        store = PostgresKeyStore()
        _boot(monkeypatch, store, f"{ADMIN_KEY}:admin")
        assert store.verify(ADMIN_KEY) is not None
        assert store.verify(VIEWER_KEY) is None
        assert [row[:2] for row in operator_rows()] == [("operator-env-1", False), ("operator-env-2", True)]
    finally:
        purge()
        reset_pool()


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="AGENT_BOM_POSTGRES_URL not set")
def test_postgres_operator_session_binding_survives_reload_but_not_rotation(monkeypatch):
    from fastapi import HTTPException

    from agent_bom.api.auth import Role
    from agent_bom.api.browser_session import create_browser_session_token, verify_browser_session_token
    from agent_bom.api.postgres_access import PostgresKeyStore
    from agent_bom.api.postgres_common import reset_pool
    from agent_bom.api.session_authorization import authorize_browser_session

    reset_pool()
    store = PostgresKeyStore()
    _boot(monkeypatch, store, f"{ADMIN_KEY}:admin")
    record = store.verify(ADMIN_KEY)
    assert record is not None
    token, _ = create_browser_session_token(
        subject=record.name,
        role="admin",
        tenant_id="default",
        key_id=record.key_id,
        auth_method="browser_session",
        operator_key_hash=record.key_hash,
        max_age_seconds=300,
    )
    payload = verify_browser_session_token(token)

    def authorize():
        return authorize_browser_session(
            role=Role.ADMIN,
            scopes=[],
            tenant_id="default",
            key_id=record.key_id,
            auth_method="browser_session",
            method="GET",
            path="/v1/scan",
            operator_binding=payload["operator_key_binding"],
            nonce=payload["nonce"],
        )

    try:
        _boot(monkeypatch, PostgresKeyStore(), f"{ADMIN_KEY}:admin")
        assert authorize()[0] == Role.ADMIN
        _boot(monkeypatch, PostgresKeyStore(), f"{ADMIN_KEY}:viewer")
        assert authorize()[0] == Role.VIEWER
        _boot(monkeypatch, PostgresKeyStore(), f"{VIEWER_KEY}:viewer")
        with pytest.raises(HTTPException) as error:
            authorize()
        assert error.value.status_code == 401
    finally:
        store.remove(record.key_id)
        reset_pool()
