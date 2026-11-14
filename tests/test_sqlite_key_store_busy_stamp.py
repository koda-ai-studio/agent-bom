"""A long write elsewhere in the database must not fail a valid key on its usage stamp."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from agent_bom.api import auth
from agent_bom.api.sqlite_key_store import SQLiteKeyStore


def _store(tmp_path: Path) -> tuple[SQLiteKeyStore, str, str]:
    store = SQLiteKeyStore(str(tmp_path / "keys.db"))
    raw, key = auth.create_api_key("ci", auth.Role.ANALYST, tenant_id="tenant-a")
    store.add(key)
    return store, raw, key.key_id


def _writer(tmp_path: Path) -> sqlite3.Connection:
    writer = sqlite3.connect(tmp_path / "keys.db", timeout=0.05)
    writer.execute("BEGIN IMMEDIATE")
    return writer


def test_valid_key_verifies_quickly_while_another_writer_holds_the_database(tmp_path: Path) -> None:
    store, raw, _key_id = _store(tmp_path)
    writer = _writer(tmp_path)
    try:
        began = time.monotonic()
        verified = store.verify(raw)
        elapsed = time.monotonic() - began
    finally:
        writer.rollback()
        writer.close()
    assert verified is not None and verified.tenant_id == "tenant-a"
    assert elapsed < 5, f"verify waited {elapsed:.1f}s for a usage stamp"


def test_invalid_and_revoked_keys_stay_refused_while_another_writer_holds_the_database(tmp_path: Path) -> None:
    store, raw, key_id = _store(tmp_path)
    removed = store.remove(key_id)
    assert removed is True
    writer = _writer(tmp_path)
    try:
        assert store.verify(raw) is None
        assert store.verify(raw[:12] + "x" * (len(raw) - 12)) is None
    finally:
        writer.rollback()
        writer.close()


def test_a_failed_write_does_not_leave_the_connection_unable_to_write(tmp_path: Path) -> None:
    store, _raw, key_id = _store(tmp_path)
    store._conn.execute("PRAGMA busy_timeout=10")
    writer = _writer(tmp_path)
    with pytest.raises(sqlite3.OperationalError):
        store.remove(key_id)
    writer.rollback()
    other = sqlite3.connect(tmp_path / "keys.db", timeout=0.05)
    other.execute("UPDATE api_keys SET name = 'changed'")
    other.commit()
    other.close()
    assert store.get(key_id) is not None
    removed = store.remove(key_id)
    assert removed is True
    writer.close()


def test_stamp_is_recorded_and_the_store_still_waits_for_other_writes_once_the_writer_leaves(tmp_path: Path) -> None:
    store, raw, key_id = _store(tmp_path)
    writer = _writer(tmp_path)
    store.verify(raw)
    writer.rollback()
    writer.close()
    assert store.get(key_id).last_used is None

    assert store.verify(raw) is not None
    assert store.get(key_id).last_used is not None
    assert store._conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
