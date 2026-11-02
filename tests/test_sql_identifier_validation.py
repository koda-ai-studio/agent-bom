"""SQLite helpers that interpolate table/column names reject anything but plain identifiers."""

from __future__ import annotations

import sqlite3

import pytest

from agent_bom.api.sqlite_rekey import primary_key_columns, rekey_table
from agent_bom.db.local_analytics_sqlite import table_columns
from agent_bom.db.sql_identifiers import validate_sql_column_list, validate_sql_identifier

_HOSTILE = ["t); DROP TABLE x; --", "t x", "", "1abc", "a" * 129, "t\x00", "main.t", '"t"']


@pytest.mark.parametrize("name", ["t", "_t", "fleet_agents", "T2", "a" * 128])
def test_plain_identifiers_pass(name: str) -> None:
    assert validate_sql_identifier(name) == name


@pytest.mark.parametrize("name", _HOSTILE)
def test_hostile_identifiers_are_rejected(name: str) -> None:
    with pytest.raises(ValueError):
        validate_sql_identifier(name)


def test_column_lists() -> None:
    assert validate_sql_column_list("id, tenant_id,\n  data") == "id, tenant_id,\n  data"
    for bad in ["", "id; DROP TABLE t", "id, (SELECT 1)", "id,"]:
        with pytest.raises(ValueError):
            validate_sql_column_list(bad)


@pytest.fixture
def conn() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute("CREATE TABLE items (id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, data TEXT)")
    connection.execute("CREATE TABLE victim (id TEXT)")
    connection.commit()
    return connection


@pytest.mark.parametrize("name", _HOSTILE)
def test_pragma_helpers_reject_hostile_names_before_executing(conn: sqlite3.Connection, name: str) -> None:
    with pytest.raises(ValueError):
        table_columns(conn, name)
    with pytest.raises(ValueError):
        primary_key_columns(conn, name)
    assert conn.execute("SELECT name FROM sqlite_master WHERE name = 'victim'").fetchone() is not None


def test_rekey_rejects_hostile_table_and_columns(conn: sqlite3.Connection) -> None:
    template = "CREATE TABLE {table} (id TEXT, tenant_id TEXT NOT NULL, data TEXT, PRIMARY KEY (tenant_id, id))"
    with pytest.raises(ValueError):
        rekey_table(conn, "items; DROP TABLE victim", key=["tenant_id", "id"], create_sql=template, columns="id")
    with pytest.raises(ValueError):
        rekey_table(conn, "items", key=["tenant_id", "id"], create_sql=template, columns="id FROM victim; --")
    assert conn.execute("SELECT name FROM sqlite_master WHERE name = 'victim'").fetchone() is not None


def test_rekey_still_rebuilds_a_valid_table(conn: sqlite3.Connection) -> None:
    conn.execute("INSERT INTO items VALUES ('a', 't1', '{}')")
    conn.commit()
    template = "CREATE TABLE {table} (id TEXT, tenant_id TEXT NOT NULL, data TEXT, PRIMARY KEY (tenant_id, id))"
    assert rekey_table(conn, "items", key=["tenant_id", "id"], create_sql=template, columns="id, tenant_id, data") is True
    assert primary_key_columns(conn, "items") == ["tenant_id", "id"]
    assert table_columns(conn, "items") == {"id", "tenant_id", "data"}
    assert conn.execute("SELECT id, tenant_id FROM items").fetchall() == [("a", "t1")]
