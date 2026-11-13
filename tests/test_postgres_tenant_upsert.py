"""Contract for `write_tenant_row`, the tenant-scoped upsert shared by the stores.

PostgreSQL 16.16 (CVE-2026-120154) checks an ON CONFLICT DO UPDATE target row
against the UPDATE policies before user quals, so `ON CONFLICT ... DO UPDATE ...
WHERE t.tenant_id = EXCLUDED.tenant_id` now raises instead of updating zero rows
when the key belongs to another tenant. The helper never asks the server to
update a row it cannot see. The live behaviour is covered in
tests/test_postgres_integration.py; this pins the statement sequence, and runs
without the optional psycopg dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import pytest

from agent_bom.api.postgres_tenant_upsert import write_tenant_row


@dataclass
class _Cursor:
    rowcount: int


@dataclass
class _Conn:
    rowcounts: list[int]
    statements: list[str] = field(default_factory=list)
    params: list[tuple] = field(default_factory=list)

    def execute(self, query, params=None):
        assert isinstance(query, str)
        self.statements.append(" ".join(query.split()))
        self.params.append(tuple(params))
        return _Cursor(self.rowcounts.pop(0))


_ROW = {"credential_ref_id": "id-1", "enabled": 1, "tenant_id": "tenant-a", "created_at": "t0", "data": "{}"}


def _write(conn: _Conn) -> bool:
    return write_tenant_row(
        conn,
        table="credential_refs",
        key="credential_ref_id",
        tenant="tenant_id",
        row=_ROW,
        update=("enabled", "data"),
    )


def _kinds(conn: _Conn) -> list[str]:
    return [statement.split()[0] for statement in conn.statements]


def test_a_new_key_is_inserted_without_touching_a_conflicting_row():
    conn = _Conn([1])
    assert _write(conn) is True
    assert _kinds(conn) == ["INSERT"]
    assert conn.statements[0] == (
        "INSERT INTO credential_refs (credential_ref_id, enabled, tenant_id, created_at, data) "
        "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (credential_ref_id) DO NOTHING"
    )
    assert conn.params[0] == ("id-1", 1, "tenant-a", "t0", "{}")


def test_an_existing_row_of_the_same_tenant_is_updated_in_place():
    conn = _Conn([0, 1])
    assert _write(conn) is True
    assert _kinds(conn) == ["INSERT", "UPDATE"]
    assert conn.statements[1] == "UPDATE credential_refs SET enabled = %s, data = %s WHERE credential_ref_id = %s AND tenant_id = %s"
    assert conn.params[1] == (1, "{}", "id-1", "tenant-a")


def test_a_row_deleted_between_the_two_statements_is_inserted_again():
    conn = _Conn([0, 0, 1])
    assert _write(conn) is True
    assert _kinds(conn) == ["INSERT", "UPDATE", "INSERT"]


def test_a_key_owned_by_another_tenant_is_reported_not_written():
    conn = _Conn([0, 0, 0, 0])
    assert _write(conn) is False
    assert _kinds(conn) == ["INSERT", "UPDATE", "INSERT", "UPDATE"]


@pytest.mark.parametrize("field_name", ["table", "key", "tenant", "row", "update"])
def test_anything_but_a_plain_identifier_is_refused(field_name):
    hostile = 't"; DROP TABLE x; --'
    kwargs = {"table": "t", "key": "id", "tenant": "tenant_id", "row": {"id": "v", "tenant_id": "a", "data": "{}"}, "update": ("data",)}
    kwargs[field_name] = {
        "table": hostile,
        "key": hostile,
        "tenant": hostile,
        "row": {"id": "v", "tenant_id": "a", hostile: "{}"},
        "update": (hostile,),
    }[field_name]
    conn = _Conn([1])
    with pytest.raises(ValueError, match="identifier"):
        write_tenant_row(conn, **kwargs)
    assert conn.statements == []


def test_no_store_relies_on_a_tenant_qual_to_skip_a_foreign_conflict():
    """`DO UPDATE ... WHERE t.tenant_id = EXCLUDED.tenant_id` raises on 16.16+; use the helper.

    Only Postgres SQL (`%s` placeholders) is in scope: SQLite stores have no
    row-level security, so the same shape still updates zero rows there.
    """
    import re
    from pathlib import Path

    guard = re.compile(r"WHERE\s+\w+\.(?:tenant_id|team_id)\s*=\s*EXCLUDED\.(?:tenant_id|team_id)", re.I)
    src = Path(__file__).resolve().parent.parent / "src"
    offenders = []
    sqlite_seen = 0
    for path in src.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for match in guard.finditer(text):
            statement = text[text.rfind("INSERT INTO", 0, match.start()) : match.end()]
            if "%s" in statement:
                offenders.append(f"{path.relative_to(src)}:{text.count(chr(10), 0, match.start()) + 1}")
            elif "?" in statement:
                sqlite_seen += 1
    assert offenders == []
    assert sqlite_seen, "the scan no longer recognises the SQLite form, so it may be matching nothing"
