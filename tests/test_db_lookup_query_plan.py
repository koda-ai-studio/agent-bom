"""The single-package advisory lookup seeks by package name, not by ecosystem alone.

Small projects (under the batch threshold) take this path on every scan, and an
ecosystem-only scan touches every advisory row for npm or a distro feed.
"""

from __future__ import annotations

import json
import sqlite3

from agent_bom.db.lookup import lookup_package
from agent_bom.db.schema import init_db
from agent_bom.db.sync import _ingest_osv_file


def _advisory(vuln_id: str, name: str) -> dict:
    return {
        "id": vuln_id,
        "summary": "lookup plan fixture",
        "affected": [
            {
                "package": {"name": name, "ecosystem": "npm"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }
        ],
    }


class _RecordingConnection:
    """Records each statement with its bound parameters.

    The planner must see the parameterized SQL: literal-expanded SQL (what a
    trace callback reports) can be planned differently.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self.calls: list[tuple[str, tuple]] = []

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        self.calls.append((sql, tuple(params)))
        return self._conn.execute(sql, params)

    def __getattr__(self, name: str):
        return getattr(self._conn, name)


def _lookup_select_plans(conn: sqlite3.Connection, name: str) -> tuple[list[str], list]:
    recorder = _RecordingConnection(conn)
    results = lookup_package(recorder, "npm", name, "1.0.0")  # type: ignore[arg-type]
    selects = [(sql, params) for sql, params in recorder.calls if "FROM affected a" in sql and "JOIN vulns v" in sql]
    assert selects, recorder.calls
    plans = [str(row[3]) for sql, params in selects for row in conn.execute("EXPLAIN QUERY PLAN " + sql, params)]
    return plans, results


def test_single_package_lookup_uses_the_package_name_index(tmp_path) -> None:
    conn = init_db(tmp_path / "plan.db")
    try:
        for index in range(30):
            _ingest_osv_file(conn, json.dumps(_advisory(f"OSV-PLAN-{index}", f"other-{index}")).encode(), f"o{index}.json")
        _ingest_osv_file(conn, json.dumps(_advisory("OSV-PLAN-TARGET", "target-pkg")).encode(), "t.json")

        plans, results = _lookup_select_plans(conn, "target-pkg")
    finally:
        conn.close()

    affected_plan = [plan for plan in plans if plan.startswith("SEARCH a ")]
    assert affected_plan, plans
    assert all("package_name=?" in plan for plan in affected_plan), plans
    assert [vuln.id for vuln in results] == ["OSV-PLAN-TARGET"]
