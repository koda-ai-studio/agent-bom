"""A seeded demo estate keeps its synthetic advisories in its own vulnerability DB.

The demo seed writes synthetic advisories with partial feed receipts. Written
to the worker's shared default DB, they made every later ``check`` on that
worker report "local vulnerability data is N days old" and exit incomplete.
"""

from __future__ import annotations

import sqlite3

from fastapi.testclient import TestClient

from agent_bom.db import schema
from agent_bom.intel_lookup import resolve_intel_db_path
from tests._vuln_db_isolation import shared_vuln_db_dirs


def test_the_demo_seed_writes_advisories_outside_the_shared_default_db(demo_estate_client: TestClient) -> None:
    del demo_estate_client
    for directory in shared_vuln_db_dirs():
        assert not (directory / "vulns.db").exists(), f"the demo seed wrote the shared vuln DB at {directory}"

    demo_db = resolve_intel_db_path()
    assert demo_db.parent not in shared_vuln_db_dirs()
    assert schema.DB_PATH == demo_db, "readers of the default DB must see the demo's own DB during the demo"
    with sqlite3.connect(demo_db) as conn:
        assert conn.execute("SELECT count(*) FROM vulns WHERE source = 'demo-advisory'").fetchone()[0] > 0
