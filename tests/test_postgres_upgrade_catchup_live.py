"""Revision 20261102_10 repairs databases migrated before the August schema edits.

Builds the pre-August shape (no ``fleet_endpoints``; ``trend_history`` without
``scan_id``) in a throwaway database, proves the store's trend upsert fails
there, then runs the revision and proves the upsert, the endpoint table and its
tenant isolation work. Runs in the real Postgres storage contract CI step;
skips without ``AGENT_BOM_POSTGRES_ADMIN_URL``.
"""

from __future__ import annotations

import importlib.util
import os
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_ADMIN_URL"), reason="AGENT_BOM_POSTGRES_ADMIN_URL is required")

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "deploy/supabase/postgres/alembic/versions/20261102_10_fleet_endpoints_trend_scan_identity.py"
TREND_UPSERT = (
    "INSERT INTO trend_history (timestamp, team_id, total_vulns, posture_score, posture_grade, scan_id) "
    "VALUES (%s, %s, 1, 70, 'C', %s) "
    "ON CONFLICT (team_id, scan_id) WHERE scan_id IS NOT NULL DO UPDATE SET timestamp = EXCLUDED.timestamp"
)


def _load_revision() -> Any:
    spec = importlib.util.spec_from_file_location("fleet_trend_catchup", MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def legacy_database() -> Iterator[Any]:
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    admin_url = os.environ["AGENT_BOM_POSTGRES_ADMIN_URL"]
    database = f"catchup_{uuid4().hex[:12]}"
    with psycopg.connect(admin_url, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
        admin.execute(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_rls_maintenance') "
            "THEN CREATE ROLE agent_bom_rls_maintenance NOLOGIN; END IF; "
            "IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_app') "
            "THEN CREATE ROLE agent_bom_app NOLOGIN NOSUPERUSER NOBYPASSRLS; END IF; END $$"
        )
    try:
        with psycopg.connect(make_conninfo(admin_url, dbname=database)) as conn:
            conn.execute(
                "CREATE FUNCTION public.abom_current_tenant() RETURNS TEXT LANGUAGE SQL STABLE AS "
                "$$ SELECT COALESCE(NULLIF(current_setting('app.tenant_id', true), ''), 'default') $$"
            )
            conn.execute(
                "CREATE FUNCTION public.abom_rls_bypass() RETURNS BOOLEAN LANGUAGE SQL STABLE AS "
                "$$ SELECT COALESCE(NULLIF(current_setting('app.bypass_rls', true), ''), '0') = '1' "
                "AND pg_has_role(session_user, 'agent_bom_rls_maintenance', 'MEMBER') $$"
            )
            conn.execute("""CREATE TABLE trend_history (id BIGSERIAL PRIMARY KEY, timestamp TEXT NOT NULL,
                team_id TEXT NOT NULL DEFAULT 'default', total_vulns INTEGER NOT NULL,
                critical INTEGER NOT NULL DEFAULT 0, high INTEGER NOT NULL DEFAULT 0,
                medium INTEGER NOT NULL DEFAULT 0, low INTEGER NOT NULL DEFAULT 0,
                posture_score REAL NOT NULL DEFAULT 0, posture_grade TEXT NOT NULL DEFAULT '')""")
            conn.execute("INSERT INTO trend_history (timestamp, team_id, total_vulns) VALUES ('2026-07-01T00:00:00Z', 'tenant-a', 4)")
            conn.commit()
            yield conn
    finally:
        with psycopg.connect(admin_url, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(database)))


def test_revision_repairs_a_database_migrated_before_the_august_schema_edits(legacy_database: Any) -> None:
    import psycopg

    conn = legacy_database
    with pytest.raises(psycopg.errors.UndefinedColumn):
        conn.execute(TREND_UPSERT, ("2026-11-02T00:00:00Z", "tenant-a", "scan-1"))
    conn.rollback()

    revision = _load_revision()
    revision.op = SimpleNamespace(execute=conn.execute)
    revision.upgrade()
    revision.upgrade()
    conn.commit()

    conn.execute(TREND_UPSERT, ("2026-11-02T00:00:00Z", "tenant-a", "scan-1"))
    conn.execute(TREND_UPSERT, ("2026-11-02T01:00:00Z", "tenant-a", "scan-1"))
    rows = conn.execute("SELECT team_id, scan_id, timestamp FROM trend_history ORDER BY id").fetchall()
    assert rows == [("tenant-a", None, "2026-07-01T00:00:00Z"), ("tenant-a", "scan-1", "2026-11-02T01:00:00Z")]

    forced = conn.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'fleet_endpoints'").fetchone()
    assert forced == (True, True)
    assert conn.execute("SELECT has_table_privilege('agent_bom_app', 'fleet_endpoints', 'INSERT')").fetchone() == (True,)
    conn.commit()

    conn.execute("SET ROLE agent_bom_app")
    conn.execute("SELECT set_config('app.tenant_id', 'tenant-a', false)")
    conn.execute(
        "INSERT INTO fleet_endpoints (tenant_id, endpoint_id, completeness, updated_at, data) "
        "VALUES ('tenant-a', 'laptop-1', 'complete', '2026-11-02T00:00:00Z', '{}'::jsonb)"
    )
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute(
            "INSERT INTO fleet_endpoints (tenant_id, endpoint_id, completeness, updated_at, data) "
            "VALUES ('tenant-b', 'laptop-2', 'complete', '2026-11-02T00:00:00Z', '{}'::jsonb)"
        )
    conn.rollback()
    conn.execute("SET ROLE agent_bom_app")
    conn.execute("SELECT set_config('app.tenant_id', 'tenant-b', false)")
    assert conn.execute("SELECT count(*) FROM fleet_endpoints").fetchone() == (0,)
    conn.execute("RESET ROLE")

    revision.downgrade()
    columns = {row[0] for row in conn.execute("SELECT column_name FROM information_schema.columns WHERE table_name = 'trend_history'")}
    assert "scan_id" in columns, "rollback keeps a column the previous release already uses"
