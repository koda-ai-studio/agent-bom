"""Run against an explicitly supplied private Postgres cluster.

AGENT_BOM_TEST_TREND_POSTGRES_URL must identify a disposable administrative
instance. Each test creates a new database and unprivileged role; shared
application databases are never used.
"""

from __future__ import annotations

import importlib.util
import os
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from agent_bom.baseline import TrendPoint

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_TEST_TREND_POSTGRES_URL"), reason="private Postgres instance required")


def test_live_kev_migration_rls_replay_and_evidence_preserving_rollback(monkeypatch):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from psycopg_pool import ConnectionPool

    from agent_bom.api.postgres_audit import PostgresTrendStore
    from agent_bom.api.postgres_common import _ensure_tenant_rls

    admin_url = os.environ["AGENT_BOM_TEST_TREND_POSTGRES_URL"]
    suffix = uuid4().hex[:12]
    database = f"kev_{suffix}"
    role = f"kev_app_{suffix}"
    with psycopg.connect(admin_url, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT").format(sql.Identifier(role)))
        admin.execute(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='agent_bom_rls_maintenance') "
            "THEN CREATE ROLE agent_bom_rls_maintenance NOLOGIN; END IF; END $$"
        )
    owner_url = make_conninfo(admin_url, dbname=database)
    app_url = make_conninfo(owner_url, user=role)
    migration_path = Path(__file__).parents[1] / "deploy/supabase/postgres/alembic/versions/20261022_01_trend_kev_count.py"
    spec = importlib.util.spec_from_file_location("trend_kev_migration", migration_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with psycopg.connect(owner_url) as owner:
        owner.execute(
            "CREATE TABLE control_plane_schema_versions (component TEXT PRIMARY KEY, "
            "version INTEGER NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        owner.execute("INSERT INTO control_plane_schema_versions(component,version) VALUES ('trend_history',2)")
        owner.execute("""CREATE TABLE trend_history (id BIGSERIAL PRIMARY KEY, timestamp TEXT NOT NULL,
            team_id TEXT NOT NULL, total_vulns INTEGER NOT NULL, critical INTEGER NOT NULL,
            high INTEGER NOT NULL, medium INTEGER NOT NULL, low INTEGER NOT NULL,
            posture_score REAL NOT NULL, posture_grade TEXT NOT NULL, scan_id TEXT,
            comparison_metadata TEXT NOT NULL DEFAULT '{}')""")
        owner.execute("CREATE UNIQUE INDEX trend_scan ON trend_history(team_id,scan_id) WHERE scan_id IS NOT NULL")
        owner.execute(
            "INSERT INTO trend_history(timestamp,team_id,total_vulns,critical,high,medium,low,posture_score,posture_grade,scan_id) "
            "VALUES ('2026-10-18T00:00:00Z','a',1,1,0,0,0,70,'C','legacy')"
        )
        monkeypatch.setattr(module, "op", SimpleNamespace(execute=owner.execute))
        module.upgrade()
        module.upgrade()
        assert owner.execute("SELECT kev_count FROM trend_history").fetchone() == (None,)
        _ensure_tenant_rls(owner, "trend_history", "team_id")
        owner.execute(sql.SQL("GRANT SELECT ON control_plane_schema_versions TO {}").format(sql.Identifier(role)))
        owner.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE ON trend_history TO {}").format(sql.Identifier(role)))
        owner.execute(sql.SQL("GRANT USAGE ON SEQUENCE trend_history_id_seq TO {}").format(sql.Identifier(role)))
        owner.commit()
        monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", app_url)
        with ConnectionPool(app_url, min_size=1, max_size=2) as pool:
            store = PostgresTrendStore(pool=pool)
            point = TrendPoint(
                timestamp="2026-10-19T00:00:00Z",
                total_vulns=3,
                critical=1,
                high=2,
                medium=0,
                low=0,
                posture_score=70,
                posture_grade="C",
                tenant_id="a",
                scan_id="current",
                kev_count=2,
            )
            store.record(point)
            store.record(replace(point, kev_count=1))
            store.record(replace(point, tenant_id="b", kev_count=0))
            assert [p.kev_count for p in store.get_history(tenant_id="a")] == [1, None]
            assert [p.kev_count for p in store.get_history(tenant_id="b")] == [0]
            assert store.get_history(tenant_id="outsider") == []
        with owner.transaction():
            with pytest.raises(psycopg.errors.CheckViolation):
                with owner.transaction():
                    owner.execute("UPDATE trend_history SET kev_count=-1")
        module.downgrade()
        assert owner.execute("SELECT version FROM control_plane_schema_versions WHERE component='trend_history'").fetchone() == (2,)
        assert owner.execute("SELECT kev_count FROM trend_history WHERE team_id='a' AND scan_id='current'").fetchone() == (1,)
        module.upgrade()
        assert owner.execute("SELECT version FROM control_plane_schema_versions WHERE component='trend_history'").fetchone() == (3,)
        assert owner.execute("SELECT kev_count FROM trend_history WHERE team_id='a' AND scan_id='current'").fetchone() == (1,)
