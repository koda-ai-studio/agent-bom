"""Operator advisories on Postgres: backend selection, migration contract, RLS isolation."""

from __future__ import annotations

import json
import os
import re
import uuid
from pathlib import Path

import pytest

from agent_bom.api import stores

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "deploy/supabase/postgres/alembic/versions/20261023_01_operator_advisories.py"
RUNTIME_SCHEMA = ROOT / "deploy/supabase/postgres/runtime-schema.sql"
ADVISORY = json.loads((ROOT / "tests/fixtures/php2shell/operator-advisory.json").read_text())
TABLES = ("operator_advisories", "operator_advisory_rematch_state")


@pytest.mark.parametrize("variable", ["AGENT_BOM_DB", "AGENT_BOM_POSTGRES_URL"])
def test_postgres_deployment_selects_postgres_store(monkeypatch: pytest.MonkeyPatch, variable: str) -> None:
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setenv(variable, "postgresql://fixture.invalid/advisories")
    monkeypatch.setattr(stores, "_operator_advisory_store", None)
    selected = lambda: (_ for _ in ()).throw(RuntimeError("selected Postgres"))  # noqa: E731
    monkeypatch.setattr("agent_bom.api.postgres_common._get_pool", selected)
    monkeypatch.setattr("agent_bom.api.postgres_operator_advisory._get_pool", selected)
    with pytest.raises(RuntimeError, match="selected Postgres"):
        stores._get_operator_advisory_store()


def _executed_sql(monkeypatch: pytest.MonkeyPatch, step: str) -> str:
    import importlib.util

    spec = importlib.util.spec_from_file_location("operator_advisories_migration", MIGRATION)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    statements: list[str] = []
    monkeypatch.setattr(module.op, "execute", lambda sql: statements.append(" ".join(str(sql).split())))
    getattr(module, step)()
    return "\n".join(statements)


def test_migration_is_chained_tenant_isolated_and_mirrored_in_runtime_schema(monkeypatch: pytest.MonkeyPatch) -> None:
    source = MIGRATION.read_text()
    assert re.search(r'^revision\s*=\s*"20261023_01"', source, re.M)
    assert re.search(r'^down_revision\s*=\s*"20261022_01"', source, re.M)
    sql = _executed_sql(monkeypatch, "upgrade")
    runtime = RUNTIME_SCHEMA.read_text()
    for table in TABLES:
        assert f"CREATE TABLE IF NOT EXISTS {table}" in sql
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in sql
        assert f"CREATE POLICY {table}_tenant_isolation ON {table}" in sql
        assert f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO agent_bom_app" in sql
        assert f"CREATE TABLE IF NOT EXISTS {table}" in runtime
        assert f"'{table}'" in runtime
    assert "VALUES ('operator_advisories', 1, now())" in sql
    assert "DISABLE ROW LEVEL SECURITY" not in sql
    downgrade = _executed_sql(monkeypatch, "downgrade")
    assert "DROP TABLE IF EXISTS operator_advisories" in downgrade


def _require_postgres() -> None:
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires restricted-role Postgres (AGENT_BOM_POSTGRES_URL)")


def test_postgres_store_round_trip_and_cross_tenant_isolation() -> None:
    _require_postgres()
    from psycopg.errors import InsufficientPrivilege

    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_operator_advisory import PostgresOperatorAdvisoryStore
    from tests.test_postgres_job_evidence_revision import tenant_scope

    tenant, other = "adv-" + uuid.uuid4().hex, "adv-" + uuid.uuid4().hex
    pools = [_new_application_pool(min_size=1, max_size=2) for _ in range(2)]
    try:
        a, b = (PostgresOperatorAdvisoryStore(pool=pool) for pool in pools)
        with tenant_scope(tenant):
            a.put(tenant, ADVISORY)
            a.put_rematch_state(tenant, {"cursor": "2026-10-22T00:00:00+00:00"})
            assert [row["id"] for row in b.list(tenant)] == ["CVE-2026-109618"]
            assert b.get_rematch_state(tenant)["cursor"] == "2026-10-22T00:00:00+00:00"
            with pytest.raises(InsufficientPrivilege):
                b.put(other, ADVISORY)
        with tenant_scope(other):
            assert b.list(tenant) == []
            assert b.get(tenant, "CVE-2026-109618") is None
            assert b.get_rematch_state(tenant) is None
            assert b.delete(tenant, "CVE-2026-109618") is False
            assert b.list(other) == []
        with tenant_scope(tenant):
            assert a.get(tenant, "CVE-2026-109618")["severity"] == "critical"
            assert a.delete(tenant, "CVE-2026-109618") is True
            assert a.list(tenant) == []
    finally:
        for pool in pools:
            pool.close()


def test_tenant_b_cannot_match_tenant_a_advisories_on_postgres(monkeypatch: pytest.MonkeyPatch) -> None:
    _require_postgres()
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_operator_advisory import PostgresOperatorAdvisoryStore
    from agent_bom.api.routes import operator_advisories as route
    from tests.test_postgres_job_evidence_revision import tenant_scope

    tenant, other = "adv-" + uuid.uuid4().hex, "adv-" + uuid.uuid4().hex
    package = {"name": "php", "version": "8.3.30", "ecosystem": "generic"}
    jobs = {
        owner: [
            ScanJob(
                job_id=f"job-{owner}",
                tenant_id=owner,
                status=JobStatus.DONE,
                created_at="2026-10-22T00:00:00Z",
                completed_at="2026-10-22T00:01:00Z",
                request=ScanRequest(images=["php:8.3"]),
                result={"agents": [{"name": "img", "mcp_servers": [{"name": "php", "packages": [package]}]}]},
            )
        ]
        for owner in (tenant, other)
    }
    monkeypatch.setattr(route, "_completed_jobs_for_tenant", lambda tenant_id: jobs[tenant_id])
    pool = _new_application_pool(min_size=1, max_size=2)
    stores.set_operator_advisory_store(PostgresOperatorAdvisoryStore(pool=pool))
    try:
        with tenant_scope(tenant):
            stores._get_operator_advisory_store().put(tenant, ADVISORY)
            assert len(route.operator_advisory_matches(tenant)["findings"]) == 1
        with tenant_scope(other):
            assert route.operator_advisory_matches(other, "CVE-2026-109618") is None
            body = route.operator_advisory_matches(other)
            assert body["advisory_ids"] == [] and body["findings"] == []
    finally:
        stores.set_operator_advisory_store(None)
        pool.close()
