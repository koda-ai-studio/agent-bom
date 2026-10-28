"""Gateway drift enforcement must scale past the tenant's open-incident count.

Lookups are scoped to (tenant, blueprint) in the store, so a busy tenant with
many open incidents on other blueprints neither hides a violation nor turns
every call into ``unavailable``.
"""

from __future__ import annotations

import pytest

from agent_bom.api import gateway_policy
from agent_bom.api.drift_incident_store import (
    DriftIncident,
    InMemoryDriftIncidentStore,
    SQLiteDriftIncidentStore,
    set_drift_incident_store,
)

TENANT = "tenant-busy"


def _incident(tenant: str, incident_id: str, blueprint: str, tools: list[str], at: str, *, resolved: bool = False) -> DriftIncident:
    return DriftIncident(
        incident_id=incident_id,
        tenant_id=tenant,
        blueprint_id=blueprint,
        status="drift_detected",
        drift_score=1.0,
        violation_count=len(tools),
        warning_count=0,
        top_violations=[{"tool_name": t} for t in tools],
        first_detected_at=at,
        last_detected_at=at,
        resolved=resolved,
    )


def _seed_busy_tenant(store) -> None:
    # The violating incident is the OLDEST row, so a tenant-wide newest-first
    # page of any size below 1,000 never reaches it.
    store.upsert(_incident(TENANT, "target", "Target-Role", ["shell_exec"], "2026-01-01T00:00:00Z"))
    for n in range(999):
        store.upsert(_incident(TENANT, f"noise-{n}", f"blueprint_{n % 250}", ["shell_exec"], f"2026-06-01T00:{n // 60:02d}:{n % 60:02d}Z"))
    store.upsert(_incident(TENANT, "resolved", "resolved_role", ["shell_exec"], "2026-07-01T00:00:00Z", resolved=True))
    store.upsert(_incident("tenant-other", "elsewhere", "clean_role", ["shell_exec"], "2026-07-01T00:00:00Z"))


@pytest.fixture(params=["memory", "sqlite"])
def busy_store(request, tmp_path):
    store = InMemoryDriftIncidentStore() if request.param == "memory" else SQLiteDriftIncidentStore(str(tmp_path / "drift.db"))
    _seed_busy_tenant(store)
    set_drift_incident_store(store)
    yield store
    set_drift_incident_store(None)


def test_violation_on_oldest_incident_is_found_past_tenant_cap(busy_store):
    lookup = gateway_policy._open_drift_violates_tool(TENANT, "target_role", "shell_exec")
    assert lookup.violates is True
    assert lookup.unavailable is False


def test_tool_outside_incident_is_allowed_without_unavailable(busy_store):
    lookup = gateway_policy._open_drift_violates_tool(TENANT, "target_role", "read_file")
    assert (lookup.violates, lookup.unavailable) == (False, False)


def test_blueprint_without_open_incident_is_allowed(busy_store):
    for blueprint in ("clean_role", "resolved_role"):
        lookup = gateway_policy._open_drift_violates_tool(TENANT, blueprint, "shell_exec")
        assert (lookup.violates, lookup.unavailable) == (False, False), blueprint


def test_other_tenants_incident_never_applies(busy_store):
    lookup = gateway_policy._open_drift_violates_tool("tenant-quiet", "clean_role", "shell_exec")
    assert (lookup.violates, lookup.unavailable) == (False, False)


def test_store_filters_open_incidents_by_normalized_blueprint(busy_store):
    rows = busy_store.list_open_for_blueprint(TENANT, "TARGET-role", limit=10)
    assert [r.incident_id for r in rows] == ["target"]
    assert busy_store.list_open_for_blueprint(TENANT, "resolved_role", limit=10) == []
    assert busy_store.list_open_for_blueprint("tenant-quiet", "clean_role", limit=10) == []
    assert len(busy_store.list_open_for_blueprint(TENANT, "blueprint_7", limit=10)) == 4


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_truncated_per_blueprint_result_is_unavailable_unless_a_match_is_seen(backend, tmp_path, monkeypatch):
    store = InMemoryDriftIncidentStore() if backend == "memory" else SQLiteDriftIncidentStore(str(tmp_path / "drift.db"))
    monkeypatch.setattr(gateway_policy, "_DRIFT_INCIDENT_LOOKUP_CAP", 3)
    for n in range(5):
        store.upsert(_incident(TENANT, f"crowded-{n}", "crowded", [f"tool_{n}"], f"2026-06-01T00:00:0{n}Z"))
    set_drift_incident_store(store)
    try:
        hidden = gateway_policy._open_drift_violates_tool(TENANT, "crowded", "tool_0")
        assert (hidden.violates, hidden.unavailable) == (False, True)
        seen = gateway_policy._open_drift_violates_tool(TENANT, "crowded", "tool_4")
        assert (seen.violates, seen.unavailable) == (True, False)
        exact = gateway_policy._open_drift_violates_tool(TENANT, "other", "tool_0")
        assert (exact.violates, exact.unavailable) == (False, False)
    finally:
        set_drift_incident_store(None)


def test_store_error_is_unavailable(monkeypatch):
    class Broken(InMemoryDriftIncidentStore):
        def list_open_for_blueprint(self, *args, **kwargs):
            raise RuntimeError("down")

    set_drift_incident_store(Broken())
    try:
        lookup = gateway_policy._open_drift_violates_tool(TENANT, "target_role", "shell_exec")
        assert (lookup.violates, lookup.unavailable) == (False, True)
    finally:
        set_drift_incident_store(None)


def test_sqlite_blueprint_lookup_uses_the_open_blueprint_index(tmp_path):
    store = SQLiteDriftIncidentStore(str(tmp_path / "drift.db"))
    sql, params = store._open_for_blueprint_query(TENANT, "target_role", 5)
    plan = " ".join(str(row[-1]) for row in store._conn.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall())
    assert "idx_drift_incidents_tenant_blueprint_open" in plan


def test_postgres_blueprint_index_is_identical_in_every_schema_path():
    from pathlib import Path

    from agent_bom.api.storage.registry_schema import DRIFT_BLUEPRINT_KEY_COLUMN_DDL, DRIFT_BLUEPRINT_OPEN_INDEX_DDL

    root = Path(__file__).resolve().parents[1] / "deploy" / "supabase" / "postgres"
    migration = (root / "alembic" / "versions" / "20261027_03_drift_blueprint_seek.py").read_text()
    assert 'down_revision = "20261027_02"' in migration
    for source in (migration, (root / "runtime-schema.sql").read_text()):
        normalized = " ".join(source.split())
        assert " ".join(DRIFT_BLUEPRINT_KEY_COLUMN_DDL.split()) + ";" in normalized
        assert " ".join(DRIFT_BLUEPRINT_OPEN_INDEX_DDL.split()) + ";" in normalized
