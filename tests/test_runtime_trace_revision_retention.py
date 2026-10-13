"""Native span revision history is bounded per tenant like runtime observations."""

import os
from uuid import uuid4

import pytest

from agent_bom.api.runtime_event_store import InMemoryRuntimeEventStore, RuntimeObservationRecord, SQLiteRuntimeEventStore
from agent_bom.api.storage.runtime_trace_imports import TraceImportCheckpoint


def _postgres_store():
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_runtime_event import PostgresRuntimeEventStore

    return PostgresRuntimeEventStore(_new_application_pool(min_size=1, max_size=2))


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryRuntimeEventStore()
    if request.param == "sqlite":
        return SQLiteRuntimeEventStore(str(tmp_path / "runtime.db"))
    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires migrated private PostgreSQL")
    return _postgres_store()


@pytest.fixture
def tenants():
    suffix = uuid4().hex[:8]
    return f"tenant-a-{suffix}", f"tenant-b-{suffix}"


class _Pager:
    def __init__(self, store, tenant):
        self.store, self.tenant, self.revision = store, tenant, 0

    def commit(self, records):
        from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

        checkpoint = TraceImportCheckpoint(
            tenant_id=self.tenant,
            import_id="source",
            revision=self.revision + 1,
            window_start="2026-10-11T00:00:00Z",
            window_end="2026-10-12T00:00:00Z",
            cursor="next",
            updated_at="2026-10-12T00:00:01Z",
        )
        token = set_current_tenant(self.tenant)
        try:
            result = self.store.commit_trace_page(checkpoint, records, expected_revision=self.revision)
        finally:
            reset_current_tenant(token)
        self.revision += 1
        return result


def _span(tenant, identity, minute, tool="read"):
    return RuntimeObservationRecord(
        tenant_id=tenant,
        observation_id=identity,
        session_id="trace:one",
        observed_at=f"2026-10-11T12:{minute:02d}:00Z",
        surface="imported_trace",
        tool_name=tool,
    )


def _history(store, tenant, identity):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant(tenant)
    try:
        return store.list_observation_revisions(tenant, identity, limit=1000)
    finally:
        reset_current_tenant(token)


def test_pruned_projection_history_is_bounded_oldest_first_per_tenant(store, tenants, monkeypatch):
    tenant_a, tenant_b = tenants
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_EVENTS", "2")
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_TRACE_REVISIONS", "4")
    pager_a, pager_b = _Pager(store, tenant_a), _Pager(store, tenant_b)
    pager_b.commit([_span(tenant_b, f"b{i}", i) for i in range(3)])
    for i in range(6):
        pager_a.commit([_span(tenant_a, f"a{i}", i)])

    retained = {f"a{i}": len(_history(store, tenant_a, f"a{i}")) for i in range(6)}
    assert sum(retained.values()) <= 4
    # Live projection rows keep their history; the oldest pruned spans go first.
    assert retained["a4"] == retained["a5"] == 1
    assert retained["a0"] == retained["a1"] == 0
    # Another tenant under its cap is untouched.
    assert [len(_history(store, tenant_b, f"b{i}")) for i in range(3)] == [1, 1, 1]


def test_live_history_churn_keeps_latest_revision(store, tenants, monkeypatch):
    tenant, _ = tenants
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_TRACE_REVISIONS", "3")
    pager = _Pager(store, tenant)
    tools = ["t0", "t1", "t2", "t3", "t4"]
    for tool in tools:
        pager.commit([_span(tenant, "span", 1, tool=tool)])

    history = _history(store, tenant, "span")
    assert 1 <= len(history) <= 3
    assert history[-1].tool_name == "t4"
    # Replaying the latest content is still recognised as unchanged.
    assert pager.commit([_span(tenant, "span", 1, tool="t4")]).unchanged == 1


def test_zero_cap_disables_revision_pruning(store, tenants, monkeypatch):
    tenant, _ = tenants
    monkeypatch.setenv("AGENT_BOM_ANALYTICS_MAX_TRACE_REVISIONS", "0")
    pager = _Pager(store, tenant)
    for tool in ["t0", "t1", "t2", "t3"]:
        pager.commit([_span(tenant, "span", 1, tool=tool)])
    assert len(_history(store, tenant, "span")) == 4
