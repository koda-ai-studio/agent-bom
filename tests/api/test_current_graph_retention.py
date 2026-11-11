"""A current graph built from evidence older than graph retention stays readable and dated by its evidence."""

from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.current_graph import CurrentGraphStore
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
from tests.api.test_findings_owner_sla import _completed_job
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

TENANT = "retention-tenant"


def _old_scan(jobs, graph_store, *, days_old: int, graph_dated_by_evidence: bool) -> str:
    generated_at = datetime.now(timezone.utc) - timedelta(days=days_old)
    scan = _completed_job(TENANT, [], generated_at=generated_at)
    scan.job_id = f"{TENANT}-old-scan"
    scan.target = {"path": "repo-a"}
    scan.result.update(scan_id=scan.job_id, scan_run={"outcome": "complete"})
    created_at = scan.completed_at if graph_dated_by_evidence else ""
    graph = UnifiedGraph(scan_id=scan.job_id, tenant_id=TENANT, created_at=created_at)
    graph.add_node(UnifiedNode(id="aged-package", entity_type=EntityType.PACKAGE, label="aged-package"))
    graph_store.save_graph(graph)
    jobs.put(scan)
    return str(scan.completed_at)


@pytest.fixture
def estate(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENT_BOM_GRAPH_RETENTION_DAYS", raising=False)
    monkeypatch.delenv("AGENT_BOM_GRAPH_RETENTION_OVERRIDES", raising=False)
    jobs = InMemoryJobStore()
    graph_store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    monkeypatch.setattr(stores, "_store", jobs)
    monkeypatch.setattr(stores, "_graph_store", graph_store)
    return jobs, graph_store


def test_current_graph_from_evidence_older_than_retention_is_served_not_rebuilt_forever(estate, monkeypatch):
    jobs, graph_store = estate
    evidence_at = _old_scan(jobs, graph_store, days_old=181, graph_dated_by_evidence=False)
    builds: list[str] = []
    materialize = CurrentGraphStore._materialize

    def counted(self, tenant, identity, *args, **kwargs):
        builds.append(identity)
        return materialize(self, tenant, identity, *args, **kwargs)

    monkeypatch.setattr(CurrentGraphStore, "_materialize", counted)
    enable_trusted_proxy_env()
    try:
        with TestClient(app, headers=proxy_headers(tenant=TENANT)) as client:
            responses = [client.get("/v1/graph", params={"limit": 100}) for _ in range(3)]
    finally:
        disable_trusted_proxy_env()
    for response in responses:
        assert response.status_code == 200, response.text
        body = response.json()
        assert {node["id"] for node in body["nodes"]} == {"aged-package"}
        # The view keeps the age of its evidence; it is not re-dated to the build time.
        assert body["created_at"] == evidence_at
    assert len(builds) == 1, f"the current graph was rebuilt {len(builds)} times"


def test_expired_source_graph_gives_honest_partial_view_not_endless_503(estate):
    jobs, graph_store = estate
    _old_scan(jobs, graph_store, days_old=181, graph_dated_by_evidence=True)
    enable_trusted_proxy_env()
    try:
        with TestClient(app, headers=proxy_headers(tenant=TENANT)) as client:
            responses = [client.get("/v1/graph") for _ in range(2)]
    finally:
        disable_trusted_proxy_env()
    for response in responses:
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["nodes"] == []
        assert body["collection_coverage"]["status"] == "partial"
        assert "graph_evidence_unavailable" in body["collection_coverage"]["reason_codes"]


def test_projection_cache_store_never_applies_age_retention(tmp_path, monkeypatch):
    monkeypatch.delenv("AGENT_BOM_GRAPH_RETENTION_DAYS", raising=False)
    backing = SQLiteGraphStore(str(tmp_path / "graph.db"))
    store = CurrentGraphStore(backing, InMemoryJobStore())
    old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    store._projection_store.save_graph_streaming(
        tenant_id=TENANT,
        scan_id="current-estate:aged",
        nodes=[],
        edges=[],
        created_at=old,
        snapshot_kind="correlation",
        correlation_id="current-estate:aged",
    )
    assert store._projection_store.snapshot_identity(tenant_id=TENANT, scan_id="current-estate:aged")[1]
    # The ordinary scan store keeps enforcing retention on its own history.
    backing.save_graph(UnifiedGraph(scan_id="aged-scan", tenant_id=TENANT, created_at=old))
    assert not backing.snapshot_identity(tenant_id=TENANT, scan_id="aged-scan")[1]
