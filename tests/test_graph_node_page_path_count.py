"""``/v1/graph`` stats count the same attack paths ``/v1/graph/attack-paths`` serves."""

from __future__ import annotations

import sqlite3

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.current_graph import _READS, CURRENT_PREFIX
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.routes.graph_routes import path_count
from agent_bom.api.server import app
from agent_bom.api.stores import set_graph_store
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode


def _topology(scan_id: str, created_at: str, servers: int) -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id="default", created_at=created_at)
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent-a"))
    for index in range(servers):
        server, package, vuln = f"server:{index}", f"pkg:npm:lib-{index}", f"vuln:CVE-2026-{index}"
        graph.add_node(UnifiedNode(id=server, entity_type=EntityType.SERVER, label=f"mcp-{index}"))
        graph.add_node(UnifiedNode(id=package, entity_type=EntityType.PACKAGE, label=f"lib-{index}"))
        graph.add_node(
            UnifiedNode(id=vuln, entity_type=EntityType.VULNERABILITY, label=f"CVE-2026-{index}", severity="critical", risk_score=9.8)
        )
        graph.add_edge(UnifiedEdge(source="agent:a", target=server, relationship=RelationshipType.USES))
        graph.add_edge(UnifiedEdge(source=server, target=package, relationship=RelationshipType.DEPENDS_ON))
        graph.add_edge(UnifiedEdge(source=package, target=vuln, relationship=RelationshipType.VULNERABLE_TO))
    return graph


@pytest.fixture
def sqlite_store(tmp_path, monkeypatch):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    monkeypatch.setattr(api_stores, "_store", InMemoryJobStore())
    original = api_stores._graph_store
    set_graph_store(store)
    try:
        yield store
    finally:
        set_graph_store(original)


def _record_scan(sqlite_store, scan_id: str, created_at: str, servers: int) -> None:
    from tests.api.test_scan_job_sla_history import job

    scan = job(10, tenant="default", target=scan_id, findings=[])
    scan.job_id = scan_id
    scan.result.update(scan_id=scan_id, scan_run={"outcome": "complete"})
    sqlite_store.save_graph(_topology(scan_id, created_at, servers=servers))
    api_stores._store.put(scan)


def _counts(client: TestClient) -> tuple[int, int, dict]:
    page = client.get("/v1/graph", params={"limit": 50})
    queue = client.get("/v1/graph/attack-paths", params={"limit": 5})
    assert page.status_code == 200 and queue.status_code == 200
    return page.json()["stats"]["attack_path_count"], queue.json()["pagination"]["total"], page.json()


def test_topology_only_snapshot_node_page_counts_derived_paths(sqlite_store):
    sqlite_store.save_graph(_topology("topo-1", "2026-10-01T00:00:00Z", servers=3))
    client = TestClient(app)

    page_count, queue_total, body = _counts(client)

    assert queue_total == 3
    assert page_count == queue_total
    assert body["stats"]["max_attack_path_risk"] > 0


def test_node_page_path_count_is_cached_per_generation(sqlite_store, monkeypatch):
    sqlite_store.save_graph(_topology("topo-1", "2026-10-01T00:00:00Z", servers=2))
    client = TestClient(app)
    calls: list[str] = []
    original = path_count._count_snapshot_paths

    async def counting(*args, **kwargs):
        calls.append(kwargs.get("scan_id", ""))
        return await original(*args, **kwargs)

    monkeypatch.setattr(path_count, "_count_snapshot_paths", counting)

    first = client.get("/v1/graph", params={"limit": 50}).json()["stats"]["attack_path_count"]
    second = client.get("/v1/graph", params={"limit": 1}).json()["stats"]["attack_path_count"]
    assert first == second == 2
    assert len(calls) == 1

    sqlite_store.save_graph(_topology("topo-2", "2026-10-02T00:00:00Z", servers=4))
    page_count, queue_total, _ = _counts(client)
    assert queue_total == 4
    assert page_count == queue_total
    assert len(calls) == 2


def test_node_page_path_count_is_tenant_scoped(sqlite_store):
    sqlite_store.save_graph(_topology("topo-1", "2026-10-01T00:00:00Z", servers=2))
    other = _topology("topo-other", "2026-10-01T00:00:00Z", servers=5)
    other.tenant_id = "tenant-b"
    sqlite_store.save_graph(other)
    page_count, queue_total, _ = _counts(TestClient(app))
    assert page_count == queue_total == 2


def test_node_page_never_loads_the_graph_to_count(sqlite_store, monkeypatch):
    sqlite_store.save_graph(_topology("topo-1", "2026-10-01T00:00:00Z", servers=3))

    def refuse(**_kwargs):
        raise AssertionError("the node page must stay store-backed")

    monkeypatch.setattr(sqlite_store, "load_graph", refuse)
    body = TestClient(app).get("/v1/graph", params={"limit": 50}).json()
    assert body["stats"]["attack_path_count"] == 3
    assert body["stats"]["attack_path_count_basis"] == "queue_total"


def test_derive_on_read_snapshot_reports_the_queue_total_once_derived(sqlite_store):
    sqlite_store.save_graph(_topology("topo-1", "2026-10-01T00:00:00Z", servers=3))
    with sqlite3.connect(sqlite_store._db_path) as conn:
        conn.execute("UPDATE graph_snapshots SET analysis_status = '{}'")
    client = TestClient(app)

    before = client.get("/v1/graph", params={"limit": 50}).json()["stats"]
    assert before["attack_path_count_basis"] == "persisted_paths"

    queue_total = client.get("/v1/graph/attack-paths", params={"limit": 5}).json()["pagination"]["total"]
    after = client.get("/v1/graph", params={"limit": 50}).json()["stats"]
    assert queue_total == 3
    assert after["attack_path_count"] == queue_total
    assert after["attack_path_count_basis"] == "queue_total"


def test_current_estate_node_page_counts_the_projection_paths(sqlite_store):
    _record_scan(sqlite_store, "estate-1", "2026-10-01T00:00:00Z", servers=3)
    client = TestClient(app)

    page = client.get("/v1/graph", params={"limit": 50}).json()
    assert page["scan_id"].startswith(CURRENT_PREFIX)
    queue_total = client.get("/v1/graph/attack-paths", params={"limit": 5}).json()["pagination"]["total"]

    assert queue_total == 3
    assert page["stats"]["attack_path_count"] == queue_total
    assert page["stats"]["attack_path_count_basis"] == "queue_total"


_SNAPSHOT_WRITES = frozenset({"save_graph_streaming", "delete_snapshot", "prior_delta_digest"})


@pytest.mark.parametrize("backend", ["sqlite", "postgres"])
def test_every_scan_scoped_store_read_resolves_the_current_estate(backend):
    import inspect

    from agent_bom.api.postgres_store import PostgresGraphStore

    store_class = SQLiteGraphStore if backend == "sqlite" else PostgresGraphStore
    scoped = {
        name
        for name, method in inspect.getmembers(store_class, callable)
        if not name.startswith("_") and "scan_id" in inspect.signature(method).parameters
    }
    assert scoped - _SNAPSHOT_WRITES <= _READS, sorted(scoped - _SNAPSHOT_WRITES - _READS)
