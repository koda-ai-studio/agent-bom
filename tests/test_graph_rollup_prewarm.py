"""A committed snapshot pre-warms the roll-up views the graph page opens first.

Cold first hits at 115k nodes took 2.8 s (rollup) and 4.6 s (attack-path
mode) against ~50 ms warm. After a snapshot commits, a bounded background
worker computes those first views into the generation-keyed roll-up cache, so
the first reader is served warm. The worker never blocks or fails the write.
"""

from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient

from agent_bom.api import graph_rollup_cache, graph_rollup_prewarm, stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType

pytestmark = pytest.mark.graph_contract("warn")


def _graph(scan_id: str = "warm-scan") -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id="default", created_at="2026-10-18T00:00:00+00:00")
    graph.add_node(UnifiedNode(id="org:o", entity_type=EntityType.ORG, label="o"))
    for index in range(3):
        account = f"account:{index}"
        graph.add_node(UnifiedNode(id=account, entity_type=EntityType.ACCOUNT, label=account))
        graph.add_edge(UnifiedEdge(source="org:o", target=account, relationship=RelationshipType.CONTAINS))
    return graph


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    monkeypatch.delenv("AGENT_BOM_API_KEY", raising=False)
    monkeypatch.setattr(graph_rollup_cache, "_CACHE", type(graph_rollup_cache._CACHE)())
    graph_store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    graph_store.save_graph(_graph())
    # Current-estate reads join graph snapshots with completed scan jobs.
    # Keep both stores local so unrelated jobs cannot replace this graph.
    monkeypatch.setattr(stores, "_store", InMemoryJobStore())
    monkeypatch.setattr(stores, "_graph_store", graph_store)
    yield graph_store


def _count_loads(monkeypatch, graph_store: SQLiteGraphStore) -> list[str]:
    loads: list[str] = []
    for name in ("load_rollup_graph", "load_graph"):
        original = getattr(graph_store, name)

        def counting(_original=original, _name=name, **kwargs):
            loads.append(_name)
            return _original(**kwargs)

        monkeypatch.setattr(graph_store, name, counting)
    return loads


@pytest.mark.parametrize(
    "params",
    [
        {"limit": 100},
        {"limit": 100, "scan_id": "warm-scan"},
        {"mode": "attack_path"},
        {},
    ],
)
def test_prewarmed_first_views_are_served_without_loading_the_graph(store, monkeypatch, params) -> None:
    warmed = graph_rollup_prewarm.prewarm_rollup(store, tenant_id="default")
    assert warmed >= 3
    loads = _count_loads(monkeypatch, store)

    client = TestClient(app)
    served = client.get("/v1/graph/rollup", params=params)
    assert served.status_code == 200, served.text
    assert loads == []

    # Identical to a cold computation of the same view.
    monkeypatch.setattr(graph_rollup_cache, "_CACHE", type(graph_rollup_cache._CACHE)())
    cold = client.get("/v1/graph/rollup", params=params)
    assert loads, "the cold read must load the graph"
    assert served.json() == cold.json()


def test_single_root_estate_prewarms_the_auto_descend_drill(store, monkeypatch) -> None:
    graph_rollup_prewarm.prewarm_rollup(store, tenant_id="default")
    loads = _count_loads(monkeypatch, store)
    generation = store.snapshot_identity(tenant_id="default", scan_id="", for_paging=True)[1]

    body = TestClient(app).get("/v1/graph/rollup", params={"node": "org:o", "limit": 100}).json()

    assert [row["id"] for row in body["children"]] == ["account:0", "account:1", "account:2"]
    assert body["snapshot_generation"] == generation
    assert loads == []


def test_prewarm_entries_outlive_the_request_cache_window(store, monkeypatch) -> None:
    graph_rollup_prewarm.prewarm_rollup(store, tenant_id="default")
    start = time.monotonic()
    monkeypatch.setattr(graph_rollup_cache.time, "monotonic", lambda: start + graph_rollup_cache._TTL_SECONDS + 60)
    loads = _count_loads(monkeypatch, store)

    assert TestClient(app).get("/v1/graph/rollup", params={"limit": 100}).status_code == 200
    assert loads == []


def test_scheduling_returns_at_once_and_coalesces_while_a_warm_up_runs(monkeypatch) -> None:
    started, release, finished = threading.Event(), threading.Event(), threading.Event()
    runs: list[str] = []

    def slow_prewarm(_store, *, tenant_id: str) -> int:
        runs.append(tenant_id)
        started.set()
        release.wait(5)
        finished.set()
        return 0

    monkeypatch.setattr(graph_rollup_prewarm, "prewarm_rollup", slow_prewarm)
    monkeypatch.delenv("AGENT_BOM_GRAPH_ROLLUP_PREWARM", raising=False)

    graph_rollup_prewarm.schedule_rollup_prewarm(lambda: object(), tenant_id="tenant-a")
    assert started.wait(5)
    for _ in range(5):
        graph_rollup_prewarm.schedule_rollup_prewarm(lambda: object(), tenant_id="tenant-a")
    # Scheduling returned while the warm-up is still held open: it never waited on it.
    assert not finished.is_set()
    release.set()
    assert graph_rollup_prewarm.wait_idle(5)
    # The first run plus at most one coalesced re-run for the repeat commits.
    assert runs == ["tenant-a", "tenant-a"]


def test_a_failing_warm_up_never_reaches_the_writer(monkeypatch) -> None:
    def broken_factory():
        raise RuntimeError("store unavailable")

    monkeypatch.delenv("AGENT_BOM_GRAPH_ROLLUP_PREWARM", raising=False)
    graph_rollup_prewarm.schedule_rollup_prewarm(broken_factory, tenant_id="default")
    assert graph_rollup_prewarm.wait_idle(5)


def test_fatal_worker_exit_releases_busy_state_without_hiding_failure(monkeypatch):
    from collections import OrderedDict

    class WorkerPanic(BaseException):
        pass

    def panic():
        raise WorkerPanic("serializer panic")

    idle = threading.Event()
    monkeypatch.setattr(graph_rollup_prewarm, "_PENDING", OrderedDict([("tenant-a", panic)]))
    monkeypatch.setattr(graph_rollup_prewarm, "_IDLE", idle)
    monkeypatch.setattr(graph_rollup_prewarm, "_WORKER", threading.current_thread())
    try:
        with pytest.raises(WorkerPanic, match="serializer panic"):
            graph_rollup_prewarm._drain()
        assert idle.is_set()
        assert graph_rollup_prewarm._WORKER is None
    finally:
        idle.set()


def test_prewarm_can_be_disabled(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(graph_rollup_prewarm, "prewarm_rollup", lambda _store, *, tenant_id: calls.append(tenant_id) or 0)
    monkeypatch.setenv("AGENT_BOM_GRAPH_ROLLUP_PREWARM", "0")

    graph_rollup_prewarm.schedule_rollup_prewarm(lambda: object(), tenant_id="default")
    assert graph_rollup_prewarm.wait_idle(5)
    assert calls == []


def test_persisting_a_scan_snapshot_schedules_the_warm_up(tmp_path, monkeypatch) -> None:
    from agent_bom.api import pipeline
    from agent_bom.api.models import ScanJob, ScanRequest

    graph_store = SQLiteGraphStore(tmp_path / "pipeline.db")
    monkeypatch.setattr(pipeline, "_get_graph_store", lambda: graph_store)
    scheduled: list[str] = []
    monkeypatch.setattr(graph_rollup_prewarm, "schedule_rollup_prewarm", lambda _factory, *, tenant_id: scheduled.append(tenant_id))
    job = ScanJob(job_id="warm-job", tenant_id="default", created_at="2026-10-18T00:00:00Z", request=ScanRequest())

    pipeline._persist_graph_snapshot(job, {"scan_id": "warm-job", "agents": []})

    assert scheduled == ["default"]
