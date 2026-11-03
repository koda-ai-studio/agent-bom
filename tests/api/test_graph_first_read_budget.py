"""PR-sized synthetic API budgets: 12 agents and the same generator at 120.

Cold means a new current-estate projection and empty process response caches;
the operating-system page cache is not flushed. Times include ASGI, database,
serialization and client decode/transfer in-process, not browser paint/network.
"""

from __future__ import annotations

import json
import platform
import time
import tracemalloc
from concurrent.futures import ThreadPoolExecutor

import pytest

from agent_bom.api import stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.store import SQLiteJobStore
from agent_bom.graph.builder import build_unified_graph_from_report
from scripts.generate_graph_benchmark_estate import generate_estate
from scripts.run_graph_api_benchmark import _percentiles
from tests.auth_helpers import proxy_headers
from tests.graph_read_budget_probe import DatabaseWork
from tests.test_api_read_contracts import empty_estate_client  # noqa: F401


def _seed(tmp_path, monkeypatch, agents):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("AGENT_BOM_EXEC_PREWARM", "0")
    monkeypatch.setenv("AGENT_BOM_GRAPH_ROLLUP_PREWARM", "0")
    jobs = SQLiteJobStore(str(tmp_path / "jobs.db"))
    graphs = SQLiteGraphStore(tmp_path / "graphs.db")
    monkeypatch.setattr(stores, "_store", jobs)
    monkeypatch.setattr(stores, "_graph_store", graphs)
    report, summary = generate_estate(agents=agents, seed=2145, vulnerable_package_rate=0.08)
    report["scan_run"] = {"outcome": "complete"}
    graph = build_unified_graph_from_report(report, tenant_id="budget", scan_id=report["scan_id"])
    graphs.save_graph(graph)
    job = ScanJob(
        job_id=report["scan_id"],
        tenant_id="budget",
        status=JobStatus.DONE,
        created_at=report["generated_at"],
        completed_at=report["generated_at"],
        request=ScanRequest(),
        target={"path": "budget-repository"},
        result=report,
    )
    jobs.put(job)
    return graph, job, jobs, graphs, summary


@pytest.mark.parametrize("agents", [12, 120], ids=["1x", "10x-agents"])
def test_first_graph_and_findings_reads_stay_bounded(empty_estate_client, tmp_path, monkeypatch, agents, record_property):  # noqa: F811
    client = empty_estate_client
    graph, job, jobs, graphs, fixture = _seed(tmp_path, monkeypatch, agents)
    headers = proxy_headers(role="analyst", tenant="budget")
    work = DatabaseWork()
    work.instrument(monkeypatch)
    receipts = []

    def get(path):
        before = work.snapshot()
        started = time.perf_counter()
        response = client.get(path, headers=headers)
        elapsed = (time.perf_counter() - started) * 1000
        delta = {key: value - before.get(key, 0) for key, value in work.snapshot().items()}
        return response, elapsed, delta

    # The health request shares the application's event loop with the cold read.
    health_ms = []
    with ThreadPoolExecutor(max_workers=1) as pool:
        cold = pool.submit(get, "/v1/graph?limit=100&view=canvas")
        for _ in range(5):
            started = time.perf_counter()
            health = client.get("/health")
            health_ms.append((time.perf_counter() - started) * 1000)
            assert health.status_code == 200
            if cold.done():
                break
            time.sleep(0.01)
        response, elapsed, delta = cold.result(timeout=15)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["nodes"] and body["edges"]
    initial_generation = body["snapshot_generation"]
    receipts.append({"name": "graph-cold", "ms": elapsed, "bytes": len(response.content), "db": delta})

    for name, path in (
        ("graph", "/v1/graph?limit=100"),
        ("canvas", "/v1/graph?limit=100&view=canvas"),
        ("rollup", "/v1/graph/rollup?limit=100"),
        ("findings", "/v1/findings?limit=50&window_days=0"),
    ):
        samples = []
        for index in range(6):
            response, elapsed, delta = get(path)
            assert response.status_code == 200, response.text
            if name == "findings":
                assert response.json()["findings"]
            samples.append(elapsed)
            receipts.append(
                {"name": name, "condition": "first" if index == 0 else "warm", "ms": elapsed, "bytes": len(response.content), "db": delta}
            )
        record_property(f"{name}_warm", json.dumps(_percentiles(samples[1:])))

    # Measure allocations separately so tracing does not contaminate latency.
    tracemalloc.start()
    try:
        get("/v1/graph?limit=100")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    foreign = client.get("/v1/graph?limit=100", headers=proxy_headers(role="analyst", tenant="foreign"))
    assert foreign.status_code == 503 or not foreign.json().get("nodes")
    # A new complete scan for the same target must invalidate the cached view.
    graph.scan_id += "-next"
    graph.created_at = "2026-05-14T00:00:00Z"
    graphs.save_graph(graph)
    next_job = job.model_copy(deep=True)
    next_job.job_id = graph.scan_id
    next_job.created_at = next_job.completed_at = graph.created_at
    next_job.result["scan_id"] = graph.scan_id
    next_job.result["generated_at"] = graph.created_at
    jobs.put(next_job)
    refreshed, _, _ = get("/v1/graph?limit=100")
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["snapshot_generation"] != initial_generation
    receipt = {
        "agents": agents,
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "fixture": fixture["counts"],
        "python": platform.python_version(),
        "platform": platform.platform(),
        "reads": receipts,
        "concurrent_health_ms": health_ms,
        "warm_peak_python_bytes": peak,
    }
    record_property("budget_receipt", json.dumps(receipt))
    print(json.dumps(receipt))
    assert max(row["ms"] for row in receipts) < 2000, receipts
    assert max(row["bytes"] for row in receipts) < 2_000_000, receipts
    assert max(health_ms) < 1000, health_ms
    assert peak < 32_000_000, peak
    assert max(row["db"].get("statements", 0) for row in receipts) < 1000
    assert max(row["db"].get("fetched_rows", 0) for row in receipts) < 80_000
    warm = [row for row in receipts if row.get("condition") == "warm"]
    assert max(row["db"].get("statements", 0) for row in warm) < 200
    assert max(row["db"].get("fetched_rows", 0) for row in warm) < 2000
