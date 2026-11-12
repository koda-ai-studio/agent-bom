"""PR perf budgets for report push: deterministic estate, fresh SQLite, in-process.

Main before this change made a same-key retry wait 137 s and stalled the event
loop for the whole commit. Measured here on a shared 10-core machine at load
~20: 1x estate ingested in 2-4 s; /health stayed under the p99 budget while a
10x estate was admitted and retried. The 10x/50x end-to-end runs with
concurrent readers are nightly (``perf-scale-evidence.yml``).
"""

from __future__ import annotations

import asyncio
import gc
import json
import math
import time

import httpx
import pytest

from agent_bom.api import server_storage
from scripts.generate_graph_benchmark_estate import generate_estate

pytestmark = pytest.mark.graph_performance

ESTATE_SEED = 2145
INGEST_BUDGET_SECONDS = 5.0
ADMISSION_BUDGET_SECONDS = 2.0
HEALTH_P99_BUDGET_SECONDS = 0.25
BASELINE_RATIO = 4.0


def _observed_p99(samples: list[float]) -> float:
    # A measured percentile is an order statistic, not an extrapolation past
    # the slowest observation. With fewer than 100 samples, p99 is the maximum.
    return sorted(samples)[math.ceil(0.99 * len(samples)) - 1]


@pytest.mark.parametrize(
    ("samples", "expected"),
    [([0.004] * 29 + [0.216], 0.216), ([0.004] * 99 + [0.3], 0.004), ([0.216] * 2 + [0.004] * 99, 0.216)],
)
def test_health_p99_is_an_observed_nearest_rank(samples: list[float], expected: float) -> None:
    assert _observed_p99(samples) == expected


@pytest.fixture
def sqlite_control_plane(tmp_path, monkeypatch: pytest.MonkeyPatch):
    from agent_bom.api import stores
    from agent_bom.api.fleet_store import SQLiteFleetStore
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.idempotency_store import SQLiteIdempotencyStore
    from agent_bom.api.scan_queue import reset_local_dispatches_for_tests
    from agent_bom.api.server import set_fleet_store, set_graph_store, set_job_store
    from agent_bom.api.store import SQLiteJobStore

    db = str(tmp_path / "control-plane.db")
    originals = (stores._get_store(), stores._get_fleet_store(), stores._get_graph_store(), stores._get_idempotency_store())
    set_job_store(SQLiteJobStore(db))
    set_fleet_store(SQLiteFleetStore(db))
    set_graph_store(SQLiteGraphStore(tmp_path / "graph.db"))
    stores.set_idempotency_store(SQLiteIdempotencyStore(db))
    reset_local_dispatches_for_tests()
    monkeypatch.delenv("AGENT_BOM_PUSH_INGEST_MODE", raising=False)
    # Measure the heap API start-up leaves: start-up objects frozen out of full collections.
    monkeypatch.setattr(server_storage, "_startup_heap_frozen", False)
    server_storage._freeze_startup_heap()
    yield stores
    gc.unfreeze()
    from agent_bom.api import finding_reachability_prewarm, graph_rollup_prewarm, pipeline

    # Large estates queue minutes of warm-up on a loaded runner; drain before restoring stores.
    pipeline.shutdown_scan_executor(wait=True, cancel_futures=False)
    assert graph_rollup_prewarm.wait_idle(300)
    assert finding_reachability_prewarm.wait_idle(300)
    set_job_store(originals[0])
    set_fleet_store(originals[1])
    set_graph_store(originals[2])
    stores.set_idempotency_store(originals[3])
    reset_local_dispatches_for_tests()


def _estate_body(agents: int, key: str) -> bytes:
    report, _summary = generate_estate(agents=agents, seed=ESTATE_SEED, vulnerable_package_rate=0.08)
    report = {key_: value for key_, value in report.items() if key_ in {"agents", "blast_radius", "summary", "scan_id"}}
    report.update({"source_id": "perf-budget", "idempotency_key": key})
    return json.dumps(report).encode()


async def _wait_stored(client: httpx.AsyncClient, status_url: str, deadline: float) -> dict:
    while time.monotonic() < deadline:
        receipt = (await client.get(status_url)).json()
        if receipt.get("status") in {"stored", "failed"}:
            return receipt
        await asyncio.sleep(0.05)
    raise AssertionError("push was not ingested within the budget")


@pytest.mark.asyncio
async def test_estate_push_ingests_within_budget_and_a_timed_out_retry_adds_no_job(sqlite_control_plane) -> None:
    from agent_bom.api.server import app

    body = _estate_body(50, "perf-1x")
    headers = {"Content-Type": "application/json", "Prefer": "respond-async"}
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://perf") as client:
        # Measure a running API, as the 10x responsiveness budget does below.
        # FastAPI lazily builds routing/model schemas on the first matching
        # request. An invalid empty push warms that framework work without
        # admitting a job, normalizing a report or warming graph persistence.
        assert (await client.post("/v1/results/push", json={})).status_code == 422
        began = time.monotonic()
        first = await client.post("/v1/results/push", content=body, headers=headers)
        admitted = time.monotonic() - began
        # The client "timed out" and retries the identical report immediately.
        retry = await client.post("/v1/results/push", content=body, headers=headers)
        assert first.status_code == 202, first.text
        assert retry.status_code in {201, 202}
        assert retry.json()["job_id"] == first.json()["job_id"]
        receipt = await _wait_stored(client, first.json()["status_url"], began + INGEST_BUDGET_SECONDS * 4)
        elapsed = time.monotonic() - began

    assert admitted <= ADMISSION_BUDGET_SECONDS, f"admission took {admitted:.2f}s (budget {ADMISSION_BUDGET_SECONDS}s)"
    assert receipt["status"] == "stored"
    assert receipt["graph_persistence"]["status"] == "persisted"
    assert receipt["graph_persistence"]["nodes"] > 0
    assert elapsed <= INGEST_BUDGET_SECONDS, f"1x estate push took {elapsed:.2f}s (budget {INGEST_BUDGET_SECONDS}s)"
    assert len(sqlite_control_plane._get_store().list_all(all_tenants=True)) == 1


@pytest.mark.asyncio
async def test_event_loop_stays_live_while_a_10x_push_is_admitted_and_retried(
    sqlite_control_plane, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The request path (parse, fingerprint, claim, durable admission, in-flight retry) never stalls other requests.

    The graph build is deferred so the budget measures what this API process does
    per push; with ``AGENT_BOM_API_ROLE=worker`` the build runs in another process.
    """
    from agent_bom.api.server import app

    monkeypatch.setattr("agent_bom.api.scan_job_dispatch.submit_scan_job", lambda _job: None)
    warmup = _estate_body(50, "perf-warmup")
    body = _estate_body(500, "perf-10x")
    headers = {"Content-Type": "application/json", "Prefer": "respond-async"}
    latencies: list[float] = []
    stop = asyncio.Event()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://perf", timeout=600) as client:
        # Warm imports first: the budget is for a running API, not a cold process.
        assert (await client.post("/v1/results/push", content=warmup, headers=headers)).status_code == 202

        async def _probe() -> None:
            while not stop.is_set():
                began = time.monotonic()
                assert (await client.get("/health")).status_code == 200
                latencies.append(time.monotonic() - began)
                await asyncio.sleep(0.01)

        # Idle baseline on the same isolated runner (including host CPU steal).
        for _ in range(30):
            began = time.monotonic()
            await client.get("/health")
            latencies.append(time.monotonic() - began)
            await asyncio.sleep(0.01)
        baseline_p99 = _observed_p99(latencies)
        latencies.clear()
        prober = asyncio.create_task(_probe())
        await asyncio.sleep(0.2)
        first = await client.post("/v1/results/push", content=body, headers=headers)
        retry = await client.post("/v1/results/push", content=body, headers=headers)
        while len(latencies) < 30:
            await asyncio.sleep(0.01)
        stop.set()
        await asyncio.gather(prober)

    assert (first.status_code, retry.status_code) == (202, 202)
    assert first.json()["job_id"] == retry.json()["job_id"]
    assert len(latencies) >= 20
    p99 = _observed_p99(latencies)
    # 250 ms on a quiet runner; on a saturated one, no worse than 4x the idle p99.
    budget = max(HEALTH_P99_BUDGET_SECONDS, BASELINE_RATIO * baseline_p99)
    assert p99 < budget, (
        f"/health p99 {p99 * 1000:.0f} ms during a 10x admission "
        f"(idle p99 {baseline_p99 * 1000:.0f} ms, budget {budget * 1000:.0f} ms, "
        f"samples {len(latencies)}, max {max(latencies) * 1000:.0f} ms, "
        f"slowest_ms {[round(value * 1000, 1) for value in sorted(latencies)[-5:]]})"
    )
