"""On PostgreSQL, a rebuild after a push serves the promoted projection at once, labelled.

Live tier: needs ``AGENT_BOM_POSTGRES_ADMIN_URL`` and ``AGENT_BOM_POSTGRES_URL``.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from starlette.exceptions import HTTPException

from agent_bom.api import current_graph_builds
from agent_bom.api.current_graph import CurrentGraphStore
from agent_bom.api.finding_read_context import finding_read_scope
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.store import SQLiteJobStore
from agent_bom.core.estate_read_boundary import estate_read_boundary
from agent_bom.graph.builder import build_unified_graph_from_report
from scripts.generate_graph_benchmark_estate import generate_estate
from tests.test_postgres_migrated_graph_parity import migrated_fresh_database  # noqa: F401
from tests.test_postgres_migrated_graph_parity import pytestmark as pytestmark

TENANT = "pg-previous-tenant"
OTHER = "pg-previous-other"


@pytest.fixture(autouse=True)
def _private_queue(monkeypatch):
    queue = current_graph_builds.CurrentBuildQueue()
    monkeypatch.setattr(current_graph_builds, "_QUEUE", queue)
    yield
    queue.executor.shutdown(wait=True)


def _push(jobs: SQLiteJobStore, tenant: str, seed: int, completed_at: str) -> set[str]:
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.postgres_graph import PostgresGraphStore

    report, _summary = generate_estate(agents=12, seed=seed, vulnerable_package_rate=0.08)
    report.update(scan_id=f"{tenant}-scan-{seed}", scan_run={"outcome": "complete"}, generated_at=completed_at)
    graph = build_unified_graph_from_report(report, tenant_id=tenant, scan_id=report["scan_id"])
    token = set_current_tenant(tenant)
    try:
        PostgresGraphStore().save_graph(graph)
    finally:
        reset_current_tenant(token)
    jobs.put(
        ScanJob(
            job_id=report["scan_id"],
            tenant_id=tenant,
            status=JobStatus.DONE,
            created_at=completed_at,
            completed_at=completed_at,
            request=ScanRequest(),
            target={"path": "previous-repository"},
            result=report,
        )
    )
    return set(graph.nodes)


def _store(jobs: SQLiteJobStore) -> CurrentGraphStore:
    from agent_bom.api.postgres_graph import PostgresGraphStore

    return CurrentGraphStore(PostgresGraphStore(), jobs)


def _read(store: CurrentGraphStore, tenant: str):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    token = set_current_tenant(tenant)
    try:
        with estate_read_boundary(), finding_read_scope():
            identity = store.latest_snapshot_id(tenant_id=tenant)
            return identity, store.snapshot_stats(tenant_id=tenant), set(store.load_graph(tenant_id=tenant).nodes)
    except HTTPException as exc:
        return exc
    finally:
        reset_current_tenant(token)


def _held_read(store: CurrentGraphStore, tenant: str):
    entered, release = threading.Event(), threading.Event()
    materialize = store._materialize

    def held(*args, **kwargs):
        entered.set()
        assert release.wait(30)
        return materialize(*args, **kwargs)

    store._materialize = held  # type: ignore[method-assign]
    with ThreadPoolExecutor(max_workers=1) as workers:
        began = time.monotonic()
        reader = workers.submit(_read, store, tenant)
        try:
            result = reader.result(timeout=10)
            elapsed = time.monotonic() - began
            assert entered.wait(10), "the read never started the rebuild"
        finally:
            release.set()
    return elapsed, result


def test_postgres_rebuild_serves_the_promoted_generation_immediately(tmp_path: Path, monkeypatch, migrated_fresh_database) -> None:  # noqa: F811
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "5000")
    jobs = SQLiteJobStore(str(tmp_path / "jobs.db"))
    old_nodes = _push(jobs, TENANT, 2145, "2026-11-13T10:00:00+00:00")
    first = _store(jobs)
    token = set_current_tenant(TENANT)
    try:
        assert first.prepare_current(TENANT, seconds=120)
    finally:
        reset_current_tenant(token)
    old = first._cache[TENANT][2]
    new_nodes = _push(jobs, TENANT, 2146, "2026-11-14T10:00:00+00:00")
    assert new_nodes != old_nodes

    # A restarted worker: no in-process record, only the shared projection and its promotion stamp.
    restarted = _store(jobs)
    elapsed, result = _held_read(restarted, TENANT)

    assert not isinstance(result, HTTPException), result
    identity, stats, nodes = result
    assert elapsed < 2.0, f"the read waited {elapsed:.2f}s on the rebuild"
    assert identity == old
    assert nodes == old_nodes, "one response mixed generations"
    coverage = stats["collection_coverage"]
    assert coverage["freshness"] == "previous_generation"
    assert coverage["refresh_status"] == "building"
    assert coverage["as_of"].startswith("2026-11-13")

    token = set_current_tenant(TENANT)
    try:
        final = current_graph_builds.await_current_build(restarted, TENANT, seconds=120)
    finally:
        reset_current_tenant(token)
    assert final and final != old
    identity, stats, nodes = _read(restarted, TENANT)
    assert identity == final
    assert nodes == new_nodes
    assert "freshness" not in stats["collection_coverage"]

    # Another tenant with no promoted generation is a cold start: never served this tenant's graph.
    _push(jobs, OTHER, 2147, "2026-11-14T11:00:00+00:00")
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS", "20")
    _elapsed, cold = _held_read(_store(jobs), OTHER)
    assert isinstance(cold, HTTPException)
    assert cold.detail["code"] == "current_estate_building"
