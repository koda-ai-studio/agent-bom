"""PR regression budget for the whole workflow: collect, scan, ingest, store, query, export, retain, rebuild.

Runs the ``ci-budget`` profile in process against fresh SQLite stores and a
mocked upstream. Ceilings are several times the local measurement (see
docs/PERFORMANCE_BENCHMARKS.md, "End-to-end workflow budgets") so a loaded
GitHub runner does not flake; they catch order-of-magnitude regressions such as
an unbounded upstream fan-out, a stage that stops streaming, or storage that
grows with every identical push. Accuracy checks are exact.
"""

from __future__ import annotations

import pytest

from scripts.perf.workflow_budget import run_workflow, sqlite_footprint
from scripts.perf.workflow_profiles import PROFILES

pytestmark = pytest.mark.graph_performance

PROFILE = PROFILES["ci-budget"]
# CPU-seconds per stage. Local (M-series, 10 cores, load ~3): collection 0.01,
# scan 2-4, ingest 1-2, graph reads ~0.6, exports ~0.4, rebuild 1-2.
STAGE_CPU_SECONDS = {
    "collection": 2.0,
    "scan_enrichment": 25.0,
    "ingest": 20.0,
    "graph_api": 15.0,
    "report_export": 15.0,
    "retention": 10.0,
    "rebuild": 20.0,
}
WORKFLOW_CPU_SECONDS = 90.0
PEAK_RSS_MIB = 1536  # the profile's 2 GiB limit minus headroom for the test runner
READ_P95_MS = 2000.0
# One OSV batch (plus the injected 503 retry), one detail call per advisory, and
# at most one registry/feed lookup per package: fan-out must stay linear.
UPSTREAM_REQUESTS_PER_PACKAGE = 3.0
INGEST_GROWTH_BYTES = 64 * 1024 * 1024
# Bytes are deterministic for the pinned fixture (largest: graph page ~1.9 MB at
# limit=100), so this ceiling is ~2x, not a timing allowance.
RESPONSE_BYTES_PER_READ = 4 * 1024 * 1024


@pytest.fixture
def workflow_control_plane(tmp_path, monkeypatch: pytest.MonkeyPatch):
    from agent_bom.api import stores
    from agent_bom.api.fleet_store import SQLiteFleetStore
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.idempotency_store import SQLiteIdempotencyStore
    from agent_bom.api.scan_queue import reset_local_dispatches_for_tests
    from agent_bom.api.server import set_fleet_store, set_graph_store, set_job_store
    from agent_bom.api.store import SQLiteJobStore

    db_dir = tmp_path / "db"
    db_dir.mkdir()
    db = str(db_dir / "control-plane.db")
    monkeypatch.setenv("AGENT_BOM_SCAN_CACHE", str(tmp_path / "scan-cache.db"))
    monkeypatch.delenv("AGENT_BOM_PUSH_INGEST_MODE", raising=False)
    originals = (stores._get_store(), stores._get_fleet_store(), stores._get_graph_store(), stores._get_idempotency_store())
    set_job_store(SQLiteJobStore(db))
    set_fleet_store(SQLiteFleetStore(db))
    set_graph_store(SQLiteGraphStore(db_dir / "graph.db"))
    stores.set_idempotency_store(SQLiteIdempotencyStore(db))
    reset_local_dispatches_for_tests()
    yield db_dir
    from agent_bom.api import finding_reachability_prewarm, graph_rollup_prewarm, pipeline

    pipeline.shutdown_scan_executor(wait=True, cancel_futures=False)
    assert graph_rollup_prewarm.wait_idle(300)
    assert finding_reachability_prewarm.wait_idle(300)
    set_job_store(originals[0])
    set_fleet_store(originals[1])
    set_graph_store(originals[2])
    stores.set_idempotency_store(originals[3])
    reset_local_dispatches_for_tests()


@pytest.mark.asyncio
async def test_ci_profile_workflow_stays_accurate_and_inside_its_resource_budget(workflow_control_plane, tmp_path) -> None:
    result = await run_workflow(PROFILE, tmp_path / "work", footprint=sqlite_footprint(workflow_control_plane))
    stages = result["stages"]

    assert list(stages) == ["collection", "scan_enrichment", "ingest", "graph_api", "report_export", "retention", "rebuild"]
    accuracy = result["accuracy"]
    assert accuracy["expected_findings"] > 0
    assert accuracy["scanned_matches_expected"], accuracy
    assert accuracy["stored_matches_scanned"], accuracy
    assert accuracy["rebuilt_matches_stored"], accuracy
    assert result["network"]["blocked_connections"] == []

    upstream = stages["scan_enrichment"]["upstream"]
    assert upstream["injected_failures"] == 1, "the retry path must run"
    assert upstream["by_endpoint"]["osv:querybatch"] >= 2
    packages = stages["collection"]["packages"]
    assert upstream["requests"] <= UPSTREAM_REQUESTS_PER_PACKAGE * packages, upstream

    ingest = stages["ingest"]
    assert ingest["status"] == "stored" and ingest["retry_same_job"]
    assert ingest["graph_nodes"] and ingest["graph_nodes"] > 0
    assert 0 < result["storage"]["ingest_growth_bytes"] <= INGEST_GROWTH_BYTES, result["storage"]

    for name, read in stages["graph_api"]["reads"].items():
        assert read["status"] == 200, (name, read)
        assert read["samples"] == PROFILE.query_repeats
        assert read["p95_ms"] <= READ_P95_MS, (name, read)
        assert read["response_bytes"] <= RESPONSE_BYTES_PER_READ, (name, read)

    exports = stages["report_export"]
    assert exports["graph_export_json"]["status"] == 200 and exports["graph_export_json"]["bytes"] > 0
    assert exports["graph_export_graphml"]["status"] == 200
    assert exports["findings_report"]["status"] == "done", exports["findings_report"]
    assert exports["findings_report"]["retained_lookup_status"] == 200
    assert exports["findings_report"]["download_bytes"]

    assert stages["retention"]["jobs_removed"] >= 1 and stages["retention"]["jobs_after"] == 0, stages["retention"]
    assert stages["rebuild"]["status"] == "stored" and stages["rebuild"]["new_job"], stages["rebuild"]

    for name, ceiling in STAGE_CPU_SECONDS.items():
        assert stages[name]["cpu_seconds"] <= ceiling, (name, stages[name])
    assert result["process"]["cpu_seconds"] <= WORKFLOW_CPU_SECONDS, result["process"]
    assert result["process"]["rss_peak_mib"] <= PEAK_RSS_MIB, result["process"]
