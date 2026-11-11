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
# Measured 2026-11-10/11 on an Apple M4 (10 cores) shared with other agents, load
# 6-18. CPU-seconds per stage: collection 0.1, scan 2.8-4.2, ingest 3.3-5.1,
# graph reads 4.9-5.4, exports 2.9, retention 0.03, rebuild 1.3-5.5; whole run
# 17-26. Ceilings are 3-5x so a 4-vCPU GitHub runner does not flake.
STAGE_CPU_SECONDS = {
    "collection": 2.0,
    "scan_enrichment": 25.0,
    "ingest": 20.0,
    "graph_api": 20.0,
    "report_export": 15.0,
    "retention": 5.0,
    "rebuild": 20.0,
}
WORKFLOW_CPU_SECONDS = 90.0
PEAK_RSS_MIB = 1536  # measured 410-540; the profile's 2 GiB limit less runner headroom
# Eight samples, so p95 is the slowest read: 2.0 s was observed at load ~18.
# This ceiling only catches order-of-magnitude stalls; latency is not a PR SLO.
READ_P95_MS = 8000.0
# Measured 93 upstream requests for 573 packages: one OSV batch plus the injected
# retry, one detail call per advisory, capped registry/advisory lookups. A new
# per-package call would add >= 573, so the ceiling is half a request per package.
UPSTREAM_REQUESTS_PER_PACKAGE = 0.5
# Sizes are near-deterministic for the pinned fixture, so these are ~2x:
# SQLite growth 13.9 MB per push, CLI JSON report 10.6 MB, largest read
# (graph page at limit=100) 2.0 MB.
INGEST_GROWTH_BYTES = 32 * 1024 * 1024
REPORT_BYTES = 24 * 1024 * 1024
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
    assert stages["scan_enrichment"]["report_bytes"] <= REPORT_BYTES, stages["scan_enrichment"]["report_bytes"]
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
