"""Finding ↔ graph parity: one severity breakdown across report, graph, and API.

For a scan, the report's findings[], the graph's finding nodes, the graph
stats served by ``/v1/graph``, and the findings collected for ``/v1/findings``
must agree, and every finding must resolve to an existing finding node.
"""

from __future__ import annotations

import copy
import json
import os
from collections import Counter
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.severity_floor import counts_as_finding_node

ROOT = Path(__file__).resolve().parent
SCAN_ID = "parity-scan"


def _scan(tmp_path: Path, *args: str) -> dict:
    out = tmp_path / "report.json"
    CliRunner().invoke(main, ["scan", "--offline", "-f", "json", "-q", *args, "-o", str(out)])
    assert out.is_file()
    return json.loads(out.read_text())


def _graph_finding_severities(graph) -> Counter:
    return Counter(node.severity for node in graph.nodes.values() if counts_as_finding_node(node) and node.severity)


def _api_graph_severity_counts(tmp_path: Path, graph, monkeypatch) -> dict:
    from starlette.testclient import TestClient

    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.server import app
    from agent_bom.api.stores import set_graph_store

    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    monkeypatch.delenv("AGENT_BOM_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_BOM_API_KEYS", raising=False)
    graph.scan_id, graph.tenant_id = SCAN_ID, "default"
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    store.save_graph(graph)
    set_graph_store(store)
    try:
        response = TestClient(app).get(f"/v1/graph?scan_id={SCAN_ID}&limit=5")
    finally:
        set_graph_store(None)  # type: ignore[arg-type]
    assert response.status_code == 200, response.text
    return response.json()["stats"]["severity_counts"]


def _api_finding_severities(report: dict) -> Counter:
    from agent_bom.api.finding_collection import collect_scan_findings
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest

    job = ScanJob(
        job_id=SCAN_ID,
        tenant_id="default",
        request=ScanRequest(),
        status=JobStatus.DONE,
        created_at="2026-01-01T00:00:00+00:00",
        result=report,
    )
    return Counter(row["severity"] for row in collect_scan_findings(job))


def _assert_parity(tmp_path: Path, report: dict, monkeypatch) -> None:
    graph = build_unified_graph_from_report(copy.deepcopy(report), scan_id=SCAN_ID, tenant_id="default")
    report_severities = Counter(finding["severity"] for finding in report["findings"])
    assert report_severities, "parity scenario must produce findings"

    assert _graph_finding_severities(graph) == report_severities
    assert Counter(graph.stats()["severity_counts"]) == report_severities
    assert Counter(_api_graph_severity_counts(tmp_path, graph, monkeypatch)) == report_severities
    assert _api_finding_severities(report) == report_severities

    unresolved = [
        (finding["finding_type"], finding["title"])
        for finding in report["findings"]
        if not finding.get("finding_node_id") or finding["finding_node_id"] not in graph.nodes
    ]
    assert unresolved == []


def test_demo_scan_parity(tmp_path, monkeypatch):
    # An online --demo enables --enrich, which runs the legacy toxic-combination
    # detector whose graph nodes previously inflated finding counts. Offline
    # forces enrich off, so let only that detector see an enriched scan.
    from agent_bom.cli.agents.scan_pipeline import graph as graph_stage

    detect = graph_stage._detect_toxic_combinations

    def _detect_as_enriched(opts, st):
        opts.enrich = True
        detect(opts, st)

    monkeypatch.setattr(graph_stage, "_detect_toxic_combinations", _detect_as_enriched)
    report = _scan(tmp_path, "--demo")
    assert report.get("toxic_combinations"), "scenario must exercise toxic-combination nodes"
    _assert_parity(tmp_path, report, monkeypatch)


def test_iac_fixture_scan_parity(tmp_path, monkeypatch):
    report = _scan(tmp_path, "--no-scan", "--no-discover", "--exit-zero", "-p", str(ROOT / "fixtures" / "iac"))
    assert any(finding["finding_type"] == "CIS_FAIL" for finding in report["findings"])
    _assert_parity(tmp_path, report, monkeypatch)


def test_quickstart_sample_parity(tmp_path, monkeypatch):
    from agent_bom.samples import write_first_run_sample

    sample = tmp_path / "sample"
    write_first_run_sample(sample)
    report = _scan(
        tmp_path,
        "--no-scan",
        "--exit-zero",
        "--inventory",
        str(sample / "inventory.json"),
        "-p",
        str(sample),
        "--scan-prompts",
        "--agent-project",
        str(sample),
        "--ai-inventory",
        str(sample),
    )
    _assert_parity(tmp_path, report, monkeypatch)


@pytest.mark.parametrize("name", sorted(json.loads((ROOT / "fixtures" / "graph_cloud_context" / "reports.json").read_text())))
def test_cloud_fixture_stats_count_only_finding_nodes(name):
    report = json.loads((ROOT / "fixtures" / "graph_cloud_context" / "reports.json").read_text())[name]
    graph = build_unified_graph_from_report(copy.deepcopy(report), scan_id=SCAN_ID)
    assert Counter(graph.stats()["severity_counts"]) == _graph_finding_severities(graph)


def _rated_estate():
    from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode

    graph = UnifiedGraph(scan_id=SCAN_ID, tenant_id="default")
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a", severity="high"))
    graph.add_node(UnifiedNode(id="toxic:combo", entity_type=EntityType.MISCONFIGURATION, label="combo", severity="critical"))
    graph.add_node(UnifiedNode(id="vuln:CVE-1", entity_type=EntityType.VULNERABILITY, label="CVE-1", severity="critical"))
    graph.add_node(UnifiedNode(id="misconfig:iac:R:f:1", entity_type=EntityType.MISCONFIGURATION, label="R", severity="low"))
    return graph


@pytest.mark.parametrize("backend", ["sqlite", "postgres"])
def test_snapshot_severity_counts_cached_and_live_count_only_findings(tmp_path, backend):
    graph = _rated_estate()
    if backend == "sqlite":
        from agent_bom.api.graph_store import SQLiteGraphStore

        store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    else:
        if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
            pytest.skip("AGENT_BOM_POSTGRES_URL not set")
        from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
        from agent_bom.api.postgres_graph import PostgresGraphStore

        store = PostgresGraphStore()
        token = set_current_tenant("default")
    try:
        store.save_graph(graph)
        cached = store.snapshot_stats(tenant_id="default", scan_id=SCAN_ID)
        live = store.snapshot_stats(tenant_id="default", scan_id=SCAN_ID, entity_types={"agent", "misconfiguration", "vulnerability"})
    finally:
        if backend == "postgres":
            store.delete_snapshot(tenant_id="default", scan_id=SCAN_ID)
            reset_current_tenant(token)
    expected = {"critical": 1, "low": 1}
    assert graph.stats()["severity_counts"] == expected
    assert cached["severity_counts"] == expected
    assert live["severity_counts"] == expected
