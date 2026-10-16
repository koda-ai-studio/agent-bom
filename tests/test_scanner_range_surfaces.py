"""Unverified advisory matches stay uncertain through graph and export surfaces."""

import json

from agent_bom.db.lookup import lookup_package
from agent_bom.db.schema import init_db
from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package
from agent_bom.scanners.package_scan import _local_vuln_to_vulnerability


def _candidate_report(tmp_path):
    conn = init_db(tmp_path / "candidate.db")
    try:
        conn.execute("INSERT INTO vulns (id,summary,severity,source) VALUES ('CVE-2026-1234','Uncertain package range','high','osv')")
        conn.execute("INSERT INTO affected VALUES ('CVE-2026-1234','pypi','candidate','0','2.0','',NULL)")
        vulnerability = _local_vuln_to_vulnerability(lookup_package(conn, "pypi", "candidate", "1.0")[0])
    finally:
        conn.close()
    package = Package(name="candidate", version="1.0", ecosystem="pypi", vulnerabilities=[vulnerability])
    server = MCPServer(name="candidate-server", packages=[package])
    agent = Agent(name="candidate-agent", agent_type=AgentType.CUSTOM, config_path="/fixture/config", mcp_servers=[server])
    blast = BlastRadius(
        vulnerability=vulnerability,
        package=package,
        affected_agents=[agent],
        affected_servers=[server],
        exposed_credentials=[],
        exposed_tools=[],
        graph_reachable=True,
    )
    return AIBOMReport(scan_id="candidate-scan", agents=[agent], blast_radii=[blast])


def test_candidate_cannot_become_confirmed_reachability(tmp_path):
    from agent_bom.graph.applicability import applicability_from_payload, applicability_from_row
    from agent_bom.output import to_json

    report = _candidate_report(tmp_path)
    assert report.blast_radii[0].reachability == "unknown"
    row = to_json(report)["blast_radius"][0]
    assert row["reachability"] == "unknown"
    assert row["match_confidence_tier"] == "unverified_range"
    assert "unverified_advisory_match" in row["reachability_basis"]
    assert not applicability_from_payload(applicability_from_row(row)).permits_exploit_chain


def test_candidate_match_evidence_survives_sbom_exports(tmp_path):
    from agent_bom.output.cyclonedx_fmt import to_cyclonedx
    from agent_bom.output.spdx_fmt import to_spdx

    report = _candidate_report(tmp_path)
    cdx = to_cyclonedx(report)
    entry = cdx["vulnerabilities"][0]
    receipt = json.loads(next(p["value"] for p in entry["properties"] if p["name"] == "agent-bom:match-evidence"))
    assert receipt == {"affects_ref": entry["affects"][0]["ref"], "match_confidence_tier": "unverified_range", "fixed_version": None}
    assert "recommendation" not in entry
    assert "agent-bom:match-confidence-tier=unverified_range" in json.dumps(to_spdx(report))


def test_candidate_keeps_one_finding_and_uncertainty_after_storage_and_api(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    from agent_bom.api import stores
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.server import app
    from agent_bom.api.store import InMemoryJobStore
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.output import to_json
    from agent_bom.output.sarif import to_sarif

    report = _candidate_report(tmp_path)
    payload = to_json(report)
    jobs = InMemoryJobStore()
    jobs.put(
        ScanJob(job_id=report.scan_id, status=JobStatus.DONE, created_at="2026-10-16T00:00:00Z", request=ScanRequest(), result=payload)
    )
    monkeypatch.setattr(stores, "_store", jobs)
    database = tmp_path / "graph.db"
    store = SQLiteGraphStore(database)
    graph = build_unified_graph_from_report(payload, scan_id=report.scan_id, tenant_id="default")
    store.save_graph(graph)
    monkeypatch.setattr(stores, "_graph_store", SQLiteGraphStore(database))
    client = TestClient(app)
    response = client.get("/v1/findings")
    assert response.status_code == 200
    rows = [r for r in response.json()["findings"] if r.get("vulnerability_id") == "CVE-2026-1234"]
    assert len(rows) == 1
    assert rows[0]["match_confidence_tier"] == "unverified_range"
    assert rows[0]["reachability"] == "unknown"
    assert rows[0]["effective_reach_score"] is None
    assert rows[0]["effective_reach_band"] is None
    assert rows[0]["effective_reach"] is None
    response = client.get("/v1/graph", params={"scan_id": report.scan_id})
    assert response.status_code == 200
    assert response.json()["nodes"] and response.json()["edges"]
    assert "unverified_advisory_match" in json.dumps(response.json())
    sarif = to_sarif(report)
    results = [r for r in sarif["runs"][0]["results"] if r["ruleId"] == "CVE-2026-1234"]
    assert len(results) == 1
    assert results[0]["properties"]["match_confidence_tier"] == "unverified_range"


def test_component_scoped_match_evidence_survives_cyclonedx_reimport(tmp_path):
    from copy import deepcopy

    from agent_bom.output.cyclonedx_fmt import to_cyclonedx
    from agent_bom.sbom import parse_cyclonedx

    report = _candidate_report(tmp_path)
    known = deepcopy(report.agents[0].mcp_servers[0].packages[0])
    known.name = "known"
    known.vulnerabilities[0].match_confidence_tier = "osv_range"
    known.vulnerabilities[0].fixed_version = "2.0"
    report.agents[0].mcp_servers[0].packages.insert(0, known)
    cdx = to_cyclonedx(report)
    assert len(cdx["vulnerabilities"]) == 1
    assert "recommendation" not in cdx["vulnerabilities"][0]
    packages = {p.name: p for p in parse_cyclonedx(cdx)}
    assert packages["candidate"].vulnerabilities[0].match_confidence_tier == "unverified_range"
    assert packages["known"].vulnerabilities[0].match_confidence_tier == "osv_range"
    assert packages["known"].vulnerabilities[0].fixed_version == "2.0"
    assert packages["candidate"].vulnerabilities[0].fixed_version is None
    assert packages["candidate"].vulnerabilities[0] is not packages["known"].vulnerabilities[0]
