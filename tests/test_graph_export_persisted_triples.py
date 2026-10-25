"""The JSON export's (source, target, relationship) triples are the persisted graph's."""

from __future__ import annotations

from unittest import mock

from agent_bom.api import pipeline
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import ScanJob, ScanRequest
from agent_bom.graph.evaluation import evaluate_graph
from agent_bom.output.graph_export import build_graph_from_scan_data, to_json
from tests.test_graph_export import _agent, _make_scan_json, _pkg, _server, _vuln


def _report() -> dict:
    vulnerable = _pkg("next", "16.2.6", "npm", vulns=[_vuln("CVE-2026-21441", "critical")])
    server = _server("github", [vulnerable, _pkg("lodash", "4.17.21", "npm")], credential_env_vars=["GITHUB_TOKEN"])
    return {**_make_scan_json([_agent("triples-agent", [server])]), "scan_id": "triples-scan"}


def test_export_relationships_are_the_persisted_relationships(tmp_path):
    report = _report()
    store = SQLiteGraphStore(tmp_path / "graph.db")
    with mock.patch.object(pipeline, "_get_graph_store", lambda: store):
        job = ScanJob(job_id="triples-scan", tenant_id="default", created_at="2026-10-24T00:00:00Z", request=ScanRequest())
        pipeline._persist_graph_snapshot(job, report)
    persisted = store.load_graph(tenant_id="default", scan_id="triples-scan")
    persisted_triples = {(edge.source, edge.target, edge.relationship.value) for edge in persisted.edges}

    exported = to_json(build_graph_from_scan_data(report))
    exported_triples = {(edge["source"], edge["target"], edge["relationship"]) for edge in exported["edges"]}

    assert ("pkg:npm:next@16.2.6", "vuln:CVE-2026-21441", "vulnerable_to") in exported_triples
    assert exported_triples <= persisted_triples, sorted(exported_triples - persisted_triples)
    vuln_edges = [edge for edge in exported["edges"] if edge["target"] == "vuln:CVE-2026-21441"]
    assert [edge["kind"] for edge in vuln_edges] == ["affects"]  # the legacy label stays on kind


def test_expected_specs_written_with_affects_still_match():
    exported = to_json(build_graph_from_scan_data(_report()))
    for relationship in ("affects", "vulnerable_to"):
        spec = {"expected_edges": [["pkg:npm:next@16.2.6", "vuln:CVE-2026-21441", relationship]]}
        assert evaluate_graph(exported, spec).to_dict()["scores"]["edges"]["matched"] == 1, relationship
