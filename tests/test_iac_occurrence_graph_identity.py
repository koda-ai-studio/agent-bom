"""Distinct IaC evidence at one source coordinate must survive every graph join."""

import copy

import pytest

from agent_bom.finding import iac_finding_to_finding
from agent_bom.graph import EntityType
from agent_bom.graph.asset_entity import link_findings_to_graph_nodes
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.models import AIBOMReport
from agent_bom.output.json_fmt import to_json, to_redacted_json


@pytest.mark.parametrize("path", ["infra/deployment.yaml", "/private/team/deployment.yaml"])
def test_distinct_same_line_iac_occurrences_preserve_findings_and_references(path):
    hits = [
        {
            "rule_id": "K8S-004",
            "category": "kubernetes",
            "file_path": path,
            "line_number": 12,
            "title": "Dangerous capability",
            "message": capability,
            "severity": "high",
        }
        for capability in ("NET_RAW", "SYS_ADMIN")
    ]
    findings = [iac_finding_to_finding(hit) for hit in hits]
    report = AIBOMReport(agents=[], findings=findings, iac_findings_data={"findings": hits + [copy.deepcopy(hits[0])]})
    graph = build_unified_graph_from_report(to_json(report))
    nodes = [node for node in graph.nodes.values() if node.entity_type == EntityType.MISCONFIGURATION]
    assert len(nodes) == 2
    assert {node.attributes["message"] for node in nodes} == {"NET_RAW", "SYS_ADMIN"}
    assert link_findings_to_graph_nodes(findings, graph) == 2
    assert len({finding.finding_node_id for finding in findings}) == 2
    for finding in findings:
        assert graph.nodes[finding.finding_node_id].attributes["finding_id"] == finding.id
        assert graph.has_edge(finding.finding_node_id, finding.node_id)
    for serialized in (to_json(report), to_redacted_json(report)):
        rebuilt = build_unified_graph_from_report(serialized)
        assert len([node for node in rebuilt.nodes.values() if node.entity_type == EntityType.MISCONFIGURATION]) == 2
        for row in serialized["findings"]:
            assert row["finding_node_id"] in rebuilt.nodes
            assert rebuilt.has_edge(row["finding_node_id"], row["node_id"])
        reversed_report = copy.deepcopy(serialized)
        reversed_report["iac_findings"]["findings"].reverse()
        reversed_graph = build_unified_graph_from_report(reversed_report)
        assert set(rebuilt.nodes) == set(reversed_graph.nodes)


def test_occurrence_identity_does_not_depend_on_other_hits_or_duplicate_order():
    from agent_bom.evidence.iac_identity import prepare_iac_occurrences

    first = {"rule_id": "K8S-004", "file_path": "pod.yaml", "line_number": 3, "title": "Capability", "message": "NET_RAW"}
    second = {**first, "message": "SYS_ADMIN"}
    source = {"iac_findings": {"findings": [first]}}
    original = copy.deepcopy(source)
    alone = prepare_iac_occurrences(source)["iac_findings"]["findings"][0]["occurrence_id"]
    together = prepare_iac_occurrences({"iac_findings": {"findings": [second, first, first]}})
    assert together["iac_findings"]["findings"][1]["occurrence_id"] == alone
    assert together["iac_findings"]["findings"][2]["occurrence_id"] == alone
    assert together["iac_findings"]["findings"][0]["occurrence_id"] != alone
    assert source == original


def test_legacy_join_does_not_guess_between_different_occurrences():
    from agent_bom.evidence.iac_identity import prepare_iac_occurrences

    hit = {"rule_id": "R", "file_path": "main.tf", "line_number": 1, "title": "Public", "message": "one"}
    row = {"id": "legacy-import", "evidence": {"iac": True, "rule_id": "R", "file_path": "main.tf", "line_number": 1}}
    prepared = prepare_iac_occurrences({"iac_findings": {"findings": [hit, {**hit, "message": "two"}]}, "findings": [row]})
    assert prepared["findings"] == [row]


def test_imported_occurrence_key_must_be_an_opaque_uuid():
    from agent_bom.evidence.iac_identity import iac_occurrence_id, prepare_iac_occurrences

    hit = {"rule_id": "R", "file_path": "main.tf", "line_number": 1, "title": "Public", "occurrence_id": "/private/path"}
    prepared = prepare_iac_occurrences({"iac_findings": {"findings": [hit]}})
    assert prepared["iac_findings"]["findings"][0]["occurrence_id"] == iac_occurrence_id(hit)


def test_occurrence_ids_survive_persist_reload_and_reingest(tmp_path):
    from agent_bom.db.graph_store import load_graph, open_graph_db, save_graph

    hits = [
        {"rule_id": "R", "file_path": "infra/main.tf", "line_number": 2, "title": "Policy", "message": value}
        for value in ("first", "second")
    ]
    report = AIBOMReport(agents=[], iac_findings_data={"findings": hits})
    payload = to_json(report)
    graph = build_unified_graph_from_report(payload, scan_id="occurrences", tenant_id="tenant-a")
    expected = {row["finding_node_id"] for row in payload["findings"]}
    assert len(expected) == 2
    with open_graph_db(tmp_path / "graph.db") as conn:
        save_graph(conn, graph)
    with open_graph_db(tmp_path / "graph.db") as conn:
        loaded = load_graph(conn, scan_id="occurrences", tenant_id="tenant-a")
        assert expected <= loaded.nodes.keys()
        save_graph(conn, build_unified_graph_from_report(payload, scan_id="occurrences", tenant_id="tenant-a"))
        again = load_graph(conn, scan_id="occurrences", tenant_id="tenant-a")
        assert set(loaded.nodes) == set(again.nodes)
        assert {edge.id for edge in loaded.edges} == {edge.id for edge in again.edges}
        assert not load_graph(conn, scan_id="occurrences", tenant_id="tenant-b").nodes
