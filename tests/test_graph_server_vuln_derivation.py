"""A server's vulnerability shortcut is marked as derived from its package."""

from __future__ import annotations

from types import SimpleNamespace

from agent_bom.graph import EntityType, RelationshipType
from agent_bom.graph.asset_entity import link_findings_to_graph_nodes
from agent_bom.graph.builder import build_unified_graph_from_report
from tests.test_graph_builder import _minimal_report


def _vuln_edges(graph):
    return [edge for edge in graph.edges if edge.relationship == RelationshipType.VULNERABLE_TO and edge.target == "vuln:CVE-2024-1234"]


def test_server_vulnerability_edge_names_the_package_it_rolls_up():
    graph = build_unified_graph_from_report(_minimal_report())
    edges = _vuln_edges(graph)
    package_edges = [edge for edge in edges if graph.get_node(edge.source).entity_type == EntityType.PACKAGE]
    server_edges = [edge for edge in edges if graph.get_node(edge.source).entity_type == EntityType.SERVER]
    assert len(package_edges) == 1 and server_edges
    assert not package_edges[0].evidence.get("derived_via")
    for edge in server_edges:
        assert edge.evidence["derived_via"] == [package_edges[0].source]
        assert any(
            dep.source == edge.source and dep.target == package_edges[0].source and dep.relationship == RelationshipType.DEPENDS_ON
            for dep in graph.edges
        )


def test_finding_owner_resolves_to_package_not_both_holders():
    graph = build_unified_graph_from_report(_minimal_report())
    package_id = next(edge.source for edge in _vuln_edges(graph) if graph.get_node(edge.source).entity_type == EntityType.PACKAGE)
    finding = SimpleNamespace(id="finding-1", cve_id="CVE-2024-1234", title="", asset=None, evidence={}, node_id=None)
    link_findings_to_graph_nodes([finding], graph)
    assert finding.node_id == package_id


def test_name_only_server_link_stays_primary_evidence():
    report = _minimal_report()
    report["blast_radius"][0]["package_name"] = "not-in-inventory"
    graph = build_unified_graph_from_report(report)
    server_edges = [edge for edge in _vuln_edges(graph) if graph.get_node(edge.source).entity_type == EntityType.SERVER]
    assert server_edges
    assert all("derived_via" not in edge.evidence for edge in server_edges)
