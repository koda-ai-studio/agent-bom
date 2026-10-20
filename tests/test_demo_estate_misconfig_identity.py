"""Estate misconfigurations follow the product's finding-node contract and occurrence edges.

The estate minted ``misconfig:demo-estate:<finding-id>`` per finding and linked
it only by ``affects``/``contains``, so no attack path could end at one. Each
finding is now an occurrence of the node ``finding_row_node_id`` names (one per
benchmark check, IaC rule hit or finding, as for a live scan), and the asset
holds it by ``vulnerable_to`` wherever the relationship contract admits that
asset kind, exactly as ``graph.finding_row_projection`` attaches a finding row.
"""

from __future__ import annotations

import pytest

from agent_bom.demo_estate.enterprise_composition import build_demo_estate
from agent_bom.demo_estate.enterprise_findings import build_estate_findings
from agent_bom.demo_estate.estate_graph import project_estate_into_graph
from agent_bom.evidence.finding_node_ids import finding_row_node_id
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.relationship_specs import relationship_spec
from agent_bom.graph.types import EntityType, RelationshipType


@pytest.fixture(scope="module")
def estate_findings():
    estate = build_demo_estate(tenant_id="default")
    return estate, build_estate_findings(estate)


@pytest.fixture(scope="module")
def graph(estate_findings):
    estate, findings = estate_findings
    built = UnifiedGraph(scan_id="estate-misconfig-identity", tenant_id="default")
    project_estate_into_graph(built, estate, findings=findings)
    return built


def _misconfigs(findings):
    return [f for f in findings if f.finding_type.value != "CVE"]


def test_no_per_finding_estate_misconfig_ids_remain(graph) -> None:
    assert not [node_id for node_id in graph.nodes if node_id.startswith("misconfig:demo-estate:")]


def test_finding_node_ids_follow_the_product_contract(estate_findings, graph) -> None:
    _, findings = estate_findings
    for finding in _misconfigs(findings):
        assert finding.finding_node_id == finding_row_node_id(finding.to_dict())
        node = graph.nodes[finding.finding_node_id]
        assert node.entity_type is EntityType.MISCONFIGURATION
        assert finding.id in node.attributes["finding_ids_by_asset"][finding.node_id]
        assert f"misconfig:demo-estate:{finding.id}" in node.attributes["identity"]["aliases"]
    shared = [n for n in graph.nodes.values() if len(n.attributes.get("finding_ids_by_asset") or {}) > 1]
    assert shared, "benchmark checks failing on several assets share one node, as in a live scan"


def test_assets_hold_their_misconfigurations_as_the_contract_admits(estate_findings, graph) -> None:
    _, findings = estate_findings
    spec = relationship_spec(RelationshipType.VULNERABLE_TO)
    assert spec is not None
    edges = {(e.source, e.target, e.relationship): e for e in graph.edges}
    held = 0
    for finding in _misconfigs(findings):
        asset = graph.nodes[finding.node_id]
        assert (finding.finding_node_id, finding.node_id, RelationshipType.AFFECTS) in edges
        occurrence = edges.get((finding.node_id, finding.finding_node_id, RelationshipType.VULNERABLE_TO))
        if spec.allows(asset.entity_type, EntityType.MISCONFIGURATION):
            assert occurrence is not None, (finding.node_id, finding.finding_node_id)
            assert finding.id in occurrence.evidence["finding_ids"]
            assert isinstance(occurrence.evidence.get("applicability"), dict)
            held += 1
        else:
            assert occurrence is None
    assert held > 100
