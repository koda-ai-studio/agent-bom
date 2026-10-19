"""The in-memory blast radius follows the same reach policy as the stores.

``UnifiedGraph.impact_of`` feeds OCSF ``graph_context.blast_radius`` and the
in-memory API double, so walking containment or finding edges there made a
cluster, its environment and sibling findings "affected" while the REST and MCP
answers for the same node said otherwise.
"""

from __future__ import annotations

from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def _estate() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="reach-policy", tenant_id="default")
    for node_id, kind in (
        ("env:prod", EntityType.ENVIRONMENT),
        ("cluster:k8s", EntityType.CLUSTER),
        ("agent:copilot", EntityType.AGENT),
        ("server:files", EntityType.SERVER),
        ("pkg:npm/left-pad@1.0.0", EntityType.PACKAGE),
        ("vuln:CVE-2026-0001", EntityType.VULNERABILITY),
        ("vuln:CVE-2026-0002", EntityType.VULNERABILITY),
    ):
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))
    for source, target, rel in (
        ("env:prod", "cluster:k8s", RelationshipType.CONTAINS),
        ("cluster:k8s", "server:files", RelationshipType.CONTAINS),
        ("agent:copilot", "server:files", RelationshipType.USES),
        ("server:files", "pkg:npm/left-pad@1.0.0", RelationshipType.DEPENDS_ON),
        ("pkg:npm/left-pad@1.0.0", "vuln:CVE-2026-0001", RelationshipType.VULNERABLE_TO),
        ("pkg:npm/left-pad@1.0.0", "vuln:CVE-2026-0002", RelationshipType.VULNERABLE_TO),
    ):
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=rel))
    return graph


def test_asset_impact_skips_containment_parents() -> None:
    impact = _estate().impact_of("server:files")
    assert impact["affected_nodes"] == ["agent:copilot"]
    assert impact["affected_by_type"] == {"agent": 1}
    assert impact["max_depth_reached"] == 1


def test_package_impact_walks_dependants_not_its_findings() -> None:
    impact = _estate().impact_of("pkg:npm/left-pad@1.0.0")
    assert impact["affected_nodes"] == ["agent:copilot", "server:files"]
    assert impact["max_depth_reached"] == 2


def test_finding_impact_enters_through_the_named_asset() -> None:
    impact = _estate().impact_of("vuln:CVE-2026-0001")
    # The sibling CVE on the same package is not "affected" by this one, and
    # the containment parents of the server are not either.
    assert impact["affected_nodes"] == ["agent:copilot", "pkg:npm/left-pad@1.0.0", "server:files"]
    assert impact["max_depth_reached"] == 3


def test_depth_budget_counts_the_finding_hop() -> None:
    impact = _estate().impact_of("vuln:CVE-2026-0001", max_depth=2)
    assert impact["affected_nodes"] == ["pkg:npm/left-pad@1.0.0", "server:files"]


def test_unknown_node_has_no_impact() -> None:
    assert _estate().impact_of("missing")["affected_count"] == 0
