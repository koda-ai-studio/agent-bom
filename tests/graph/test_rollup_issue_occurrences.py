"""A finding node shared by several assets counts one issue per occurrence."""

from __future__ import annotations

import pytest

from agent_bom.graph import UnifiedEdge
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.rollup import rollup_view
from agent_bom.graph.rollup_issues import build_issue_index
from agent_bom.graph.types import EntityType, RelationshipType

pytestmark = pytest.mark.graph_contract("warn")


def test_shared_benchmark_node_contributes_each_recorded_occurrence() -> None:
    graph = UnifiedGraph(scan_id="issues", tenant_id="t")
    graph.add_node(
        UnifiedNode(
            id="misconfig:cis_benchmark:1.16",
            entity_type=EntityType.MISCONFIGURATION,
            label="CIS 1.16",
            severity="high",
            attributes={"finding_ids_by_asset": {"role:a": ["f-1"], "role:b": ["f-2", "f-3"]}},
        )
    )
    graph.add_node(
        UnifiedNode(
            id="misconfig:iac:x", entity_type=EntityType.MISCONFIGURATION, label="x", severity="low", attributes={"finding_id": "f-9"}
        )
    )
    index = build_issue_index(graph)
    assert index["misconfig:cis_benchmark:1.16"] == ("occurrence:f-1", "occurrence:f-2", "occurrence:f-3")
    assert index["misconfig:iac:x"] == ("occurrence:f-9",)


def _shared_advisory_graph() -> UnifiedGraph:
    """One advisory node: two image packages record their findings, a third package holds it unrecorded."""
    graph = UnifiedGraph(scan_id="occurrences", tenant_id="t")
    graph.add_node(UnifiedNode(id="org:o", entity_type=EntityType.ORG, label="o"))
    graph.add_node(UnifiedNode(id="account:a", entity_type=EntityType.ACCOUNT, label="a"))
    graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="s"))
    graph.add_edge(UnifiedEdge(source="org:o", target="account:a", relationship=RelationshipType.CONTAINS))
    graph.add_edge(UnifiedEdge(source="account:a", target="server:s", relationship=RelationshipType.CONTAINS))
    graph.add_node(
        UnifiedNode(
            id="vuln:CVE-2020-14343",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-2020-14343",
            severity="critical",
            attributes={
                "vulnerability_id": "CVE-2020-14343",
                "finding_ids_by_asset": {"pkg:pypi:pyyaml@5.3:image:a": ["f-a"], "pkg:pypi:pyyaml@5.3:image:b": ["f-b"]},
            },
        )
    )
    for package in ("pkg:pypi:pyyaml@5.3:image:a", "pkg:pypi:pyyaml@5.3:image:b", "pkg:pypi:pyyaml@5.3"):
        graph.add_node(UnifiedNode(id=package, entity_type=EntityType.PACKAGE, label="pyyaml@5.3", attributes={"version": "5.3"}))
        graph.add_edge(UnifiedEdge(source="server:s", target=package, relationship=RelationshipType.DEPENDS_ON))
        graph.add_edge(UnifiedEdge(source=package, target="vuln:CVE-2020-14343", relationship=RelationshipType.VULNERABLE_TO))
    graph.add_node(
        UnifiedNode(
            id="misconfig:cis:1",
            entity_type=EntityType.MISCONFIGURATION,
            label="cis",
            severity="high",
            attributes={"finding_ids_by_asset": {"role:a": ["m-1"], "role:b": ["m-2"]}},
        )
    )
    graph.add_edge(UnifiedEdge(source="account:a", target="misconfig:cis:1", relationship=RelationshipType.CONTAINS))
    return graph


def test_occurrences_count_each_recorded_finding_and_unrecorded_holder_not_each_node() -> None:
    summary = rollup_view(_shared_advisory_graph())["summary"]
    # Two finding nodes and three issues (one advisory on one package, two
    # benchmark occurrences), but five occurrences: f-a, f-b, the pyyaml
    # holder the graph models without a recorded finding id, m-1 and m-2.
    assert summary["issue_count"] == 3
    assert summary["finding_occurrence_count"] == 5


def test_a_shared_advisory_without_recorded_ids_counts_one_occurrence_per_holder() -> None:
    graph = _shared_advisory_graph()
    graph.nodes["vuln:CVE-2020-14343"].attributes.pop("finding_ids_by_asset")
    summary = rollup_view(graph)["summary"]
    assert summary["finding_occurrence_count"] == 3 + 2
    assert summary["finding_occurrence_count"] >= summary["issue_count"]


def test_a_scope_counts_only_the_occurrences_it_holds() -> None:
    graph = _shared_advisory_graph()
    graph.add_node(UnifiedNode(id="org:other", entity_type=EntityType.ORG, label="other"))
    view = rollup_view(graph)
    org = next(entry for entry in view["top_level"] if entry["id"] == "org:o")
    assert org["aggregate"]["finding_occurrence_count"] == 5
