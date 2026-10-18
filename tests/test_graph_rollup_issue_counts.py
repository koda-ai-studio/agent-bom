"""Roll-up severity counts open finding issues, not every rated node.

The scope card reads ``aggregate.severity_counts`` as "contained critical /
high". It must count what the overview counts: open findings, VEX-suppressed
ones excluded, grouped onto one issue per advisory and package. A rated asset
(an agent or package carrying a rolled-up risk severity) is not a finding.
"""

from __future__ import annotations

import pytest

from agent_bom.graph import UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.rollup import drill_down, rollup_view
from agent_bom.graph.rollup_edges import MAX_CROSS_CONTAINER_EDGES as _MAX_CROSS_CONTAINER_EDGES
from agent_bom.graph.types import EntityType, RelationshipType

pytestmark = pytest.mark.graph_contract("warn")


def _edge(graph: UnifiedGraph, source: str, target: str, rel: RelationshipType) -> None:
    graph.add_edge(UnifiedEdge(source=source, target=target, relationship=rel))


def _package(graph: UnifiedGraph, node_id: str, label: str, *, severity: str = "") -> None:
    name, _, version = label.rpartition("@")
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=EntityType.PACKAGE,
            label=label,
            severity=severity,
            attributes={"version": version, "ecosystem": "pypi", "purl": f"pkg:pypi/{name}@{version}"},
        )
    )


def _vuln(graph: UnifiedGraph, node_id: str, cve: str, severity: str, **attrs: object) -> None:
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=EntityType.VULNERABILITY,
            label=cve,
            severity=severity,
            attributes={"vulnerability_id": cve, **attrs},
        )
    )


def _estate() -> UnifiedGraph:
    """org -> account -> two servers, each with its own pyyaml occurrence of one CVE."""
    g = UnifiedGraph(scan_id="issues", tenant_id="default")
    g.add_node(UnifiedNode(id="org:acme", entity_type=EntityType.ORG, label="Acme"))
    g.add_node(UnifiedNode(id="account:prod", entity_type=EntityType.ACCOUNT, label="prod"))
    _edge(g, "org:acme", "account:prod", RelationshipType.CONTAINS)
    for index in (1, 2):
        server = f"server:s{index}"
        package = f"pkg:pyyaml:{index}"
        g.add_node(UnifiedNode(id=server, entity_type=EntityType.SERVER, label=server, severity="critical"))
        _edge(g, "account:prod", server, RelationshipType.CONTAINS)
        # A rated asset: its severity is a roll-up of the findings beneath it.
        _package(g, package, "PyYAML@5.3", severity="critical")
        _edge(g, server, package, RelationshipType.DEPENDS_ON)
        # One occurrence node per asset, the same advisory on the same package.
        vuln = f"vuln:occurrence:{index}"
        _vuln(g, vuln, "CVE-2020-14343", "critical", finding_id=f"finding-{index}")
        _edge(g, package, vuln, RelationshipType.VULNERABLE_TO)
    # A misconfiguration is its own issue per occurrence.
    g.add_node(
        UnifiedNode(
            id="mc:open-sg", entity_type=EntityType.MISCONFIGURATION, label="open sg", severity="high", attributes={"finding_id": "mc-1"}
        )
    )
    _edge(g, "account:prod", "mc:open-sg", RelationshipType.CONTAINS)
    # Operator-asserted VEX not_affected: kept as evidence, not an open finding.
    _vuln(g, "vuln:suppressed", "CVE-2024-9999", "critical", vex_status="not_affected", vex_source="operator")
    _edge(g, "pkg:pyyaml:1", "vuln:suppressed", RelationshipType.VULNERABLE_TO)
    return g


def test_rollup_severity_counts_distinct_open_issues_not_rated_nodes() -> None:
    view = rollup_view(_estate())
    org = next(entry for entry in view["top_level"] if entry["id"] == "org:acme")
    agg = org["aggregate"]

    # Two occurrences of CVE-2020-14343 on pyyaml are one issue; the suppressed
    # CVE and the critical-rated servers/packages are not findings at all.
    assert agg["severity_counts"]["critical"] == 1
    assert agg["severity_counts"]["high"] == 1
    assert agg["issue_count"] == 2
    assert agg["finding_occurrence_count"] == 3
    # The node histogram stays available under an explicit name.
    assert agg["node_severity_counts"]["critical"] == 2 + 2 + 2 + 1
    assert view["aggregate_count_metadata"]["severity_basis"] == "issue_groups"

    summary = view["summary"]
    assert summary["issue_severity_counts"]["critical"] == 1
    assert summary["issue_severity_counts"]["high"] == 1
    assert summary["issue_count"] == 2


def test_one_shared_advisory_node_counts_one_issue_per_package() -> None:
    g = UnifiedGraph(scan_id="shared", tenant_id="default")
    g.add_node(UnifiedNode(id="org:acme", entity_type=EntityType.ORG, label="Acme"))
    g.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="s"))
    _edge(g, "org:acme", "server:s", RelationshipType.CONTAINS)
    _package(g, "pkg:a", "requests@2.0")
    _package(g, "pkg:b", "urllib3@1.0")
    _edge(g, "server:s", "pkg:a", RelationshipType.DEPENDS_ON)
    _edge(g, "server:s", "pkg:b", RelationshipType.DEPENDS_ON)
    # Scanner graphs keep one node per advisory, linked from every package.
    _vuln(g, "vuln:CVE-2024-1", "CVE-2024-1", "high")
    _edge(g, "pkg:a", "vuln:CVE-2024-1", RelationshipType.VULNERABLE_TO)
    _edge(g, "pkg:b", "vuln:CVE-2024-1", RelationshipType.VULNERABLE_TO)

    view = rollup_view(g)
    assert view["top_level"][0]["aggregate"]["severity_counts"]["high"] == 2
    assert view["summary"]["issue_severity_counts"]["high"] == 2


def test_orphan_findings_reach_the_estate_issue_total() -> None:
    g = _estate()
    g.add_node(UnifiedNode(id="mc:orphan", entity_type=EntityType.MISCONFIGURATION, label="orphan", severity="low"))
    view = rollup_view(g)
    assert view["summary"]["issue_severity_counts"]["low"] == 1
    assert view["summary"]["issue_count"] == 3
    assert view["orphan_summary"]["issue_severity_counts"]["low"] == 1


def test_drilldown_children_carry_issue_basis_and_connection_totals() -> None:
    g = UnifiedGraph(scan_id="wide", tenant_id="default")
    g.add_node(UnifiedNode(id="org:wide", entity_type=EntityType.ORG, label="wide"))
    child_count = _MAX_CROSS_CONTAINER_EDGES + 50
    for index in range(child_count):
        account = f"account:{index:04d}"
        g.add_node(UnifiedNode(id=account, entity_type=EntityType.ACCOUNT, label=account))
        _edge(g, "org:wide", account, RelationshipType.CONTAINS)
        role = f"role:{index:04d}"
        g.add_node(UnifiedNode(id=role, entity_type=EntityType.ROLE, label=role))
        _edge(g, account, role, RelationshipType.CONTAINS)
    # account:0000 holds a role trusted by a role in every other account.
    for index in range(1, child_count):
        _edge(g, f"role:{index:04d}", "role:0000", RelationshipType.TRUSTS)

    page = drill_down(g, "org:wide", offset=0, limit=child_count)
    assert page["summary"]["direct_child_count"] == child_count
    assert page["summary"]["returned_child_count"] == child_count
    # The presentation cap trims the edge rows the UI counts...
    assert page["edge_count_metadata"]["truncated"] is True
    assert len(page["edges"]) == _MAX_CROSS_CONTAINER_EDGES
    hub = next(child for child in page["children"] if child["id"] == "account:0000")
    # ...so each entry carries the uncapped total of connected entries itself.
    assert hub["connections"]["connected_entry_count"] == child_count - 1
    assert hub["connections"]["relationship_count"] == child_count - 1
    assert "before the row cap" in page["edge_count_metadata"]["connections_definition"]

    small = drill_down(g, "org:wide", offset=0, limit=3)
    assert small["summary"]["direct_child_count"] == child_count
    assert small["summary"]["returned_child_count"] == 3
    assert small["pagination"]["total"] == child_count
