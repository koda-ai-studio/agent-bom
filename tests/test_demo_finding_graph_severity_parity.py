"""The demo graph rates every finding exactly as the findings list does.

``misconfig:showcase:sg-open`` carried an empty severity, so the graph severity
histogram summed one short of the findings total; and CVE-2022-0235 was rated
medium/6.1 on the bundled inventory but high in the estate, so its one advisory
node could not agree with both. Each finding now joins to a node with its own
severity, and one advisory has one severity everywhere.
"""

from __future__ import annotations

from collections import Counter

import pytest

from agent_bom.graph.types import EntityType


@pytest.fixture(scope="module")
def graph_and_findings():
    from agent_bom.demo_estate import showcase_graph as sg
    from agent_bom.demo_estate.bootstrap import _run_demo_scan_report

    identities = sg.build_demo_identity_store("default")
    graph, identity_store, drift_store = sg.build_showcase_graph(
        tenant_id="default", scan_id="showcase", profile="current", identity_store=identities
    )
    sg.apply_showcase_overlays(graph, tenant_id="default", identity_store=identity_store, drift_store=drift_store)
    sg.finalize_showcase_snapshot(graph, profile="current")
    sg.project_estate_onto_showcase(graph, tenant_id="default", profile="current")
    return graph, _run_demo_scan_report(tenant_id="default")["findings"]


def test_every_finding_joins_a_node_with_its_own_severity(graph_and_findings) -> None:
    graph, findings = graph_and_findings
    mismatched = []
    for row in findings:
        node = graph.nodes.get(str(row.get("finding_node_id") or ""))
        assert node is not None, row.get("finding_node_id")
        if node.severity != str(row.get("severity") or "").lower():
            mismatched.append((row["finding_node_id"], node.severity, row.get("severity")))
    assert not mismatched


def test_graph_severity_counts_equal_finding_counts(graph_and_findings) -> None:
    graph, findings = graph_and_findings
    by_finding = Counter(str(row.get("severity") or "").lower() for row in findings)
    by_graph = Counter(graph.nodes[row["finding_node_id"]].severity for row in findings)
    assert by_graph == by_finding
    assert sum(by_graph.values()) == len(findings)


def test_no_finding_node_is_unrated(graph_and_findings) -> None:
    graph, _ = graph_and_findings
    unrated = [
        node.id
        for node in graph.nodes.values()
        if node.entity_type in (EntityType.VULNERABILITY, EntityType.MISCONFIGURATION) and not node.severity
    ]
    assert not unrated
