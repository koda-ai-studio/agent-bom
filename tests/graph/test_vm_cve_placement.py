"""A CVE found on a VM rolls up under its instance, carries a verdict, and never reaches itself."""

from __future__ import annotations

from agent_bom.api import finding_reachability
from agent_bom.api.finding_reachability import project_attack_path_reachability
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.finding_row_projection import project_finding_rows
from agent_bom.graph.rollup import rollup_view

_INSTANCE = "cloud_resource:aws:aws_instance:111122223333/us-east-1/i-0abc"
_CVE = "vuln:CVE-2023-38408"


def _vm_graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="estate", tenant_id="default")
    graph.add_node(UnifiedNode(id="account:aws:111122223333", entity_type=EntityType.ACCOUNT, label="prod"))
    graph.add_node(UnifiedNode(id=_INSTANCE, entity_type=EntityType.CLOUD_RESOURCE, label="i-0abc"))
    graph.add_node(UnifiedNode(id=_CVE, entity_type=EntityType.VULNERABILITY, label="CVE-2023-38408", severity="high"))
    graph.add_edge(UnifiedEdge(source="account:aws:111122223333", target=_INSTANCE, relationship=RelationshipType.OWNS))
    graph.add_edge(UnifiedEdge(source=_INSTANCE, target=_CVE, relationship=RelationshipType.VULNERABLE_TO))
    return graph


def test_vm_cve_is_placed_under_its_instance_not_an_orphan():
    payload = rollup_view(_vm_graph())

    top_ids = {entry["id"] for entry in payload["top_level"]}
    assert _CVE not in top_ids
    assert payload["orphan_summary"]["by_type"].get("vulnerability", 0) == 0
    account = next(entry for entry in payload["top_level"] if entry["id"] == "account:aws:111122223333")
    assert account["aggregate"]["descendant_count"] == 2
    assert account["aggregate"]["worst_severity"] == "high"


def test_cloud_cve_finding_node_carries_a_verdict_and_effective_reach():
    graph = UnifiedGraph(scan_id="estate", tenant_id="default")
    graph.add_node(UnifiedNode(id=_INSTANCE, entity_type=EntityType.CLOUD_RESOURCE, label="i-0abc"))
    row = {
        "id": "compute-cve-01",
        "finding_type": "CVE",
        "source": "CLOUD_SECURITY",
        "cve_id": "CVE-2023-38408",
        "severity": "high",
        "node_id": _INSTANCE,
        "finding_node_id": _CVE,
        "effective_reach_score": 42.5,
        "effective_reach_band": "amber",
    }

    project_finding_rows(graph, [row])

    attributes = graph.nodes[_CVE].attributes
    assert attributes["reachability"] == "unknown"
    assert attributes["reachability_basis"]
    assert attributes["effective_reach_score"] == 42.5
    assert attributes["effective_reach_band"] == "amber"


def test_a_path_from_the_findings_own_holder_is_not_inbound_reach():
    finding_reachability.clear_reachability_index_cache()
    self_path = AttackPath(
        source=_INSTANCE,
        target=_CVE,
        hops=[_INSTANCE, _CVE],
        edges=["vulnerable_to"],
        finding_ids=["compute-cve-01"],
        vuln_ids=["CVE-2023-38408"],
    )
    rows = [{"id": "compute-cve-01", "cve_id": "CVE-2023-38408", "node_id": _INSTANCE}]

    stamped = project_attack_path_reachability(rows, [self_path])

    assert stamped == 0
    assert rows[0].get("graph_reachable") is None
    assert _INSTANCE not in (rows[0].get("graph_reachable_from") or [])


def test_an_inbound_path_through_the_holder_still_counts_without_listing_the_holder():
    agent_path = AttackPath(
        source="agent:ops",
        target=_CVE,
        hops=["agent:ops", "server:s", _INSTANCE, _CVE],
        edges=["uses", "hosted_on", "vulnerable_to"],
        finding_ids=["compute-cve-01"],
        vuln_ids=["CVE-2023-38408"],
    )
    rows = [{"id": "compute-cve-01", "cve_id": "CVE-2023-38408", "node_id": _INSTANCE}]

    project_attack_path_reachability(rows, [agent_path])

    assert rows[0]["graph_reachable"] is True
    assert rows[0]["graph_reachable_from"] == ["agent:ops"]
