"""Cloud inventory builds one connected provider -> account -> resource hierarchy.

The inventory records which provider and account every collected asset came
from. That evidence must become edges: a provider node with no edges, or an
instance with no account, surfaces as an unconnected top-level entry in the
estate roll-up and never shows under its account on drill-down.
"""

from __future__ import annotations

from typing import Any

from agent_bom.graph import RelationshipType
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.rollup import drill_down, rollup_view


def _inventory(**extra: Any) -> dict[str, Any]:
    return {
        "cloud_inventory": [
            {
                "provider": "aws",
                "status": "ok",
                "account_id": "123456789012",
                "region": "us-east-1",
                "buckets": [{"name": "logs"}],
                "instances": [{"instance_id": "i-1", "name": "web"}],
                **extra,
            }
        ]
    }


def _edges(graph: Any, rel: RelationshipType) -> set[tuple[str, str]]:
    return {(edge.source, edge.target) for edge in graph.edges if edge.relationship == rel}


def test_provider_hosts_the_inventoried_account_with_evidence() -> None:
    graph = build_unified_graph_from_report(_inventory())
    assert ("provider:aws", "account:aws:123456789012") in _edges(graph, RelationshipType.HOSTS)
    edge = next(e for e in graph.edges if e.source == "provider:aws" and e.relationship == RelationshipType.HOSTS)
    assert edge.evidence.get("source") == "cloud-inventory"
    assert edge.evidence.get("reason") == "inventory_account_provider"


def test_inventoried_instance_belongs_to_its_account() -> None:
    graph = build_unified_graph_from_report(_inventory())
    instance = next(node_id for node_id in graph.nodes if ":instance:" in node_id and node_id.endswith("/i-1"))
    assert ("account:aws:123456789012", instance) in _edges(graph, RelationshipType.CONTAINS)
    assert ("account:aws:123456789012", instance) in _edges(graph, RelationshipType.OWNS)


def test_inventory_rolls_up_to_one_provider_root_without_orphans() -> None:
    graph = build_unified_graph_from_report(_inventory())
    view = rollup_view(graph)
    assert [row["id"] for row in view["top_level"]] == ["provider:aws"]
    assert view["summary"]["orphan_count"] == 0
    assert view["top_level"][0]["aggregate"]["descendant_count"] == len(graph.nodes) - 1
    assert [row["id"] for row in drill_down(graph, "provider:aws")["children"]] == ["account:aws:123456789012"]


def _cloud_agent_report() -> dict[str, Any]:
    principal = {"principal_id": "role-1", "principal_type": "iam-role", "policies": [], "trust_principals": []}
    origin = {
        "provider": "aws",
        "service": "bedrock",
        "resource_type": "agent",
        "resource_id": "agent-1",
        "scope": {"org_id": "org-1", "account_id": "123456789012"},
        "location": "us-east-1",
    }
    metadata = {"cloud_origin": origin, "cloud_principal": principal}
    return {"agents": [{"name": "assistant", "type": "custom", "source": "aws-bedrock", "metadata": metadata, "mcp_servers": []}]}


def test_cloud_origin_scope_nests_org_account_and_principal() -> None:
    graph = build_unified_graph_from_report(_cloud_agent_report())
    assert ("org:aws:org-1", "account:aws:123456789012") in _edges(graph, RelationshipType.CONTAINS)
    assert ("account:aws:123456789012", "role:aws:role-1") in _edges(graph, RelationshipType.OWNS)
    view = rollup_view(graph)
    top_ids = {row["id"] for row in view["top_level"]}
    assert "provider:aws" in top_ids
    assert not {"org:aws:org-1", "account:aws:123456789012", "role:aws:role-1"} & top_ids
    assert [row["id"] for row in drill_down(graph, "provider:aws")["children"]] == ["org:aws:org-1"]
    assert [row["id"] for row in drill_down(graph, "org:aws:org-1")["children"]] == ["account:aws:123456789012"]
    assert "role:aws:role-1" in {row["id"] for row in drill_down(graph, "account:aws:123456789012")["children"]}


def test_provider_alone_without_account_records_no_invented_edge() -> None:
    report = _inventory()
    report["cloud_inventory"][0].pop("account_id")
    graph = build_unified_graph_from_report(report)
    assert not [edge for edge in graph.edges if edge.source == "provider:aws"]
