"""The graph build stores each asset's risk context with its provenance."""

from __future__ import annotations

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.risk_context_overlay import apply_node_risk_context
from agent_bom.graph.types import EntityType, RelationshipType

_RDS = "cloud_resource:aws:rds:database:arn:aws:rds:us-east-1:111122223333:db:prod-db"
_EKS = "cloud_resource:aws:eks:container_cluster:arn:aws:eks:us-east-1:111122223333:cluster/main"


def _inventory() -> dict:
    return {
        "status": "ok",
        "provider": "aws",
        "account_id": "111122223333",
        "rds_instances": [
            {
                "name": "prod-db",
                "arn": "arn:aws:rds:us-east-1:111122223333:db:prod-db",
                "engine": "postgres",
                "publicly_accessible": True,
                "location": "us-east-1",
            }
        ],
        "eks_clusters": [
            {
                "name": "main",
                "arn": "arn:aws:eks:us-east-1:111122223333:cluster/main",
                "endpoint_public": False,
                "internet_exposed": False,
                "location": "us-east-1",
            }
        ],
    }


def test_build_stores_exposure_with_the_recorded_fact_and_scan() -> None:
    graph = build_unified_graph_from_report({"scan_id": "scan-risk-1", "cloud_inventory": _inventory()})
    rds = graph.nodes[_RDS].attributes["risk_context"]
    assert rds["internet_exposed"] is True
    assert rds["scan_id"] == graph.scan_id
    assert rds["sources"] == sorted(graph.nodes[_RDS].data_sources)
    exposure = [reason for reason in rds["reasons"] if reason["field"] == "internet_exposed"]
    assert exposure[0]["rule"] == "recorded_internet_exposed"
    assert exposure[0]["evidence"]["source"] == "cloud-inventory"
    assert exposure[0]["evidence"]["inputs"] == {"publicly_accessible": True}

    eks = graph.nodes[_EKS].attributes["risk_context"]
    assert eks["internet_exposed"] is False
    assert {reason["rule"] for reason in eks["reasons"] if reason["field"] == "internet_exposed"} == {"recorded_not_public"}


def _graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="scan-k8s", tenant_id="tenant-a")
    graph.add_node(UnifiedNode(id="sa:ops", entity_type=EntityType.SERVICE_ACCOUNT, label="ops"))
    graph.add_node(UnifiedNode(id="sa:reader", entity_type=EntityType.SERVICE_ACCOUNT, label="reader"))
    graph.add_node(
        UnifiedNode(
            id="role:cluster-admin",
            entity_type=EntityType.ROLE,
            label="ClusterRole: cluster-admin",
            attributes={"kubernetes_kind": "ClusterRole", "kubernetes_name": "cluster-admin"},
        )
    )
    graph.add_node(
        UnifiedNode(
            id="role:view",
            entity_type=EntityType.ROLE,
            label="ClusterRole: view",
            attributes={"kubernetes_kind": "ClusterRole", "kubernetes_name": "view"},
        )
    )
    binding = {"binding": "ClusterRoleBinding/ops-admin", "role": "ClusterRole/cluster-admin"}
    graph.add_edge(UnifiedEdge(source="sa:ops", target="role:cluster-admin", relationship=RelationshipType.INHERITS, evidence=binding))
    graph.add_edge(
        UnifiedEdge(source="sa:reader", target="role:view", relationship=RelationshipType.INHERITS, evidence={"role": "ClusterRole/view"})
    )
    graph.add_node(
        UnifiedNode(id="pkg:x", entity_type=EntityType.PACKAGE, label="x", attributes={"internet_exposed": True, "is_admin": True})
    )
    graph.add_node(UnifiedNode(id="vuln:x", entity_type=EntityType.VULNERABILITY, label="CVE-X", attributes={"data_sensitivity": "pii"}))
    return graph


def test_cluster_admin_binding_makes_the_bound_account_admin() -> None:
    graph = _graph()
    counts = apply_node_risk_context(graph)
    ops = graph.nodes["sa:ops"].attributes["risk_context"]
    assert (ops["privilege_level"], ops["is_admin"]) == ("admin", True)
    assert ops["reasons"][0]["evidence"]["binding"] == "ClusterRoleBinding/ops-admin"
    assert "risk_context" not in graph.nodes["sa:reader"].attributes
    assert counts["admin"] == 1


def test_findings_and_packages_never_carry_risk_context() -> None:
    graph = _graph()
    apply_node_risk_context(graph)
    assert "risk_context" not in graph.nodes["pkg:x"].attributes
    assert "risk_context" not in graph.nodes["vuln:x"].attributes


def test_reapplying_drops_a_context_whose_facts_are_gone() -> None:
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(UnifiedNode(id="vm", entity_type=EntityType.CLOUD_RESOURCE, label="vm", attributes={"internet_exposed": True}))
    apply_node_risk_context(graph)
    assert graph.nodes["vm"].attributes["risk_context"]["internet_exposed"] is True
    graph.nodes["vm"].attributes.pop("internet_exposed")
    apply_node_risk_context(graph)
    assert "risk_context" not in graph.nodes["vm"].attributes


def test_crown_jewel_lists_every_matching_rule() -> None:
    graph = UnifiedGraph(scan_id="s", tenant_id="t")
    graph.add_node(
        UnifiedNode(
            id="ds",
            entity_type=EntityType.DATA_STORE,
            label="payments",
            attributes={"data_sensitivity": "pci", "asset_criticality": "crown_jewel"},
        )
    )
    apply_node_risk_context(graph)
    context = graph.nodes["ds"].attributes["risk_context"]
    assert context["crown_jewel"] is True
    rules = [reason["rule"] for reason in context["reasons"] if reason["field"] == "crown_jewel"]
    assert rules == ["sensitive_data_store", "declared_critical_asset"]
