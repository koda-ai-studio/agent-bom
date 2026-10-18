"""Supabase native inventory/advisory graph evidence, without authority inference."""

from __future__ import annotations

from typing import Any

from agent_bom.cloud.resource_model import normalize_cloud_inventory
from agent_bom.cloud.supabase_inventory import project_node_id
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge
from agent_bom.graph.types import EntityType, RelationshipType


def project_supabase_inventory(graph: UnifiedGraph, inventory: dict[str, Any]) -> None:
    """Project validated project metadata, scope, coverage and native finding links."""
    account = inventory.get("account_id")
    if not isinstance(account, str) or not account:
        return
    account_node = "account:supabase:" + account
    sources = ["supabase-management"]
    graph.add_node(
        UnifiedNode(
            id=account_node,
            entity_type=EntityType.ACCOUNT,
            label=account,
            attributes={"account_id": account, "cloud_provider": "supabase"},
            data_sources=sources,
        )
    )
    for resource in normalize_cloud_inventory(inventory):
        project = resource.raw
        node_id = project_node_id(account, project["ref"])
        attributes = {
            "resource_id": resource.resource_id,
            "resource_name": project["name"],
            "resource_type": "database",
            "resource_kind": "supabase.project",
            "cloud_provider": "supabase",
            "account_id": account,
            "project_ref": project["ref"],
            "location": project["region"],
            "provider_status": project["status"],
            "configuration": {key: value for key, value in project.items() if key.startswith("database_")},
            "coverage": inventory.get("coverage", []),
            "is_data_store": True,
            "internet_exposed": None,
            "source": "supabase-management",
        }
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=project["name"],
                attributes=attributes,
                data_sources=sources,
                dimensions=NodeDimensions(cloud_provider="supabase", surface="database"),
            )
        )
        _add_rel_edge(
            graph,
            account_node,
            node_id,
            RelationshipType.OWNS,
            {"source": "supabase-management", "basis": "project.organization_id", "tier": "modeled_infrastructure"},
        )
        _project_findings(graph, inventory, account, node_id)


def _project_findings(graph: UnifiedGraph, inventory: dict[str, Any], account: str, node_id: str) -> None:
    """Bind native finding occurrences to their exact project node."""
    for finding in inventory.get("findings", []):
        if not isinstance(finding, dict) or finding.get("node_id") != node_id:
            continue
        evidence = finding.get("evidence", {})
        fid = finding["finding_node_id"]
        graph.add_node(
            UnifiedNode(
                id=fid,
                entity_type=EntityType.MISCONFIGURATION,
                label=finding["title"],
                severity=finding["severity"],
                attributes={
                    "finding_id": finding["id"],
                    "finding_type": finding["finding_type"],
                    "finding_source": "CLOUD_SECURITY",
                    "cloud_provider": "supabase",
                    "account_id": account,
                    "evidence": evidence,
                },
                data_sources=["supabase-security-advisors"],
            )
        )
        _add_rel_edge(
            graph,
            fid,
            node_id,
            RelationshipType.AFFECTS,
            {
                "source": "supabase-security-advisors",
                "native_id": evidence.get("native_id"),
                "source_observed_at": evidence.get("source_observed_at"),
                "tier": "modeled_infrastructure",
            },
        )
