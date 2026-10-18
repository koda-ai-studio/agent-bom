"""Vercel ownership/configuration relationships, without runtime inference."""

from __future__ import annotations

from typing import Any

from agent_bom.cloud.resource_model import normalize_cloud_inventory
from agent_bom.cloud.vercel_model import node_id
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge
from agent_bom.graph.types import EntityType, RelationshipType


def project_vercel_inventory(graph: UnifiedGraph, inventory: dict[str, Any]) -> None:
    account = inventory.get("account_id")
    if not isinstance(account, str) or not account:
        return
    account_node = "account:vercel:" + account
    graph.add_node(
        UnifiedNode(
            id=account_node,
            entity_type=EntityType.ACCOUNT,
            label=account,
            attributes={"account_id": account, "cloud_provider": "vercel"},
            data_sources=["vercel-management"],
        )
    )
    resources = normalize_cloud_inventory(inventory)
    projects = {r.raw["id"] for r in resources if r.native_type == "vercel.project"}
    for resource in resources:
        item = resource.raw
        kind = resource.native_type.split(".")[-1]
        if kind == "deployment" and item.get("project_id") not in projects:
            continue
        identifier = node_id(account, kind, item["id"])
        graph.add_node(
            UnifiedNode(
                id=identifier,
                entity_type=EntityType.CLOUD_RESOURCE,
                label=resource.name,
                attributes={
                    **item,
                    "resource_id": resource.resource_id,
                    "resource_kind": resource.native_type,
                    "cloud_provider": "vercel",
                    "internet_exposed": None,
                    "source": "vercel-management",
                },
                dimensions=NodeDimensions(cloud_provider="vercel", surface="cloud"),
                data_sources=["vercel-management"],
            )
        )
        parent = account_node if kind == "project" else node_id(account, "project", item["project_id"])
        _add_rel_edge(
            graph,
            parent,
            identifier,
            RelationshipType.OWNS if kind == "project" else RelationshipType.CONTAINS,
            {"source": "vercel-management", "basis": "accountId" if kind == "project" else "projectId", "tier": "modeled_infrastructure"},
        )
    for finding in inventory.get("findings", []):
        if not isinstance(finding, dict) or finding.get("node_id") not in graph.nodes:
            continue
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
                    "cloud_provider": "vercel",
                    "evidence": finding["evidence"],
                },
                data_sources=["vercel-management"],
            )
        )
        _add_rel_edge(
            graph,
            fid,
            finding["node_id"],
            RelationshipType.AFFECTS,
            {"source": "vercel-management", "basis": "configuration", "tier": "modeled_infrastructure"},
        )
