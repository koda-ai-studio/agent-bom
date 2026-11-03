"""Repository-scoped dbt artifacts and lineage; exact connector links stay non-traversable."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from agent_bom.core.repository_identity import relative_path, repository_id
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.dbt_identity import connector_index, qualified_parts
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.repository_identity import repository_scope, scoped_file_path, scoped_node_id
from agent_bom.graph.types import EntityType, RelationshipType

_SOURCE = "dbt-manifest"


def _edge(graph: UnifiedGraph, source: str, target: str, relationship: RelationshipType, **extra: Any) -> None:
    graph.add_edge(
        UnifiedEdge(
            source=source,
            target=target,
            relationship=relationship,
            traversable=relationship != RelationshipType.CORRELATES_WITH,
            evidence={"source": _SOURCE, "tier": "static_scan", "artifact": "target/manifest.json", **extra},
        )
    )


def apply_dbt_overlay(graph: UnifiedGraph, report: dict[str, Any], now: datetime) -> None:
    inventory = report.get("project_inventory")
    scope = repository_scope(inventory)
    if not scope or not isinstance(inventory, dict):
        return
    context = inventory.get("repository_context", {})
    dbt = context.get("dbt")
    if not isinstance(dbt, dict) or not isinstance(dbt.get("nodes"), list):
        return
    root = scoped_node_id("directory", ".", scope)
    if dbt["nodes"] and root not in graph.nodes:
        graph.add_node(
            UnifiedNode(
                id=root,
                entity_type=EntityType.DIRECTORY,
                label="Project root",
                attributes={"repository_scope": scope, "path": ".", "is_repo_root": True},
                dimensions=NodeDimensions(surface="code"),
            )
        )
    ids: dict[str, str] = {}
    files: dict[str, list[str]] = defaultdict(list)
    index = connector_index(graph)
    for row in dbt["nodes"][:2000]:
        if not isinstance(row, dict) or not isinstance(row.get("kind"), str) or row["kind"] not in {"model", "source", "seed", "exposure"}:
            continue
        key, name = row.get("key"), row.get("name")
        if not isinstance(key, str) or not key or len(key) > 512 or not isinstance(name, str) or not name or len(name) > 256:
            continue
        node_id = repository_id(scope, "dbt", key)
        ids[key] = node_id
        path = relative_path(row.get("path"))
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CODE_MODULE,
                label=name,
                first_seen=now.isoformat(),
                last_seen=now.isoformat(),
                attributes={
                    "subtype": f"dbt_{row['kind']}",
                    "dbt_unique_id": key,
                    "repository_scope": scope,
                    "path": path,
                    "evidence_tier": "static_scan",
                    "artifact": dbt.get("artifact"),
                    "artifact_digest": dbt.get("digest"),
                    "generated_at": dbt.get("generated_at"),
                    "freshness": dbt.get("freshness"),
                    "collection_status": dbt.get("status"),
                },
                data_sources=[_SOURCE],
                dimensions=NodeDimensions(surface="code"),
            )
        )
        _edge(graph, root, node_id, RelationshipType.CONTAINS)
        if path:
            files[path].append(node_id)
        _join_connector(graph, node_id, row, dbt, index)
    raw_edges = dbt.get("edges")
    for edge in raw_edges[:10_000] if isinstance(raw_edges, list) else []:
        if isinstance(edge, dict) and isinstance(edge.get("source"), str) and isinstance(edge.get("target"), str):
            source, target = ids.get(edge["source"]), ids.get(edge["target"])
            if source and target:
                _edge(graph, source, target, RelationshipType.DEPENDS_ON, basis="manifest_depends_on")
    _finding_links(graph, inventory, files)


def _join_connector(graph: UnifiedGraph, node_id: str, row: dict[str, Any], dbt: dict[str, Any], index: dict) -> None:
    node = graph.nodes[node_id]
    account, parts = dbt.get("snowflake_account"), qualified_parts(row.get("relation_name"))
    status = "identity_unavailable"
    if dbt.get("freshness") != "current":
        status = "manifest_not_current"
    elif graph.tenant_id and dbt.get("adapter") == "snowflake" and isinstance(account, str) and account and parts:
        candidates = index.get((account, parts), [])
        status = "matched" if len(candidates) == 1 else "ambiguous" if candidates else "unmatched"
        if len(candidates) == 1:
            _edge(
                graph,
                node_id,
                candidates[0],
                RelationshipType.CORRELATES_WITH,
                basis="tenant_account_identifier_tuple",
                tenant_id=graph.tenant_id,
                account_id=account,
                identifier_parts=list(parts),
            )
    node.attributes["connector_match_status"] = status


def _finding_links(graph: UnifiedGraph, inventory: dict[str, Any], files: dict[str, list[str]]) -> None:
    for finding in graph.nodes.values():
        if finding.entity_type != EntityType.MISCONFIGURATION or finding.attributes.get("category") != "dbt":
            continue
        path = scoped_file_path(finding.attributes.get("file_path"), inventory)
        candidates = files.get(path or "", [])
        if len(candidates) == 1:
            _edge(graph, finding.id, candidates[0], RelationshipType.BELONGS_TO, basis="unique_manifest_source_file", source_file=path)
        elif candidates:
            finding.attributes["dbt_link_status"] = "ambiguous_source_file"
