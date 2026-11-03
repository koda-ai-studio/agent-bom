"""Scoped source-to-import and agent declaration artifacts, not runtime call edges."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agent_bom.core.repository_identity import relative_path, repository_id
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.repository_artifacts import source_artifact, static_edge
from agent_bom.graph.repository_identity import repository_scope
from agent_bom.graph.types import EntityType, RelationshipType

_SOURCE = "repository-python-static"


def _module(graph: UnifiedGraph, scope: str, path: str) -> str:
    file = source_artifact(graph, scope, path, "", _SOURCE)
    node_id = repository_id(scope, "source_module", path)
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=EntityType.CODE_MODULE,
            label=path,
            attributes={"repository_scope": scope, "path": path, "subtype": "python_module"},
            dimensions=NodeDimensions(surface="code"),
            data_sources=[_SOURCE],
        )
    )
    static_edge(graph, file, node_id, RelationshipType.DEFINES, _SOURCE, artifact=path)
    return node_id


def apply_sdk_overlay(graph: UnifiedGraph, report: dict[str, Any], now: datetime) -> None:
    inventory = report.get("project_inventory")
    scope = repository_scope(inventory)
    if not scope or not isinstance(inventory, dict):
        return
    context = inventory["repository_context"].get("code")
    if not isinstance(context, dict) or not isinstance(context.get("files"), list):
        return
    for row in context["files"][:250]:
        if not isinstance(row, dict) or not (path := relative_path(row.get("path"))):
            continue
        file = source_artifact(graph, scope, path, str(row.get("digest") or ""), _SOURCE)
        node = graph.nodes[file]
        node.attributes["static_calls"] = row.get("calls", [])[:100] if isinstance(row.get("calls"), list) else []
        node.attributes["collection_status"] = context.get("status")
        imports = row.get("imports", [])
        for item in imports[:64] if isinstance(imports, list) else []:
            if not isinstance(item, dict) or not isinstance(item.get("module"), str) or len(item["module"]) > 512:
                continue
            local = relative_path(item.get("target_path"))
            if local:
                target = _module(graph, scope, local)
            else:
                target = repository_id(scope, "external_import", item["module"])
                graph.add_node(
                    UnifiedNode(
                        id=target,
                        entity_type=EntityType.EXTERNAL_IMPORT,
                        label=item["module"],
                        attributes={"repository_scope": scope, "evidence_tier": "static_scan"},
                        data_sources=[_SOURCE],
                        dimensions=NodeDimensions(surface="code"),
                    )
                )
            static_edge(
                graph, file, target, RelationshipType.IMPORTS, _SOURCE, artifact=path, line=item.get("line"), alias=item.get("alias")
            )
        implementations = row.get("implementations", [])
        for item in implementations[:100] if isinstance(implementations, list) else []:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str) or len(item["name"]) > 256:
                continue
            declaration = repository_id(scope, "agent_implementation", f"{path}:{item['name']}:{item.get('line')}")
            graph.add_node(
                UnifiedNode(
                    id=declaration,
                    entity_type=EntityType.CODE_MODULE,
                    label=item["name"],
                    attributes={
                        "repository_scope": scope,
                        "path": path,
                        "line": item.get("line"),
                        "factory": item.get("symbol"),
                        "subtype": "agent_implementation",
                        "evidence_tier": "static_scan",
                        "runtime_status": "not_observed",
                    },
                    first_seen=now.isoformat(),
                    last_seen=now.isoformat(),
                    data_sources=[_SOURCE],
                    dimensions=NodeDimensions(surface="code"),
                )
            )
            static_edge(graph, file, declaration, RelationshipType.DEFINES, _SOURCE, artifact=path, line=item.get("line"))
