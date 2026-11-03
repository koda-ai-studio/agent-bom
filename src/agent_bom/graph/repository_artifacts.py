"""Shared scoped source artifacts for static repository overlays."""

from __future__ import annotations

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.repository_identity import scoped_node_id
from agent_bom.graph.types import EntityType, RelationshipType


def static_edge(graph: UnifiedGraph, source: str, target: str, relationship: RelationshipType, origin: str, **evidence) -> None:
    graph.add_edge(
        UnifiedEdge(
            source=source,
            target=target,
            relationship=relationship,
            traversable=False,
            evidence={"source": origin, "tier": "static_scan", **evidence},
        )
    )


def source_artifact(graph: UnifiedGraph, scope: str, path: str, digest: str, origin: str) -> str:
    root = scoped_node_id("directory", ".", scope)
    if root not in graph.nodes:
        graph.add_node(
            UnifiedNode(
                id=root,
                entity_type=EntityType.DIRECTORY,
                label="Project root",
                attributes={"repository_scope": scope, "path": ".", "is_repo_root": True},
                dimensions=NodeDimensions(surface="code"),
            )
        )
    kind = EntityType.SOURCE_FILE if path.endswith(".py") else EntityType.CONFIG_FILE
    node_id = scoped_node_id(kind.value, path, scope)
    attributes = {"repository_scope": scope, "path": path, "evidence_tier": "static_scan"}
    if digest:
        attributes["artifact_digest"] = digest
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=kind,
            label=path.rsplit("/", 1)[-1],
            attributes=attributes,
            data_sources=[origin],
            dimensions=NodeDimensions(surface="code"),
        )
    )
    directory = root
    if "/" in path:
        parent = path.rsplit("/", 1)[0]
        directory = scoped_node_id("directory", parent, scope)
        if directory not in graph.nodes:
            graph.add_node(
                UnifiedNode(
                    id=directory,
                    entity_type=EntityType.DIRECTORY,
                    label=parent,
                    attributes={"repository_scope": scope, "path": parent},
                    dimensions=NodeDimensions(surface="code"),
                )
            )
            static_edge(graph, root, directory, RelationshipType.CONTAINS, origin)
    static_edge(graph, directory, node_id, RelationshipType.CONTAINS, origin, artifact=path)
    return node_id
