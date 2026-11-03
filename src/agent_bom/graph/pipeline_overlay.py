"""Project local pipeline declarations, distinct from runtime or permission evidence."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agent_bom.core.repository_identity import relative_path, repository_id
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.repository_artifacts import source_artifact, static_edge
from agent_bom.graph.repository_identity import repository_scope
from agent_bom.graph.types import EntityType, RelationshipType

_SOURCE = "repository-pipeline"


def apply_pipeline_overlay(graph: UnifiedGraph, report: dict[str, Any], now: datetime) -> None:
    inventory = report.get("project_inventory")
    scope = repository_scope(inventory)
    if not scope or not isinstance(inventory, dict):
        return
    context = inventory["repository_context"].get("pipelines")
    if not isinstance(context, dict) or not isinstance(context.get("nodes"), list):
        return
    ids: dict[str, str] = {}
    parents: list[tuple[str, str]] = []
    for row in context["nodes"][:2000]:
        if not isinstance(row, dict):
            continue
        key, name, kind, path = row.get("key"), row.get("name"), row.get("kind"), relative_path(row.get("path"))
        if not isinstance(key, str) or not key or len(key) > 1024 or not isinstance(name, str) or not name or len(name) > 256:
            continue
        if not isinstance(kind, str) or kind not in {"gitlab_job", "airflow_dag", "airflow_task"} or not path:
            continue
        node_id = repository_id(scope, "pipeline", key)
        ids[key] = node_id
        attributes = {
            "subtype": kind,
            "repository_scope": scope,
            "path": path,
            "evidence_tier": "static_scan",
            "collection_status": context.get("status"),
            "artifact_digest": row.get("digest"),
        }
        for field in ("line", "deployment_target", "secret_references", "connection_references"):
            if field in row:
                attributes[field] = row[field]
        graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.CI_JOB,
                label=name,
                attributes=attributes,
                first_seen=now.isoformat(),
                last_seen=now.isoformat(),
                data_sources=[_SOURCE],
                dimensions=NodeDimensions(surface="ci"),
            )
        )
        file = source_artifact(graph, scope, path, str(row.get("digest") or ""), _SOURCE)
        relationship = RelationshipType.DEFINES if path.endswith(".py") else RelationshipType.CONFIGURES
        static_edge(graph, file, node_id, relationship, _SOURCE, artifact=path, line=row.get("line"))
        if isinstance(row.get("parent"), str):
            parents.append((row["parent"], key))
    for parent, child in parents:
        if parent in ids and child in ids:
            static_edge(graph, ids[parent], ids[child], RelationshipType.CONTAINS, _SOURCE, basis="declared_dag_scope")
    raw = context.get("edges", [])
    for edge in raw[:10_000] if isinstance(raw, list) else []:
        if not isinstance(edge, dict) or not isinstance(edge.get("source"), str) or not isinstance(edge.get("target"), str):
            continue
        if edge["source"] in ids and edge["target"] in ids:
            static_edge(
                graph,
                ids[edge["source"]],
                ids[edge["target"]],
                RelationshipType.DEPENDS_ON,
                _SOURCE,
                artifact=edge.get("path"),
                line=edge.get("line"),
                basis=edge.get("basis"),
            )
