"""Ast tool projection."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.canonical_ids import canonical_graph_node_id
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode, stable_node_id
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.security import sanitize_sensitive_payload, sanitize_text


def _apply_ast_tool_overlay(graph: UnifiedGraph, report_json: Mapping[str, Any]) -> None:
    """Materialise source-defined tool and application entrypoints."""
    inventory = report_json.get("ai_inventory")
    if not isinstance(inventory, Mapping):
        return
    analysis = inventory.get("ast_analysis")
    if not isinstance(analysis, Mapping):
        return
    raw_tools = analysis.get("tools")
    raw_entrypoints = analysis.get("application_entrypoints")
    if not isinstance(raw_tools, list):
        raw_tools = []
    if not isinstance(raw_entrypoints, list):
        raw_entrypoints = []
    _project_ast_tools(graph, raw_tools)
    _project_ast_entrypoints(graph, raw_entrypoints)


def _project_ast_tools(graph: UnifiedGraph, raw_tools: list[Any]) -> None:
    for raw in raw_tools:
        if not isinstance(raw, Mapping):
            continue
        tool_name = sanitize_text(raw.get("name", ""), max_len=200).strip()
        source_file = sanitize_text(raw.get("file", ""), max_len=500).strip().replace("\\", "/")
        while source_file.startswith("./"):
            source_file = source_file[2:]
        if not tool_name or not source_file:
            continue

        file_id = f"{EntityType.SOURCE_FILE.value}:{source_file}"
        if file_id not in graph.nodes:
            graph.add_node(
                UnifiedNode(
                    id=file_id,
                    entity_type=EntityType.SOURCE_FILE,
                    label=source_file.rsplit("/", 1)[-1],
                    attributes={
                        "path": source_file,
                        "evidence_tier": "static_scan",
                        "canonical_id": canonical_graph_node_id(EntityType.SOURCE_FILE.value, file_id),
                    },
                    data_sources=["ast_analysis"],
                    dimensions=NodeDimensions(surface="code"),
                )
            )

        tool_id = f"tool:source:{stable_node_id(source_file, tool_name)}"
        graph.add_node(
            UnifiedNode(
                id=tool_id,
                entity_type=EntityType.TOOL,
                label=tool_name,
                attributes={
                    "description": sanitize_text(raw.get("description", ""), max_len=1_000),
                    "source_file": source_file,
                    "line": raw.get("line") if isinstance(raw.get("line"), int) else None,
                    "parameters": sanitize_sensitive_payload(raw.get("parameters", [])),
                    "handler": sanitize_text(raw.get("handler", ""), max_len=200),
                    "registration_kind": sanitize_text(raw.get("registration_kind", ""), max_len=100),
                    "framework": sanitize_text(raw.get("framework", ""), max_len=100),
                    "provenance": sanitize_text(raw.get("provenance", ""), max_len=500),
                    "discovery_source": "ast_analysis",
                    "canonical_id": canonical_graph_node_id(EntityType.TOOL.value, tool_id),
                },
                data_sources=["ast_analysis"],
                dimensions=NodeDimensions(surface="code"),
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=file_id,
                target=tool_id,
                relationship=RelationshipType.DEFINES,
                evidence={
                    "source": "ast_analysis",
                    "line": raw.get("line"),
                    "registration_kind": sanitize_text(raw.get("registration_kind", ""), max_len=100),
                    "framework": sanitize_text(raw.get("framework", ""), max_len=100),
                    "provenance": sanitize_text(raw.get("provenance", ""), max_len=500),
                },
            )
        )


def _project_ast_entrypoints(graph: UnifiedGraph, raw_entrypoints: list[Any]) -> None:
    for raw in raw_entrypoints:
        if not isinstance(raw, Mapping):
            continue
        entry_name = sanitize_text(raw.get("name", ""), max_len=200).strip()
        handler = sanitize_text(raw.get("handler", ""), max_len=200).strip()
        source_file = sanitize_text(raw.get("file", ""), max_len=500).strip().replace("\\", "/")
        while source_file.startswith("./"):
            source_file = source_file[2:]
        if not entry_name or not handler or not source_file:
            continue

        file_id = f"{EntityType.SOURCE_FILE.value}:{source_file}"
        if file_id not in graph.nodes:
            graph.add_node(
                UnifiedNode(
                    id=file_id,
                    entity_type=EntityType.SOURCE_FILE,
                    label=source_file.rsplit("/", 1)[-1],
                    attributes={
                        "path": source_file,
                        "evidence_tier": "static_scan",
                        "canonical_id": canonical_graph_node_id(EntityType.SOURCE_FILE.value, file_id),
                    },
                    data_sources=["ast_analysis"],
                    dimensions=NodeDimensions(surface="code"),
                )
            )

        entry_id = f"application_entrypoint:source:{stable_node_id(source_file, entry_name, handler)}"
        graph.add_node(
            UnifiedNode(
                id=entry_id,
                entity_type=EntityType.CODE_MODULE,
                label=entry_name,
                attributes={
                    "node_kind": "application_entrypoint",
                    "handler": handler,
                    "entrypoint_kind": sanitize_text(raw.get("kind", ""), max_len=100),
                    "framework": sanitize_text(raw.get("framework", ""), max_len=100),
                    "language": sanitize_text(raw.get("language", ""), max_len=100),
                    "provenance": sanitize_text(raw.get("provenance", ""), max_len=500),
                    "source_file": source_file,
                    "line": raw.get("line") if isinstance(raw.get("line"), int) else None,
                    "discovery_source": "ast_analysis",
                    "canonical_id": canonical_graph_node_id(EntityType.CODE_MODULE.value, entry_id),
                },
                data_sources=["ast_analysis"],
                dimensions=NodeDimensions(surface="code"),
            )
        )
        graph.add_edge(
            UnifiedEdge(
                source=file_id,
                target=entry_id,
                relationship=RelationshipType.DEFINES,
                evidence={
                    "source": "ast_analysis",
                    "line": raw.get("line"),
                    "provenance": sanitize_text(raw.get("provenance", ""), max_len=500),
                },
            )
        )
