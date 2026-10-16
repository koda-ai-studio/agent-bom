"""Model, dataset and serving evidence projected from their own report sections."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from agent_bom.canonical_ids import canonical_id
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.edge_evidence import edge_evidence
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType, RelationshipType


def project_model_provenance(graph: UnifiedGraph, model_provenance: list[dict[str, Any]]) -> None:
    for model_dict in model_provenance:
        model_name = model_dict.get("model_name", model_dict.get("name", "unknown"))
        model_id = _model_node_id(model_name)
        graph.add_node(
            UnifiedNode(
                id=model_id,
                entity_type=EntityType.MODEL,
                label=model_name,
                attributes={
                    "framework": model_dict.get("framework", ""),
                    "source": model_dict.get("source", ""),
                    "hash": model_dict.get("hash", ""),
                    "verified": model_dict.get("verified", False),
                },
                data_sources=["model-provenance"],
            )
        )


def project_serving_configs(graph: UnifiedGraph, serving_configs: list[dict[str, Any]]) -> None:
    for serving_dict in serving_configs:
        container_image = serving_dict.get("container_image", "")
        if not container_image:
            continue
        # This is a configuration observation, not a running container identity.
        container_id = f"container:serving-config:{canonical_id(serving_dict)}"
        graph.add_node(
            UnifiedNode(
                id=container_id,
                entity_type=EntityType.CONTAINER,
                label=serving_dict.get("name") or container_image,
                attributes={
                    "container_image": container_image,
                    "inventory_role": "serving_configuration",
                    "runtime_identity_proven": False,
                    "identity": {"basis": "source_observation", "aliases": [f"container:{container_image}"]},
                    "framework": serving_dict.get("framework", ""),
                    "source_file": serving_dict.get("source_file", ""),
                    "model_uri": serving_dict.get("model_uri", ""),
                    "endpoint_url": serving_dict.get("endpoint_url", ""),
                    "security_flags": serving_dict.get("security_flags", []),
                },
                dimensions=NodeDimensions(surface="container"),
                data_sources=["training-pipeline"],
            )
        )
        model_id = _resolve_model_id(graph, serving_dict.get("model_uri", ""))
        if model_id:
            graph.add_edge(
                UnifiedEdge(
                    source=container_id,
                    target=model_id,
                    relationship=RelationshipType.SERVES_MODEL,
                    evidence=edge_evidence("serving-config", "static_scan"),
                )
            )


def project_dataset_cards(graph: UnifiedGraph, dataset_cards: dict[str, Any] | None) -> None:
    if isinstance(dataset_cards, dict):
        for dataset_dict in dataset_cards.get("datasets", []):
            dataset_name = dataset_dict.get("name") or dataset_dict.get("source_file") or "unknown-dataset"
            graph.add_node(
                UnifiedNode(
                    id=f"dataset:card:{canonical_id(dataset_dict)}",
                    entity_type=EntityType.DATASET,
                    label=dataset_name,
                    attributes={
                        "identity": {"basis": "source_observation", "aliases": [f"dataset:{dataset_name}"]},
                        "description": dataset_dict.get("description", ""),
                        "license": dataset_dict.get("license", ""),
                        "source_url": dataset_dict.get("source_url", ""),
                        "version": dataset_dict.get("version", ""),
                        "features": dataset_dict.get("features", []),
                        "splits": dataset_dict.get("splits", {}),
                        "size_bytes": dataset_dict.get("size_bytes", 0),
                        "source_file": dataset_dict.get("source_file", ""),
                        "languages": dataset_dict.get("languages", []),
                        "task_categories": dataset_dict.get("task_categories", []),
                        "security_flags": dataset_dict.get("security_flags", []),
                    },
                    compliance_tags=_flatten_compliance_tags(dataset_dict.get("compliance_tags")),
                    data_sources=["dataset-cards"],
                )
            )


def _flatten_compliance_tags(raw: Any) -> list[str]:
    """Normalize arbitrary compliance-tag payloads into a simple list."""
    if not raw:
        return []
    if isinstance(raw, list):
        return sorted({str(tag) for tag in raw if tag})
    if isinstance(raw, dict):
        tags: set[str] = set()
        for value in raw.values():
            if isinstance(value, list):
                tags.update(str(tag) for tag in value if tag)
            elif value:
                tags.add(str(value))
        return sorted(tags)
    return [str(raw)]


def _normalize_model_ref(ref: str) -> str:
    """Preserve provider, path and case: a label is not a cross-provider identity."""
    return str(ref or "").strip()


def _model_node_id(ref: str) -> str:
    """Shared model-reference node spelling, without inferred provider aliases."""
    return f"model:{quote(_normalize_model_ref(ref), safe='')}"


def _resolve_model_id(graph: UnifiedGraph, model_uri: str) -> str:
    """Only bind an exact recorded model reference; URI suffixes are ambiguous."""
    if not model_uri:
        return ""
    candidate = _model_node_id(model_uri)
    return candidate if graph.has_node(candidate) else ""
