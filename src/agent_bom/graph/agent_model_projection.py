"""Agent → model ``serves_model`` edges carrying where each model is declared.

A framework agent's ``model_uses`` name the model, its provider, and whether
it is set in code, in config, or selected by an environment variable. An
environment-selected model with no literal default becomes an ``env:<NAME>``
model node: the variable's name, never its value.
"""

from __future__ import annotations

from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.training_projection import _model_node_id
from agent_bom.graph.types import EntityType, RelationshipType

_DECLARATION_KEYS = ("model", "provider", "declared_in", "file_path", "line_number", "via", "env_var")


def project_agent_models(graph: UnifiedGraph, agent_id: str, item: dict[str, Any], data_source: str) -> None:
    """Link an agent to each model it uses; payloads without ``model_uses`` link their ``model_refs``."""
    declarations: dict[str, list[dict[str, Any]]] = {}
    for use in item.get("model_uses") or []:
        if not isinstance(use, dict):
            continue
        target = _ensure_model_node(graph, use, data_source)
        if target:
            declarations.setdefault(target, []).append({key: use.get(key, "") for key in _DECLARATION_KEYS})
    for raw_ref in item.get("model_refs") or []:
        ref = str(raw_ref or "").strip()
        if ref and _model_node_id(ref) not in declarations:
            declarations[_ensure_model_node(graph, {"model": ref}, data_source)] = []
    for target, uses in declarations.items():
        evidence = _edge_evidence(graph, target, uses)
        graph.add_edge(UnifiedEdge(source=agent_id, target=target, relationship=RelationshipType.SERVES_MODEL, evidence=evidence))


def _ensure_model_node(graph: UnifiedGraph, use: dict[str, Any], data_source: str) -> str:
    model = str(use.get("model") or "").strip()
    env_var = str(use.get("env_var") or "").strip()
    if not model and not env_var:
        return ""
    label = model or f"env:{env_var}"
    attributes: dict[str, Any] = {"model_ref": label, "source": "framework-agent"}
    provider = str(use.get("provider") or "").strip()
    if provider:
        attributes["provider"] = provider
    if not model:
        attributes["selected_by_env"] = env_var
    node_id = _model_node_id(label)
    graph.add_node(
        UnifiedNode(
            id=node_id,
            entity_type=EntityType.MODEL,
            label=label,
            attributes=attributes,
            dimensions=NodeDimensions(surface="model"),
            data_sources=[data_source, "source-ast"],
        )
    )
    return node_id


def _edge_evidence(graph: UnifiedGraph, target: str, uses: list[dict[str, Any]]) -> dict[str, Any]:
    evidence: dict[str, Any] = {"source": "source-ast", "model_ref": graph.nodes[target].label}
    if not uses:
        return evidence
    first = uses[0]
    evidence.update({key: first[key] for key in _DECLARATION_KEYS[1:] if first.get(key) not in ("", None)})
    if len(uses) > 1:
        evidence["declarations"] = uses
    return evidence
