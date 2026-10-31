"""Recorded agent context; membership never establishes execution or model use."""

from __future__ import annotations

from itertools import chain
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType as E
from agent_bom.graph.types import RelationshipType as R

CONTEXT_ITEM_LIMIT = 16
_SCOPES = {E.ORG, E.ACCOUNT, E.ENVIRONMENT, E.FLEET, E.CLUSTER}
_EXECUTION_HOSTS = {E.CLOUD_RESOURCE, E.CONTAINER, E.CLUSTER}
_MEMBERSHIP = {R.CONTAINS, R.OWNS, R.PART_OF, R.BELONGS_TO, R.MEMBER_OF}


def _text(value: Any, maximum: int = 200) -> str:
    return value.strip()[:maximum] if isinstance(value, str) else ""


def _category(edge: UnifiedEdge, other: UnifiedNode, *, outgoing: bool) -> str | None:
    relation = edge.relationship
    if not outgoing and other.entity_type == E.PROVIDER and relation in {R.PLATFORM_FOR, R.HOSTS}:
        # Historical provider HOSTS rows are platform associations, not hosts.
        return "platforms"
    endpoint_host = (
        other.entity_type == E.FLEET
        and bool(_text(other.attributes.get("endpoint_id")))
        and edge.evidence.get("source") == "endpoint_inventory"
        and edge.evidence.get("identity_match_basis") == "exact_source_id"
    )
    if (other.entity_type in _EXECUTION_HOSTS or endpoint_host) and (
        (outgoing and relation == R.HOSTED_ON) or (not outgoing and relation == R.HOSTS)
    ):
        return "execution"
    if other.entity_type in _SCOPES and relation in _MEMBERSHIP:
        is_membership = outgoing if relation in {R.PART_OF, R.BELONGS_TO, R.MEMBER_OF} else not outgoing
        return "membership" if is_membership else None
    if outgoing and other.entity_type == E.MODEL and relation == R.SERVES_MODEL:
        return "models"
    return None


def _reference(edge: UnifiedEdge, node: UnifiedNode) -> dict[str, Any]:
    attrs = node.attributes
    raw_scope = attrs.get("scope")
    scope = raw_scope if isinstance(raw_scope, dict) else {}
    return {
        "node_id": node.id,
        "label": _text(node.label),
        "entity_type": node.entity_type.value,
        "relationship": edge.relationship.value,
        "evidence_kind": _text(edge.evidence.get("tier")) or "unknown",
        "source": _text(edge.evidence.get("source")) or "unknown",
        "provider": _text(attrs.get("cloud_provider")) or _text(node.dimensions.cloud_provider),
        "service": _text(attrs.get("cloud_service")) or _text(attrs.get("service")),
        "account_id": _text(attrs.get("account_id")) or _text(scope.get("account_id")),
        "region": _text(attrs.get("region")) or _text(scope.get("region")) or _text(attrs.get("location")),
        "last_seen": _text(edge.last_seen),
        "source_scan_id": _text(edge.source_scan_id),
    }


def agent_context(graph: UnifiedGraph, agent: UnifiedNode) -> dict[str, Any]:
    """Return bounded references to direct recorded relationships in this graph.

    A model link does not identify its publisher or endpoint unless that model's
    own evidence does. Provider association never supplies a missing host/model.
    """
    groups: dict[str, dict[str, Any]] = {
        name: {"status": "not_recorded", "items": [], "recorded_count": 0, "truncated": False}
        for name in ("platforms", "execution", "models", "membership")
    }
    edges = chain(((edge, True) for edge in graph.edges_from(agent.id)), ((edge, False) for edge in graph.edges_to(agent.id)))
    for edge, outgoing in edges:
        other = graph.nodes.get(edge.target if outgoing else edge.source)
        if other is None:
            continue
        category = _category(edge, other, outgoing=outgoing)
        if category is None:
            continue
        group = groups[category]
        group["status"] = "recorded"
        group["recorded_count"] += 1
        if len(group["items"]) < CONTEXT_ITEM_LIMIT:
            group["items"].append(_reference(edge, other))
        else:
            group["truncated"] = True
    return {
        "schema_version": "agent.context.v1",
        "agent_kind": _text(agent.attributes.get("agent_type"), 80) or "unknown",
        **groups,
    }


def annotate_agent_context(graph: UnifiedGraph) -> None:
    """Persist the same contextual facts for graph API, MCP and file consumers."""
    for agent in graph.iter_nodes_by_type(E.AGENT):
        context = agent_context(graph, agent)
        # Neighbour reads can evict a store-backed node; mutate its live row.
        graph.nodes[agent.id].attributes["agent_context"] = context
