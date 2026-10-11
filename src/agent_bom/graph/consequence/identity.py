"""Exact, expiring session transitions. Connectivity never transfers authority."""

from __future__ import annotations

from datetime import datetime

from pydantic import ValidationError

from agent_bom.graph.compromise import _instant
from agent_bom.graph.consequence.contracts import SessionBinding
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.types import EntityType, RelationshipType

PRINCIPALS = frozenset(
    {
        EntityType.USER,
        EntityType.ROLE,
        EntityType.GROUP,
        EntityType.SERVICE_ACCOUNT,
        EntityType.SERVICE_PRINCIPAL,
        EntityType.FEDERATED_IDENTITY,
        EntityType.MANAGED_IDENTITY,
    }
)
TRANSITIONS = frozenset({RelationshipType.AUTHENTICATES_AS, RelationshipType.ASSUMES, RelationshipType.DELEGATED_TO})


def session_transition(graph: UnifiedGraph, edge: UnifiedEdge, at: datetime, max_age: int) -> tuple[SessionBinding | None, str | None]:
    try:
        binding = SessionBinding.model_validate(edge.evidence.get("session_binding"))
    except ValidationError:
        return None, "identity_session_not_recorded"
    target = graph.nodes.get(edge.target)
    if (
        binding.tenant_id != graph.tenant_id
        or binding.scan_id != graph.scan_id
        or binding.source_node_id != edge.source
        or binding.identity_node_id != edge.target
        or target is None
        or target.entity_type not in PRINCIPALS | {EntityType.AGENT}
        or target.attributes.get("principal_id") != binding.principal_id
        or target.attributes.get("cloud_provider") != binding.provider
    ):
        return None, "identity_scope_mismatch"
    if binding.state != "active":
        return None, f"session_{binding.state}"
    expires, observed = _instant(binding.expires_at), _instant(binding.observed_at)
    if expires is None or expires <= at:
        return None, "session_expired"
    if observed is None or not 0 <= (at - observed).total_seconds() <= max_age:
        return None, "identity_evidence_stale"
    start, end = _instant(edge.valid_from), _instant(edge.valid_to)
    if (
        not edge.traversable
        or edge.direction != "directed"
        or start is None
        or start > at
        or (edge.valid_to is not None and (end is None or end <= at))
        or edge.evidence.get("required_context")
        or edge.evidence.get("blocked") is True
    ):
        return None, "identity_transition_unresolved"
    if any("*" in item.action or "*" in item.resource for item in binding.scope):
        return None, "identity_scope_not_exact"
    return binding, None
