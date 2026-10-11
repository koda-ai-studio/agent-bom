"""Read collected negative decisions; never synthesize permission edges."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field, ValidationError

from agent_bom.graph.compromise import CompromiseAction, _instant
from agent_bom.graph.consequence.contracts import Consequence, ConsequenceRequest, Status
from agent_bom.graph.consequence.projection import project_action
from agent_bom.graph.consequence.traversal_types import PathState
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.hop_evidence import AuthorizationReceipt, EvidenceId


class BoundaryReceipt(AuthorizationReceipt):
    target_node_id: EvidenceId
    principal_node_id: EvidenceId
    deny_binding_ids: list[EvidenceId] = Field(default_factory=list, max_length=128)
    reason_codes: list[str] = Field(default_factory=list, max_length=16)
    evidence_ref: EvidenceId


def recorded_boundaries(graph: UnifiedGraph, state: PathState, request: ConsequenceRequest, at: datetime) -> tuple[list[Consequence], bool]:
    node = graph.nodes[state.nodes[-1]]
    rows = node.attributes.get("authorization_boundaries", [])
    if not isinstance(rows, list):
        return [], True
    limited = node.attributes.get("authorization_boundaries_truncated") is True or len(rows) > 128
    result: list[Consequence] = []
    for row in rows[:128]:
        try:
            receipt = BoundaryReceipt.model_validate(row)
        except ValidationError:
            limited = True
            continue
        reasons = list(receipt.reason_codes)
        observed = _instant(receipt.observed_at)
        scoped = receipt.principal_node_id == node.id and node.attributes.get("cloud_provider") == receipt.provider
        fresh = observed is not None and 0 <= (at - observed).total_seconds() <= request.max_evidence_age_seconds
        status: Status = "unknown"
        if not scoped:
            reasons.append("principal_scope_unverified")
        if not fresh:
            reasons.append("observation_time_unverified")
        if scoped and fresh and receipt.decision in {"explicit_deny", "implicit_deny"}:
            status = "blocked"
            reasons.append("recorded_denial")
        action = CompromiseAction(
            source_node_id=node.id,
            target_node_id=receipt.target_node_id,
            source_edge_id="",
            source_snapshot_id=graph.scan_id,
            relationship="",
            provider=receipt.provider,
            principal_id=receipt.principal_id,
            action=receipt.action,
            resource=receipt.resource,
            binding_ids=receipt.binding_ids,
            observed_at=receipt.observed_at,
        )
        item = project_action(
            action,
            node_ids=[*state.nodes, receipt.target_node_id],
            edge_ids=list(state.edges),
            session_ids=[s.session_id for s in state.sessions],
            evidence_refs=[*[s.evidence_ref for s in state.sessions], receipt.evidence_ref],
            status=status,
            reasons=reasons,
        )
        result.append(item.model_copy(update={"deny_binding_ids": receipt.deny_binding_ids}))
    return result, limited
