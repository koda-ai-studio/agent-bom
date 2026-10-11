"""Bounded path-state traversal over the existing graph, with explicit frontiers."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime

from agent_bom.graph.consequence.boundaries import recorded_boundaries
from agent_bom.graph.consequence.contracts import Consequence, ConsequenceRequest, Frontier
from agent_bom.graph.consequence.eligibility import actions_for_path
from agent_bom.graph.consequence.identity import TRANSITIONS, session_transition
from agent_bom.graph.consequence.traversal_types import PathState
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.types import RelationshipType

PERMISSIONS = frozenset({RelationshipType.CAN_ACCESS, RelationshipType.HAS_PERMISSION})


@dataclass
class Walk:
    consequences: list[Consequence] = field(default_factory=list)
    frontier: list[Frontier] = field(default_factory=list)
    states_examined: int = 0
    truncated: bool = False
    reasons: set[str] = field(default_factory=set)


def boundary(state: PathState, reason: str, edge: UnifiedEdge | None = None) -> Frontier:
    blocked = reason in {"session_revoked", "session_expired", "session_pending"}
    return Frontier(
        node_ids=[*state.nodes, *([edge.target] if edge else [])],
        edge_ids=[*state.edges, *([edge.id] if edge else [])],
        status="blocked" if blocked else "unknown",
        reason_codes=[reason],
        next_collection_step=(
            "Collect an exact identity/session binding, expiry, action/resource scope and provider authorization receipts."
            if "identity" in reason or "session" in reason
            else "Collect missing source evidence for this scope, then reassess a new pinned snapshot."
        ),
    )


def _follow(
    graph: UnifiedGraph, edge: UnifiedEdge, state: PathState, request: ConsequenceRequest, at: datetime, walk: Walk, queue: deque[PathState]
) -> None:
    if edge.relationship in PERMISSIONS:
        items, limited = actions_for_path(graph, edge, request, at, state.nodes, state.edges, state.sessions, graph.completeness.truncated)
        available = request.max_results - len(walk.consequences) - len(walk.frontier)
        walk.consequences.extend(items[:available])
        if limited or len(items) > available:
            walk.truncated = True
            walk.reasons.add("receipt_or_result_limit")
        return
    if edge.relationship not in TRANSITIONS:
        walk.frontier.append(boundary(state, "relationship_does_not_transfer_authority", edge))
        return
    binding, reason = session_transition(graph, edge, at, request.max_evidence_age_seconds)
    if reason or binding is None:
        walk.frontier.append(boundary(state, reason or "identity_session_not_recorded", edge))
        return
    # Repeating an edge cannot add authority: scopes only intersect. Preserve
    # alternate paths/sessions, but terminate cycles within each witness path.
    if edge.id in state.edges:
        walk.frontier.append(boundary(state, "cycle_boundary", edge))
        return
    queue.append(PathState((*state.nodes, edge.target), (*state.edges, edge.id), (*state.sessions, binding)))


def traverse(graph: UnifiedGraph, root: str, request: ConsequenceRequest, at: datetime, *, deadline: float) -> Walk:
    outgoing: dict[str, list[UnifiedEdge]] = defaultdict(list)
    walk = Walk(truncated=graph.completeness.truncated)
    for edge in graph.edges:
        if time.monotonic() >= deadline:
            walk.truncated = True
            walk.reasons.add("deadline")
            break
        outgoing[edge.source].append(edge)
    queue = deque([PathState((root,))])
    while queue:
        if (
            time.monotonic() >= deadline
            or walk.states_examined >= request.max_states
            or len(walk.consequences) + len(walk.frontier) >= request.max_results
        ):
            walk.truncated = True
            walk.reasons.add("traversal_budget")
            break
        state = queue.popleft()
        walk.states_examined += 1
        recorded, limited = recorded_boundaries(graph, state, request, at)
        available = request.max_results - len(walk.consequences) - len(walk.frontier)
        walk.consequences.extend(recorded[:available])
        if limited or len(recorded) > available:
            walk.truncated = True
            walk.reasons.add("authorization_boundary_limit")
        edges = sorted(outgoing.get(state.nodes[-1], []), key=lambda edge: edge.id)
        if not edges and not recorded:
            walk.frontier.append(boundary(state, "outgoing_evidence_not_recorded"))
        elif len(state.edges) >= request.max_depth:
            walk.truncated = True
            walk.reasons.add("depth_limit")
            walk.frontier.append(boundary(state, "depth_limit"))
        else:
            _expand(graph, edges, state, request, at, deadline, walk, queue)
    if graph.completeness.truncated:
        walk.reasons.add("partial_graph_evidence")
    if walk.truncated:
        walk.consequences = [
            item.model_copy(update={"status": "unknown", "reason_codes": [*item.reason_codes, "incomplete_assessment"]})
            if item.status == "supported"
            else item
            for item in walk.consequences
        ]
    return walk


def _expand(
    graph: UnifiedGraph,
    edges: list[UnifiedEdge],
    state: PathState,
    request: ConsequenceRequest,
    at: datetime,
    deadline: float,
    walk: Walk,
    queue: deque[PathState],
) -> None:
    for edge in edges:
        if (
            len(walk.consequences) + len(walk.frontier) >= request.max_results
            or len(queue) + walk.states_examined >= request.max_states
            or time.monotonic() >= deadline
        ):
            walk.truncated = True
            walk.reasons.add("traversal_budget")
            return
        _follow(graph, edge, state, request, at, walk, queue)
