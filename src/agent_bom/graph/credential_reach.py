"""Bounded credential exposure within an agent's own configured/tool-call chain."""

from collections import deque
from collections.abc import Iterable

from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType, RelationshipType

MAX_EDGES = 100_000
MAX_AGENT_EDGES = 5_000
MAX_RESULTS = 10_000
MAX_DEPTH = 6
CREDENTIAL_TYPES = {EntityType.CREDENTIAL, EntityType.CREDENTIAL_REF}
_CHAIN = {
    RelationshipType.USES,
    RelationshipType.PROVIDES_TOOL,
    RelationshipType.REACHES_TOOL,
    RelationshipType.EXPOSES_CRED,
    RelationshipType.INVOKED,
    RelationshipType.CALLED,
    RelationshipType.USED_CREDENTIAL,
}
Route = tuple[list[str], list[str]]


def credential_routes(
    graph: UnifiedGraph,
    owners: Iterable[str],
    *,
    analyzer: str,
) -> dict[str, dict[str, Route]]:
    """Index edges once, stop at credentials, and never cross into another agent.

    Sharing, correlation and delegation describe context, not possession of a
    peer's credentials. Limits apply across the whole call as well as per agent;
    exhaustion remains visible in the graph's serialized analysis status.
    """
    outgoing: dict[str, list] = {}
    for edge in graph.edges:
        target = graph.nodes.get(edge.target)
        if edge.traversable and edge.relationship in _CHAIN and target is not None and target.entity_type != EntityType.AGENT:
            outgoing.setdefault(edge.source, []).append(edge)
    routes: dict[str, dict[str, Route]] = {}
    examined = results = 0
    reasons: set[str] = set()
    for owner in owners:
        if examined >= MAX_EDGES or results >= MAX_RESULTS:
            reasons.add("global_budget")
            break
        agent = graph.nodes.get(owner)
        if agent is None or agent.entity_type != EntityType.AGENT:
            continue
        reached: dict[str, Route] = {owner: ([owner], [])}
        credentials: dict[str, Route] = {}
        queue = deque([owner])
        local_edges = 0
        while queue:
            current = queue.popleft()
            hops, rels = reached[current]
            if len(rels) >= MAX_DEPTH:
                if outgoing.get(current):
                    reasons.add("depth_budget")
                continue
            for edge in outgoing.get(current, []):
                if examined >= MAX_EDGES or local_edges >= MAX_AGENT_EDGES or results >= MAX_RESULTS:
                    reasons.add("global_budget" if examined >= MAX_EDGES or results >= MAX_RESULTS else "agent_budget")
                    queue.clear()
                    break
                examined += 1
                local_edges += 1
                if edge.target in reached:
                    continue
                route = (hops + [edge.target], rels + [edge.relationship.value])
                reached[edge.target] = route
                if graph.nodes[edge.target].entity_type in CREDENTIAL_TYPES:
                    credentials[edge.target] = route
                    results += 1
                else:
                    queue.append(edge.target)
        routes[owner] = credentials
    graph.analysis_status[analyzer] = GraphAnalysisStatus(
        status=GraphAnalysisState.LIMITED if reasons else GraphAnalysisState.COMPLETE,
        reason_codes=tuple(sorted(reasons)),
        limits={"edges": MAX_EDGES, "agent_edges": MAX_AGENT_EDGES, "results": MAX_RESULTS, "depth": MAX_DEPTH},
        observed={"edges": examined, "results": results, "agents": len(routes)},
    )
    return routes
