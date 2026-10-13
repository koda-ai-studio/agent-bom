"""Bounded credential exposure within an agent's own configured/tool-call chain."""

from collections import deque
from collections.abc import Iterable

from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.types import EntityType, RelationshipType

MAX_AGENT_EDGES = 5_000
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
    peer's credentials. Only edges that can still lead to a credential are
    indexed, so tool fan-out and other dead ends cost nothing and cannot
    truncate discovery. There is no cross-agent result cap: every owner is
    evaluated. The per-agent budget and depth bound remain visible in the
    graph's serialized analysis status.
    """
    owner_ids = list(dict.fromkeys(owners))
    outgoing = _credential_leading_edges(graph) if owner_ids else {}
    routes: dict[str, dict[str, Route]] = {}
    examined = results = 0
    reasons: set[str] = set()
    for owner in owner_ids:
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
                if local_edges >= MAX_AGENT_EDGES:
                    reasons.add("agent_budget")
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
        limits={"agent_edges": MAX_AGENT_EDGES, "depth": MAX_DEPTH},
        observed={"edges": examined, "results": results, "agents": len(routes)},
    )
    return routes


def _credential_leading_edges(graph: UnifiedGraph) -> dict[str, list[UnifiedEdge]]:
    """Chain edges whose target is a credential or can still reach one.

    Pruning is exact: a node with no chain path to a credential can never lie
    on a credential route, so skipping it changes cost, never results.
    """
    chain: list[UnifiedEdge] = []
    incoming: dict[str, list[str]] = {}
    for edge in graph.edges:
        target = graph.nodes.get(edge.target)
        if edge.traversable and edge.relationship in _CHAIN and target is not None and target.entity_type != EntityType.AGENT:
            chain.append(edge)
            incoming.setdefault(edge.target, []).append(edge.source)
    useful = {node_id for node_id in incoming if graph.nodes[node_id].entity_type in CREDENTIAL_TYPES}
    frontier = list(useful)
    while frontier:
        node_id = frontier.pop()
        for source in incoming.get(node_id, ()):
            if source not in useful:
                useful.add(source)
                frontier.append(source)
    outgoing: dict[str, list[UnifiedEdge]] = {}
    for edge in chain:
        if edge.target in useful:
            outgoing.setdefault(edge.source, []).append(edge)
    return outgoing
