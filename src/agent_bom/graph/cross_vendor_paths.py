"""Attack paths across vendors from the storage-integration correlator's recorded joins.

The correlator draws ``integration --ASSUMES--> role`` and
``integration --CAN_ACCESS--> bucket`` only on recorded identifiers. No other
path family walks those edges: component paths follow holder edges back to an
agent, user or service account; privilege escalation needs a principal-typed
source; fusion needs an internet entry and a classified data store. So the
chain was traversable but never served as an attack path.

A path is emitted only for a correlator ``CAN_ACCESS`` edge whose role is
joined by a correlator ``ASSUMES`` edge with all three keys matched (role ARN,
trust principal, external id). It starts at each Snowflake object that depends
on the integration (``DEPENDS_ON``, e.g. external table → stage → integration),
or at the integration itself when nothing does, and ends at the bucket. Every
hop is an edge in the graph; the role is named in the summary and on the
``CAN_ACCESS`` edge's evidence, not drawn as a hop it has no edge for.
"""

from __future__ import annotations

from collections.abc import Callable

from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.storage_integration_correlation import SOURCE as CORRELATOR
from agent_bom.graph.types import RelationshipType

_FULL_TRUST_BASIS = frozenset(
    {"storage_aws_role_arn_matches_role_arn", "role_trust_names_integration_user", "role_trust_names_external_id"}
)
_MAX_DEPENDENT_DEPTH = 4
_MAX_PATHS = 500
_BASE_RISK = 52.0
_DEPENDS_ON = RelationshipType.DEPENDS_ON.value


def _rel(edge: UnifiedEdge) -> str:
    return str(getattr(edge.relationship, "value", edge.relationship))


def _from_correlator(edge: UnifiedEdge) -> bool:
    return (edge.evidence or {}).get("source") == CORRELATOR


def _dependent_chains(graph: UnifiedGraph, integration_id: str, incoming: dict[str, list[UnifiedEdge]]) -> list[list[str]]:
    """Each maximal ``DEPENDS_ON`` chain ending at the integration, root first."""
    chains: list[list[str]] = []

    def walk(node_id: str, suffix: list[str]) -> None:
        upstream = [
            edge.source
            for edge in incoming.get(node_id, [])
            if _rel(edge) == _DEPENDS_ON and edge.source in graph.nodes and edge.source not in suffix
        ]
        if not upstream or len(suffix) > _MAX_DEPENDENT_DEPTH:
            chains.append(suffix)
            return
        for source in sorted(set(upstream)):
            walk(source, [source, *suffix])

    walk(integration_id, [integration_id])
    return chains


def _summary(graph: UnifiedGraph, hops: list[str], role_label: str, location: str) -> str:
    source, integration, bucket = graph.nodes[hops[0]], graph.nodes[hops[-2]], graph.nodes[hops[-1]]
    through = [graph.nodes[hop].label for hop in hops[1:-2]]
    if source.id == integration.id:
        lead = integration.label
    else:
        lead = f"{source.label} depends on {integration.label}" + (f" through {', '.join(through)}" if through else "") + ", which"
    return (
        f"{lead} assumes AWS role {role_label} and can access {location} on bucket {bucket.label}; "
        "the role ARN, trust principal and external id are recorded on both sides. "
        "Configured access, not an observed transfer."
    )


def cross_vendor_storage_paths(
    graph: UnifiedGraph,
    *,
    incoming: dict[str, list[UnifiedEdge]] | None = None,
    path_boost: Callable[[list[str]], float] | None = None,
) -> list[AttackPath]:
    """Snowflake-object → AWS bucket paths, one per dependent chain and allowed bucket.

    ``incoming`` is the caller's target → edges index when it already holds one.
    """
    assumes: dict[tuple[str, str], UnifiedEdge] = {}
    access: list[UnifiedEdge] = []
    for edge in graph.edges:
        if not _from_correlator(edge):
            continue
        rel = _rel(edge)
        if rel == RelationshipType.ASSUMES.value:
            assumes[(edge.source, edge.target)] = edge
        elif rel == RelationshipType.CAN_ACCESS.value:
            access.append(edge)
    if not access:
        return []
    if incoming is None:
        incoming = {}
        for edge in graph.edges:
            if _rel(edge) == _DEPENDS_ON:
                incoming.setdefault(edge.target, []).append(edge)

    paths: list[AttackPath] = []
    for edge in sorted(access, key=lambda item: (item.source, item.target)):
        role_id = str((edge.evidence or {}).get("via_role") or "")
        joined = assumes.get((edge.source, role_id))
        if joined is None or not _FULL_TRUST_BASIS.issubset((joined.evidence or {}).get("basis") or ()):
            continue
        role = graph.nodes.get(role_id)
        if role is None or edge.source not in graph.nodes or edge.target not in graph.nodes:
            continue
        for chain in _dependent_chains(graph, edge.source, incoming):
            hops = [*chain, edge.target]
            risk = _BASE_RISK + (path_boost(hops) if path_boost else 0.0)
            paths.append(
                AttackPath(
                    source=hops[0],
                    target=edge.target,
                    hops=hops,
                    edges=[_DEPENDS_ON] * (len(chain) - 1) + [RelationshipType.CAN_ACCESS.value],
                    composite_risk=round(min(100.0, risk), 2),
                    summary=_summary(graph, hops, role.label, str((edge.evidence or {}).get("location") or "")),
                    reachability="likely",
                    reachability_basis=["recorded_identifier_match"],
                )
            )
            if len(paths) >= _MAX_PATHS:
                return paths
    return paths


__all__ = ["cross_vendor_storage_paths"]
