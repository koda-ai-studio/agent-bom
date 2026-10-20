"""Hydrate the agent stack above the findings on a graph page.

A ranked page is dominated by findings (CVEs, misconfigurations). Without the
package a CVE lives in, the workload that depends on it and the agent that uses
that workload, a finding renders as an orphan. This walk follows typed hops
upward from the page, keeps a bounded, ranked set of parents per node and
reports what it cut.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode

#: Parents kept per child per hop. A shared ``vuln:<CVE>`` can sit under
#: hundreds of packages; the page needs a representative few, not all of them.
STACK_FANOUT = 3
#: Hops walked upward: CVE → package → (package →) workload → agent.
_MAX_LEVELS = 4
#: Edge rows read per level and direction, whatever the fan-out.
_EDGE_BUDGET = 5000

_E = EntityType
_R = RelationshipType


@dataclass(frozen=True)
class _Hop:
    relationship: str
    child_types: frozenset[str]
    parent_types: frozenset[str]
    #: True when the edge points parent → child (``pkg vulnerable_to cve``);
    #: False when it points child → parent (``cve affects pkg``).
    parent_is_source: bool


def _types(*kinds: EntityType) -> frozenset[str]:
    return frozenset(kind.value for kind in kinds)


_WORKLOADS = _types(_E.SERVER, _E.CONTAINER)
_HOPS: tuple[_Hop, ...] = (
    _Hop(_R.VULNERABLE_TO.value, _types(_E.VULNERABILITY), _types(_E.PACKAGE, _E.SERVER, _E.CLOUD_RESOURCE), True),
    _Hop(_R.AFFECTS.value, _types(_E.VULNERABILITY), _types(_E.PACKAGE), False),
    _Hop(_R.AFFECTS.value, _types(_E.MISCONFIGURATION), _types(_E.AGENT, _E.SERVER), False),
    _Hop(_R.DEPENDS_ON.value, _types(_E.PACKAGE), _WORKLOADS | _types(_E.PACKAGE), True),
    _Hop(_R.USES.value, _types(_E.SERVER), _types(_E.AGENT), True),
)
#: Closer to the agent ranks first, so a package's workload beats its dependent package.
_TYPE_PRIORITY = {_E.AGENT.value: 0, _E.SERVER.value: 1, _E.CONTAINER.value: 1, _E.CLOUD_RESOURCE.value: 2, _E.PACKAGE.value: 3}


@dataclass
class StackContext:
    nodes: list[UnifiedNode] = field(default_factory=list)
    edges: list[UnifiedEdge] = field(default_factory=list)
    omitted_parent_links: int = 0
    budget_exhausted: bool = False

    def summary(self) -> dict[str, Any]:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "fanout_limit": STACK_FANOUT,
            "omitted_parent_links": self.omitted_parent_links,
            "truncated": bool(self.omitted_parent_links or self.budget_exhausted),
        }


def _kind(node: UnifiedNode) -> str:
    return node.entity_type.value if isinstance(node.entity_type, EntityType) else str(node.entity_type)


def _rel(edge: UnifiedEdge) -> str:
    return edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)


def _candidates(edges: list[UnifiedEdge], frontier: dict[str, str], *, parent_is_source: bool) -> list[tuple[str, str, UnifiedEdge, str]]:
    """``(child, parent, edge, relationship)`` for every edge whose child end is in the frontier."""
    out = []
    for edge in edges:
        child, parent = (edge.target, edge.source) if parent_is_source else (edge.source, edge.target)
        if child in frontier and parent != child:
            out.append((child, parent, edge, _rel(edge)))
    return out


def _hop_allows(child_type: str, parent_type: str, relationship: str, parent_is_source: bool) -> bool:
    return any(
        hop.relationship == relationship
        and hop.parent_is_source == parent_is_source
        and child_type in hop.child_types
        and parent_type in hop.parent_types
        for hop in _HOPS
    )


def _rank_key(node: UnifiedNode) -> tuple[int, float, str]:
    return (_TYPE_PRIORITY.get(_kind(node), 9), -float(node.risk_score or 0.0), node.id)


async def _read_level(graph_store: Any, call_store: Any, *, scan_id: str, tenant_id: str, frontier: dict[str, str], ctx: StackContext):
    child_types = set(frontier.values())
    found: list[tuple[str, str, UnifiedEdge, str, bool]] = []
    for parent_is_source, direction in ((True, "in"), (False, "out")):
        rels = {h.relationship for h in _HOPS if h.parent_is_source == parent_is_source and h.child_types & child_types}
        if not rels:
            continue
        edges = await call_store(
            graph_store.edges_for_node_ids,
            scan_id=scan_id,
            tenant_id=tenant_id,
            node_ids=set(frontier),
            direction=direction,
            relationships=rels,
            limit=_EDGE_BUDGET + 1,
        )
        if len(edges) > _EDGE_BUDGET:
            ctx.budget_exhausted = True
            edges = edges[:_EDGE_BUDGET]
        found.extend((*c, parent_is_source) for c in _candidates(list(edges), frontier, parent_is_source=parent_is_source))
    return found


async def page_agent_stack(
    graph_store: Any,
    *,
    scan_id: str,
    tenant_id: str,
    page_nodes: list[UnifiedNode],
    call_store: Any,
) -> StackContext:
    """Walk typed parent hops from the page's findings, ``STACK_FANOUT`` parents per node."""
    ctx = StackContext()
    known: dict[str, UnifiedNode] = {node.id: node for node in page_nodes}
    node_ids = set(known)
    frontier = {nid: _kind(node) for nid, node in known.items()}
    edge_keys: set[tuple[str, str, str]] = set()
    for _level in range(_MAX_LEVELS):
        if not frontier:
            break
        found = await _read_level(graph_store, call_store, scan_id=scan_id, tenant_id=tenant_id, frontier=frontier, ctx=ctx)
        missing = {parent for _c, parent, _e, _r, _s in found if parent not in known}
        if missing:
            for node in await call_store(graph_store.nodes_by_ids, scan_id=scan_id, tenant_id=tenant_id, node_ids=missing):
                known[node.id] = node
        frontier = _keep_ranked(found, frontier, known, node_ids, ctx, edge_keys)
    return ctx


def _keep_ranked(found, frontier, known, page_ids, ctx: StackContext, edge_keys) -> dict[str, str]:
    by_child: dict[str, dict[str, list[UnifiedEdge]]] = {}
    for child, parent, edge, rel, parent_is_source in found:
        node = known.get(parent)
        if node is None or not _hop_allows(frontier[child], _kind(node), rel, parent_is_source):
            continue
        by_child.setdefault(child, {}).setdefault(parent, []).append(edge)
    hydrated = {n.id for n in ctx.nodes}
    next_frontier: dict[str, str] = {}
    for child in sorted(by_child):
        parents = sorted(by_child[child], key=lambda pid: _rank_key(known[pid]))
        ctx.omitted_parent_links += max(0, len(parents) - STACK_FANOUT)
        for parent in parents[:STACK_FANOUT]:
            for edge in by_child[child][parent]:
                key = (edge.source, edge.target, _rel(edge))
                if key not in edge_keys:
                    edge_keys.add(key)
                    ctx.edges.append(edge)
            if parent in page_ids or parent in hydrated:
                continue
            hydrated.add(parent)
            ctx.nodes.append(known[parent])
            next_frontier[parent] = _kind(known[parent])
    return next_frontier


__all__ = ["STACK_FANOUT", "StackContext", "page_agent_stack"]
