"""Shared reach policy for REST impact and MCP reach: which edges a blast-radius walk follows.

A blast radius answers "what can act on this node" (inbound) or "what can this
node act on" (outbound). Only edges that carry that claim are walked: the
dependency, authority, exposure, runtime and derived traversal classes.
Containment and hosting (structural), findings, governance and correlation
edges describe where a node sits or what is wrong with it; walking them made
an account, its org and the bucket's own misconfigurations "affected".

A finding root (a CVE, a misconfiguration) is the one place finding edges are
used: its first hop reaches the assets it names, and the walk continues from
those assets over the reach classes.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agent_bom.graph.completeness import impact_completeness
from agent_bom.graph.relationship_specs import RELATIONSHIP_SPECS, TraversalClass
from agent_bom.graph.types import EntityType, RelationshipType

REACH_TRAVERSAL_CLASSES: tuple[TraversalClass, ...] = (
    TraversalClass.AUTHORITY,
    TraversalClass.DEPENDENCY,
    TraversalClass.DERIVED,
    TraversalClass.EXPOSURE,
    TraversalClass.RUNTIME,
)
EXCLUDED_REACH_TRAVERSAL_CLASSES: tuple[TraversalClass, ...] = tuple(
    sorted((cls for cls in TraversalClass if cls not in REACH_TRAVERSAL_CLASSES), key=lambda cls: cls.value)
)
REACH_RELATIONSHIP_TYPES: frozenset[RelationshipType] = frozenset(
    rel for rel, spec in RELATIONSHIP_SPECS.items() if spec.traversal_class in REACH_TRAVERSAL_CLASSES
)
# The finding edges that name an affected asset, in either orientation.
FINDING_ENTRY_RELATIONSHIP_TYPES: frozenset[RelationshipType] = frozenset({RelationshipType.VULNERABLE_TO, RelationshipType.AFFECTS})
FINDING_ROOT_TYPES: frozenset[EntityType] = frozenset({EntityType.VULNERABILITY, EntityType.MISCONFIGURATION})

# (effective_scan_id, created_at, visited, depth_by_node, edges, parents, order, truncated, depth_limited)
WalkResult = tuple[str, str, set[str], dict[str, int], dict[Any, Any], dict[str, str], list[str], bool, bool]


@dataclass(frozen=True, slots=True)
class ReachWalk:
    effective_scan_id: str
    visited: set[str]
    depth_by_node: dict[str, int]
    truncated: bool
    depth_limited: bool


def reach_walk(
    walk: Callable[..., WalkResult],
    *,
    root: str,
    root_type: EntityType | str | None,
    direction: str,
    max_depth: int,
) -> ReachWalk:
    """Run a blast-radius walk through a store's ``_walk_graph`` bound to its connection.

    ``walk`` takes ``roots``, ``direction``, ``max_depth`` and
    ``relationship_types``; everything else (tenant, scan, budgets) is bound
    by the store.
    """
    kind = getattr(root_type, "value", root_type)
    if kind not in {member.value for member in FINDING_ROOT_TYPES}:
        scan_id, _, visited, depths, *_rest, truncated, depth_limited = walk(
            roots=[root], direction=direction, max_depth=max_depth, relationship_types=set(REACH_RELATIONSHIP_TYPES)
        )
        return ReachWalk(scan_id, visited, depths, truncated, depth_limited)

    scan_id, _, entry_visited, _depths, *_rest, entry_truncated, _entry_depth_limited = walk(
        roots=[root], direction="both", max_depth=1, relationship_types=set(FINDING_ENTRY_RELATIONSHIP_TYPES)
    )
    if root not in entry_visited:
        return ReachWalk(scan_id, entry_visited, {}, entry_truncated, False)
    entry = sorted(entry_visited - {root})
    if not entry:
        return ReachWalk(scan_id, {root}, {root: 0}, entry_truncated, False)
    _scan, _, visited, depths, *_rest, truncated, depth_limited = walk(
        roots=entry, direction=direction, max_depth=max_depth - 1, relationship_types=set(REACH_RELATIONSHIP_TYPES)
    )
    depth_by_node = {node_id: depth + 1 for node_id, depth in depths.items()}
    depth_by_node[root] = 0
    return ReachWalk(scan_id, {root, *visited}, depth_by_node, entry_truncated or truncated, depth_limited)


def impact_payload(store: Any, *, tenant_id: str, scan_id: str, node_id: str, walk: ReachWalk) -> dict[str, Any]:
    """The ``impact_of`` body every backend returns for one reach walk."""
    affected = sorted(node for node in walk.visited if node != node_id)
    by_type: dict[str, int] = {}
    for node in store.nodes_by_ids(tenant_id=tenant_id, scan_id=scan_id, node_ids=set(affected)):
        kind = str(getattr(node.entity_type, "value", node.entity_type))
        by_type[kind] = by_type.get(kind, 0) + 1
    return {
        "node_id": node_id,
        "affected_nodes": affected,
        "affected_by_type": by_type,
        "affected_count": len(affected),
        "max_depth_reached": max((walk.depth_by_node.get(node, 0) for node in affected), default=0),
        "completeness": impact_completeness(
            affected_count=len(affected),
            truncated=walk.truncated,
            depth_limited=walk.depth_limited,
        ),
    }


def reach_interpretation(*, max_depth: int, direction: str = "in") -> dict[str, Any]:
    """What a recorded walk does and does not establish."""
    return {
        "basis": "recorded_reverse_reachability" if direction == "in" else "recorded_forward_reachability",
        "execution": "not_established",
        "collection_coverage": "unknown",
        "traversable_only": False,
        "max_depth": max_depth,
        "traversal_classes": [cls.value for cls in REACH_TRAVERSAL_CLASSES],
        "excluded_traversal_classes": [cls.value for cls in EXCLUDED_REACH_TRAVERSAL_CLASSES],
    }


__all__ = [
    "EXCLUDED_REACH_TRAVERSAL_CLASSES",
    "FINDING_ENTRY_RELATIONSHIP_TYPES",
    "REACH_RELATIONSHIP_TYPES",
    "REACH_TRAVERSAL_CLASSES",
    "ReachWalk",
    "impact_payload",
    "reach_interpretation",
    "reach_walk",
]
