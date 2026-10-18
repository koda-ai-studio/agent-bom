"""Cross-container relationship projection for the containment roll-up.

Containment defines the nesting a roll-up draws. Every other recorded
relationship is aggregated between the visible scopes, retaining direction and
per-kind counts, so the collapsed view reads as a graph rather than a grid of
disconnected cards. The aggregate is not proof of a direct or executable path.
"""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from collections.abc import Callable, Iterable, Sequence
from typing import Any, cast

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import RelationshipType

# Cap on aggregated cross-container edges returned. Ordered by weight, so the
# cut keeps the heaviest relationships — the ones a reviewer would look at first.
MAX_CROSS_CONTAINER_EDGES = 400

ContainmentPredicate = Callable[[UnifiedGraph, Any], bool]


def combine_reasons(*reasons: str) -> str:
    """Merge truncation reasons, deduped and order-preserving.

    A roll-up can be cut twice — once by the loader's node budget and again by
    the orphan limit. Reporting only one hides the other, so both travel as a
    comma-separated list under the single ``reason`` key clients already read.
    """
    merged: list[str] = []
    for reason in reasons:
        for part in reason.split(","):
            cleaned = part.strip()
            if cleaned and cleaned not in merged:
                merged.append(cleaned)
    return ",".join(merged)


def descendants(root: str, children: dict[str, list[str]]) -> list[str]:
    """All transitive CONTAINS descendants of *root* (excludes root). Bounded by
    a visited set so cycles terminate; returned sorted for determinism."""
    seen: set[str] = set()
    queue: deque[str] = deque(children.get(root, []))
    while queue:
        current = queue.popleft()
        if current in seen or current == root:
            continue
        seen.add(current)
        for kid in children.get(current, []):
            if kid not in seen:
                queue.append(kid)
    return sorted(seen)


def _container_of(node_ids: Iterable[str], children: dict[str, list[str]]) -> dict[str, str]:
    """Map every descendant to the visible container it rolls up into."""
    owner: dict[str, str] = {}
    for container_id in node_ids:
        owner[container_id] = container_id
        for descendant in descendants(container_id, children):
            owner.setdefault(descendant, container_id)
    return owner


def cross_container_edge_rows(
    graph: UnifiedGraph,
    container_ids: Sequence[str],
    children: dict[str, list[str]],
    is_containment: ContainmentPredicate,
) -> tuple[list[dict[str, Any]], int, dict[str, dict[str, Any]]]:
    """Return the bounded edge rows, their pre-cap source total and per-entry totals.

    Self-edges (both endpoints inside one container) are dropped: they are
    internal detail the container already stands for.
    """
    owner = _container_of(container_ids, children)
    if not owner:
        return [], 0, {}

    aggregated: dict[tuple[str, str], dict[str, Any]] = {}
    for edge in graph.edges:
        if is_containment(graph, edge):
            continue
        source_container = owner.get(edge.source)
        target_container = owner.get(edge.target)
        if not source_container or not target_container:
            continue
        if source_container == target_container:
            continue
        key = (source_container, target_container)
        entry = aggregated.get(key)
        relationship = edge.relationship.value if isinstance(edge.relationship, RelationshipType) else str(edge.relationship)
        if entry is None:
            aggregated[key] = {
                "source": source_container,
                "target": target_container,
                "count": 1,
                "relationships": {relationship},
                "directions": {edge.direction},
                "relationship_counts": {relationship: 1},
            }
            continue
        entry["count"] = int(entry["count"]) + 1
        cast(set, entry["relationships"]).add(relationship)
        cast(set, entry["directions"]).add(edge.direction)
        counts = cast(dict[str, int], entry["relationship_counts"])
        counts[relationship] = counts.get(relationship, 0) + 1

    rows = [
        {
            "source": entry["source"],
            "target": entry["target"],
            "count": entry["count"],
            "relationships": sorted(cast(set, entry["relationships"])),
            "directions": sorted(cast(set, entry["directions"])),
            "relationship_counts": dict(sorted(entry["relationship_counts"].items())),
        }
        for entry in aggregated.values()
    ]
    # Heaviest first, then deterministic by endpoint so the truncation is stable.
    rows.sort(key=lambda row: (-int(row["count"]), str(row["source"]), str(row["target"])))
    return rows[:MAX_CROSS_CONTAINER_EDGES], len(rows), _entry_connections(rows)


def _entry_connections(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Per-entry relationship totals over every row, before the presentation cap.

    A client that counted neighbours from the capped ``edges`` list would report
    a page count as the entry's total; this travels on the entry instead.
    """
    peers: dict[str, set[str]] = defaultdict(set)
    relationships: Counter[str] = Counter()
    for row in rows:
        source, target, count = str(row["source"]), str(row["target"]), int(row["count"])
        peers[source].add(target)
        peers[target].add(source)
        relationships[source] += count
        relationships[target] += count
    return {entry: _connections(len(linked), relationships[entry]) for entry, linked in peers.items()}


def _connections(connected: int, relationships: int) -> dict[str, Any]:
    return {
        "basis": "returned_entries",
        "definition": "Other entries in this response linked by non-containment relationships; not direct children.",
        "connected_entry_count": connected,
        "relationship_count": relationships,
    }


def edge_count_metadata(graph: UnifiedGraph, *, returned: int, source_total: int) -> dict[str, Any]:
    """Describe relationship-row loss independently from node completeness.

    ``source_total`` is exact for the graph materialised by the caller. If that
    source graph was already bounded, ``source_truncated`` and the inherited
    reason make clear that this is not an estate-wide denominator.
    """
    row_truncated = source_total > returned
    source_truncated = graph.completeness.truncated
    return {
        "definition": "Aggregated non-containment container-to-container relationship rows in the roll-up source graph.",
        "source_total": source_total,
        "returned": returned,
        "truncated": row_truncated or source_truncated,
        "source_truncated": source_truncated,
        "reason": combine_reasons(
            graph.completeness.reason if source_truncated else "",
            "rollup_edge_limit" if row_truncated else "",
        ),
    }


def edge_projection(
    graph: UnifiedGraph,
    entries: Sequence[dict[str, Any]],
    children: dict[str, list[str]],
    is_containment: ContainmentPredicate,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Edge rows for the returned entries; each entry gains its uncapped ``connections``."""
    rows, source_total, connections = cross_container_edge_rows(graph, [entry["id"] for entry in entries], children, is_containment)
    for entry in entries:
        entry["connections"] = connections.get(entry["id"]) or _connections(0, 0)
    return rows, edge_count_metadata(graph, returned=len(rows), source_total=source_total)
