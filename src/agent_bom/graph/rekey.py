"""Batch node re-keying for an in-memory :class:`UnifiedGraph`.

Several node ids collapse onto one canonical id: their nodes merge with the
same union semantics as :meth:`UnifiedGraph.add_node`, every edge is re-pointed
at the canonical endpoint, edges that become duplicates merge their evidence,
and an edge that would connect a node to itself is dropped (two observations of
one asset do not relate the asset to itself).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import Any


def normalized_rekey_mapping(mapping: Mapping[str, str], exists: Callable[[str], bool]) -> dict[str, str]:
    """Drop identity and unknown entries; reject chains, which have no single meaning."""
    result = {old: new for old, new in mapping.items() if old and new and old != new and exists(old)}
    chained = sorted(set(result) & set(result.values()))
    if chained:
        raise ValueError(f"rekey mapping chains through re-keyed ids: {chained[:3]}")
    return result


def _key(edge: Any) -> tuple[str, str, str]:
    rel = edge.relationship.value if hasattr(edge.relationship, "value") else str(edge.relationship)
    return (edge.source, edge.target, rel)


def _rekey_path(path: Any, moves: Mapping[str, str]) -> Any:
    hops: list[str] = []
    edges: list[str] = []
    receipts: list[dict[str, Any]] = []
    for index, hop in enumerate(moves.get(hop, hop) for hop in path.hops):
        if hops and hops[-1] == hop:
            continue  # both ends of this hop are now one asset
        if hops:
            if index - 1 < len(path.edges):
                edges.append(path.edges[index - 1])
            if index - 1 < len(path.hop_evidence):
                receipt = dict(path.hop_evidence[index - 1])
                receipt["source_node_id"], receipt["target_node_id"] = hops[-1], hop
                receipts.append(receipt)
        hops.append(hop)
    return replace(
        path,
        source=moves.get(path.source, path.source),
        target=moves.get(path.target, path.target),
        hops=hops,
        edges=edges,
        hop_evidence=receipts,
    )


def rekey_path_references(graph: Any, moves: Mapping[str, str]) -> None:
    """Re-point attack paths and interaction risks at canonical ids; paths that collapse merge."""
    if not moves:
        return
    kept: dict[tuple[str, ...], Any] = {}
    for path in graph.attack_paths:
        rewritten = _rekey_path(path, moves) if any(hop in moves for hop in (path.source, path.target, *path.hops)) else path
        key = (rewritten.source, rewritten.target, *rewritten.hops)
        if key not in kept or rewritten.composite_risk > kept[key].composite_risk:
            kept[key] = rewritten
    graph.attack_paths = list(kept.values())
    for risk in graph.interaction_risks:
        if any(node_id in moves for node_id in risk.agent_node_ids):
            risk.agent_node_ids = list(dict.fromkeys(moves.get(node_id, node_id) for node_id in risk.agent_node_ids))


def rekey_in_memory(graph: Any, mapping: Mapping[str, str]) -> int:
    """Re-key nodes in place, touching only edges incident to a moved node.

    Returns the number of edges dropped because both ends became one node.
    """
    moves = normalized_rekey_mapping(mapping, graph.nodes.__contains__)
    if not moves:
        return 0
    touched: set[tuple[str, str, str]] = set()
    for old in moves:
        for edge in (*graph.adjacency.get(old, []), *graph.reverse_adjacency.get(old, [])):
            key = _key(edge)
            touched.add(key if key in graph._edge_keys else (key[1], key[0], key[2]))
    originals = [edge for edge in graph.edges if _key(edge) in touched]
    graph.edges = [edge for edge in graph.edges if _key(edge) not in touched]
    endpoints = {endpoint for key in touched for endpoint in key[:2]}
    for index in (graph.adjacency, graph.reverse_adjacency):
        for node_id in endpoints:
            kept = [
                edge
                for edge in index.get(node_id, [])
                if _key(edge) not in touched and (_key(edge)[1], _key(edge)[0], _key(edge)[2]) not in touched
            ]
            if kept:
                index[node_id] = kept
            else:
                index.pop(node_id, None)
    graph._edge_keys.difference_update(touched)
    for old, new in sorted(moves.items()):
        node = graph.nodes.pop(old)
        node.id = new
        graph.add_node(node)
    dropped = 0
    for edge in originals:
        source, target = moves.get(edge.source, edge.source), moves.get(edge.target, edge.target)
        if source == target:
            dropped += 1
            continue
        graph.add_stored_edge(replace(edge, source=source, target=target))
    rekey_path_references(graph, moves)
    return dropped
