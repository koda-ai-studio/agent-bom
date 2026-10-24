"""Snapshot diffs compare nodes by identity, not by the id spelling each snapshot used.

A node whose id scheme changed records its retired id in ``identity.aliases``
and ``graph_node_aliases`` of the new snapshot. Diffs map those old ids to the
new canonical id before comparing, so a renamed node is unchanged (or changed
when its attributes differ) instead of removed plus added. Removed rows keep the
old snapshot's ids so they still open there.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from agent_bom.graph.drift_attributes import attribute_deltas, node_snapshot_changed

EdgeKey = tuple[str, str, str]
_LOOKUP_BATCH = 500


def snapshot_rename_map(
    candidates: Iterable[str],
    *,
    resolve: Callable[[list[str]], dict[str, str]],
    old_live: Callable[[list[str]], set[str]],
    new_live: Callable[[list[str]], Iterable[str]],
) -> dict[str, str]:
    """``{old id: new canonical id}`` for old-snapshot ids the new snapshot renamed.

    ``resolve`` maps ids through the NEW snapshot's alias bindings. A binding is
    a rename only when it is one-to-one, its target is a node of the new
    snapshot and was not already a node of the old one (that is a merge).
    """
    ids = sorted({node_id for node_id in candidates if node_id})
    resolved: dict[str, str] = {}
    for start in range(0, len(ids), _LOOKUP_BATCH):
        resolved.update(resolve(ids[start : start + _LOOKUP_BATCH]) or {})
    resolved = {old: new for old, new in resolved.items() if new and new != old}
    if not resolved:
        return {}
    targets = sorted(set(resolved.values()))
    existed, present = set(), set()
    for start in range(0, len(targets), _LOOKUP_BATCH):
        batch = targets[start : start + _LOOKUP_BATCH]
        existed |= set(old_live(batch))
        present |= set(new_live(batch))
    claims: dict[str, int] = {}
    for new in resolved.values():
        claims[new] = claims.get(new, 0) + 1
    return {old: new for old, new in sorted(resolved.items()) if claims[new] == 1 and new in present and new not in existed}


def remap_edge_keys(keys: Iterable[EdgeKey], rename: dict[str, str]) -> dict[EdgeKey, EdgeKey]:
    """``{key in new-snapshot ids: key as the old snapshot recorded it}``."""
    remapped: dict[EdgeKey, EdgeKey] = {}
    for key in keys:
        source, target, relationship = key
        remapped[(rename.get(source, source), rename.get(target, target), relationship)] = key
    return remapped


def node_set_diff(
    old_nodes: dict[str, dict[str, Any]],
    new_nodes: dict[str, dict[str, Any]],
    rename: dict[str, str],
) -> dict[str, Any]:
    """Added, removed and changed nodes with renamed old ids compared under their new id."""
    old_by_new_id = {rename.get(nid, nid): meta for nid, meta in old_nodes.items()}
    old_ids, new_ids = set(old_by_new_id), set(new_nodes)
    original = {new: old for old, new in rename.items()}
    attribute_delta_index: dict[str, list[dict[str, Any]]] = {}
    nodes_changed: list[str] = []
    for nid in sorted(old_ids & new_ids):
        if not node_snapshot_changed(old_by_new_id[nid], new_nodes[nid]):
            continue
        nodes_changed.append(nid)
        deltas = attribute_deltas(old_by_new_id[nid], new_nodes[nid])
        if deltas:
            attribute_delta_index[nid] = deltas
    return {
        "nodes_added": [new_nodes[nid] for nid in sorted(new_ids - old_ids)],
        "nodes_removed": [old_nodes[original.get(nid, nid)] for nid in sorted(old_ids - new_ids)],
        "nodes_changed": nodes_changed,
        "nodes_renamed": {new: old for old, new in sorted(rename.items(), key=lambda item: item[1])},
        "attribute_deltas": attribute_delta_index,
    }


def edge_set_diff(old_edges: set[EdgeKey], new_edges: set[EdgeKey], rename: dict[str, str]) -> dict[str, list[EdgeKey]]:
    """Added and removed edge keys; removed keys keep the old snapshot's ids."""
    old_by_new_key = remap_edge_keys(old_edges, rename)
    return {
        "edges_added": sorted(set(new_edges) - set(old_by_new_key)),
        "edges_removed": sorted(old_by_new_key[key] for key in set(old_by_new_key) - set(new_edges)),
    }


def edge_lifecycle_diff(
    old_edges: dict[EdgeKey, dict[str, Any]],
    new_edges: dict[EdgeKey, dict[str, Any]],
    rename: dict[str, str],
    fingerprint: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    """Rich edge lifecycle changes; a renamed endpoint compares under its new id."""
    originals = remap_edge_keys(old_edges, rename)
    old_by_new_key = {key: old_edges[original] for key, original in originals.items()}
    old_keys, new_keys = set(old_by_new_key), set(new_edges)
    shared = sorted(old_keys & new_keys)
    changed = [
        {"before": old_by_new_key[key], "after": new_edges[key]}
        for key in shared
        if fingerprint(old_by_new_key[key]) != fingerprint(new_edges[key])
    ]
    unchanged = [new_edges[key] for key in shared if fingerprint(old_by_new_key[key]) == fingerprint(new_edges[key])]
    removed = sorted(originals[key] for key in old_keys - new_keys)
    return {
        "edges_added": [new_edges[key] for key in sorted(new_keys - old_keys)],
        "edges_removed": [old_edges[key] for key in removed],
        "edges_changed": changed,
        "edges_unchanged": unchanged,
        "summary": {
            "added": len(new_keys - old_keys),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": len(unchanged),
        },
    }


__all__ = ["edge_lifecycle_diff", "edge_set_diff", "node_set_diff", "remap_edge_keys", "snapshot_rename_map"]
