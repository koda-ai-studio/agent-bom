"""Resolve a node id a saved link or older snapshot recorded to the id one snapshot uses.

Canonicalization replaces source-minted ids and identity schemes change; every
snapshot records the ids it replaced, so readers resolve within the snapshot
they serve and report the id they were given as ``resolved_from``. Stores are
duck-typed: any store with ``resolve_node_aliases`` resolves; others pass ids
through unchanged.
"""

from __future__ import annotations

from typing import Any


def resolve_snapshot_node_id(store: Any, *, tenant_id: str, scan_id: str, node_id: str) -> tuple[str, str | None]:
    """``(node id to read, resolved_from)``; ``resolved_from`` is None when the id is already canonical."""
    resolver = getattr(store, "resolve_node_aliases", None)
    if not node_id or not callable(resolver):
        return node_id, None
    try:
        canonical = resolver(tenant_id=tenant_id, node_ids=[node_id], scan_id=scan_id).get(node_id)
    except NotImplementedError:
        return node_id, None
    if not canonical or canonical == node_id:
        return node_id, None
    return str(canonical), node_id


def resolve_snapshot_node_ids(store: Any, *, tenant_id: str, scan_id: str, node_ids: list[str]) -> tuple[list[str], dict[str, str]]:
    """Resolve several ids at once: ``(ids to read, in order and de-duplicated, {given id: canonical id})``."""
    resolver = getattr(store, "resolve_node_aliases", None)
    mapping: dict[str, str] = {}
    if node_ids and callable(resolver):
        try:
            resolved = resolver(tenant_id=tenant_id, node_ids=list(node_ids), scan_id=scan_id) or {}
        except NotImplementedError:
            resolved = {}
        mapping = {given: str(canonical) for given, canonical in resolved.items() if canonical and canonical != given}
    ordered: list[str] = []
    for node_id in node_ids:
        read_id = mapping.get(node_id, node_id)
        if read_id not in ordered:
            ordered.append(read_id)
    return ordered, mapping
