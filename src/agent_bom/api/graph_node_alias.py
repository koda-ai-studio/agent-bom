"""Resolve a node id a saved link or older snapshot recorded to the id one snapshot uses.

Canonicalization replaces source-minted ids and identity schemes change; every
snapshot records the ids it replaced, so readers resolve within the snapshot
they serve and report the id they were given as ``resolved_from``.
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
