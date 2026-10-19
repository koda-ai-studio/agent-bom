"""Source node ids that canonicalization replaced, kept so old references resolve.

When :mod:`agent_bom.graph.asset_canonicalize` merges several observations of
one asset, the ids the sources minted live on in ``attributes.identity.aliases``
of the merged node. Persistence writes them to the tenant-keyed
``graph_node_aliases`` table; readers that receive an id recorded by an older
snapshot, a trace claim or a saved link resolve it to the canonical id.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from agent_bom.graph.correlation_scope import CORRELATION_IDENTITY_VERSION
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType

NODE_ALIAS_COLUMNS = ("tenant_id", "alias_id", "canonical_id", "entity_type", "identity_version", "scan_id", "updated_at")


def drop_live_node_aliases(graph: Any) -> int:
    """Remove recorded aliases that equal a live node id; returns how many were dropped.

    Case-preserving ids make a retired lower-cased id of one asset equal the
    current id of another, and an alias must never redirect a live node.
    """
    # Stream once and keep only nodes that carry aliases: a store-backed graph
    # must not hold every node in memory at the same time.
    carriers: list[tuple[str, list[Any]]] = []
    for node in graph.nodes.values():
        identity = node.attributes.get("identity")
        aliases = identity.get("aliases") if isinstance(identity, dict) else None
        if isinstance(aliases, list) and aliases:
            carriers.append((node.id, aliases))
    dropped = 0
    for node_id, aliases in carriers:
        kept = [alias for alias in aliases if not (isinstance(alias, str) and graph.has_node(alias))]
        if len(kept) == len(aliases):
            continue
        node = graph.get_node(node_id)
        identity = node.attributes.get("identity") if node is not None else None
        if node is None or not isinstance(identity, dict):
            continue
        dropped += len(aliases) - len(kept)
        node.attributes["identity"] = {**identity, "aliases": kept}
    return dropped


def record_node_aliases(node: UnifiedNode, aliases: Iterable[str]) -> None:
    """Add retired ids to a node's ``identity.aliases`` so persistence keeps them resolvable."""
    retired = {alias for alias in aliases if isinstance(alias, str) and alias and alias != node.id}
    if not retired:
        return
    identity = node.attributes.get("identity")
    identity = dict(identity) if isinstance(identity, dict) else {}
    known = [alias for alias in identity.get("aliases", []) if isinstance(alias, str)]
    identity["aliases"] = sorted({*known, *retired})
    node.attributes["identity"] = identity


@dataclass(slots=True)
class NodeAliasCollector:
    """Collect ``(alias_id, canonical_id, entity_type)`` while nodes stream to storage."""

    rows: list[tuple[str, str, str]] = field(default_factory=list)

    def wrap(self, nodes: Iterable[UnifiedNode]) -> Iterator[UnifiedNode]:
        for node in nodes:
            identity = node.attributes.get("identity")
            aliases = identity.get("aliases") if isinstance(identity, dict) else None
            if isinstance(aliases, list):
                entity = node.entity_type.value if isinstance(node.entity_type, EntityType) else str(node.entity_type)
                self.rows.extend(
                    (str(alias), node.id, entity) for alias in aliases if isinstance(alias, str) and alias and alias != node.id
                )
            yield node

    def records(self, *, tenant: str, scan: str, now: str) -> list[tuple[str, str, str, str, str, str, str]]:
        """Persist only unambiguous bindings within this snapshot.

        A retired label shared by distinct nodes is not identity evidence.
        Keep both observations, but never select a target by insertion order.
        """
        targets: dict[str, set[tuple[str, str]]] = {}
        for alias, canonical, entity in self.rows:
            targets.setdefault(alias, set()).add((canonical, entity))
        latest = {alias: next(iter(values)) for alias, values in targets.items() if len(values) == 1}
        return [
            (tenant, alias, canonical, entity, CORRELATION_IDENTITY_VERSION, scan, now)
            for alias, (canonical, entity) in sorted(latest.items())
        ]


# Server children are ``<prefix>:<server id>:<name>``. Their historical ids are
# the parent server's historical ids with the same suffix, so they are derived
# from the one server alias at read time instead of being stored per child
# (N tools x K server aliases rows).
SERVER_CHILD_PREFIXES = ("tool", "cred")
_MAX_CHILD_SPLITS = 16


def server_child_parts(node_id: str) -> list[tuple[str, str, str]]:
    """Every ``(prefix, server ref, child name)`` reading of a child id; names may contain colons."""
    prefix, separator, rest = node_id.partition(":")
    if not separator or prefix not in SERVER_CHILD_PREFIXES or not rest.startswith("server:"):
        return []
    parts: list[tuple[str, str, str]] = []
    position = rest.find(":", len("server:"))
    while position != -1 and len(parts) < _MAX_CHILD_SPLITS:
        parent, name = rest[:position], rest[position + 1 :]
        if name:
            parts.append((prefix, parent, name))
        position = rest.find(":", position + 1)
    return parts


def resolve_with_server_children(
    ids: Sequence[str],
    resolve_direct: Callable[[list[str]], dict[str, str]],
    live: Callable[[list[str]], set[str]],
) -> dict[str, str]:
    """Direct alias bindings plus server-child ids derived from their parent server's binding.

    A derived child binds only when exactly one reading resolves to a live child
    node in the snapshot, and never when the requested id is itself a live node.
    """
    resolved = resolve_direct(list(ids))
    pending = {node_id: server_child_parts(node_id) for node_id in ids if node_id not in resolved}
    pending = {node_id: parts for node_id, parts in pending.items() if parts}
    if not pending:
        return resolved
    parents = sorted({parent for parts in pending.values() for _prefix, parent, _name in parts})
    parent_map = resolve_direct(parents)
    derived = {
        node_id: {f"{prefix}:{parent_map[parent]}:{name}" for prefix, parent, name in parts if parent in parent_map}
        for node_id, parts in pending.items()
    }
    derived = {node_id: targets for node_id, targets in derived.items() if targets}
    if not derived:
        return resolved
    present = live(sorted({*derived, *(target for targets in derived.values() for target in targets)}))
    for node_id, targets in derived.items():
        live_targets = targets & present
        if node_id not in present and len(live_targets) == 1:
            resolved[node_id] = next(iter(live_targets))
    return resolved
