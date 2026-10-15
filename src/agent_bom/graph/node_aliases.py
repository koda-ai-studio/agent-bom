"""Source node ids that canonicalization replaced, kept so old references resolve.

When :mod:`agent_bom.graph.asset_canonicalize` merges several observations of
one asset, the ids the sources minted live on in ``attributes.identity.aliases``
of the merged node. Persistence writes them to the tenant-keyed
``graph_node_aliases`` table; readers that receive an id recorded by an older
snapshot, a trace claim or a saved link resolve it to the canonical id.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
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
    dropped = 0
    for node in list(graph.nodes.values()):
        identity = node.attributes.get("identity")
        aliases = identity.get("aliases") if isinstance(identity, dict) else None
        if not isinstance(aliases, list):
            continue
        kept = [alias for alias in aliases if not (isinstance(alias, str) and alias in graph.nodes)]
        if len(kept) != len(aliases):
            dropped += len(aliases) - len(kept)
            node.attributes["identity"] = {**identity, "aliases": kept}
    return dropped


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
        """Rows in :data:`NODE_ALIAS_COLUMNS` order; one row per alias, the latest snapshot wins."""
        latest = {alias: (canonical, entity) for alias, canonical, entity in self.rows}
        return [
            (tenant, alias, canonical, entity, CORRELATION_IDENTITY_VERSION, scan, now)
            for alias, (canonical, entity) in sorted(latest.items())
        ]
