"""The asset node a finding row declares, so every projection of the row names one node.

A producer that knows which graph node a finding attaches to records it on
the row: ``node_id`` with that node's ``entity_type``. When the report carries no
inventory for the asset, a projection mints the asset itself; it mints it under
the declared id and type instead of re-deriving ``cloud_resource:<provider>:<identifier>``,
so a graph rebuilt from the report names the asset as the graph that produced
the report does. The row's native identifier (an ARN, say) stays a node
attribute, where asset canonicalization reads strong keys.

A declaration is honored only when it is unambiguous: the declared id is the
row's own namespaced identifier, or a canonical ``cloud_resource:`` id for a
cloud resource. A row that points at another node (a package a blast radius
names) or names its asset by a bare uuid never renames its asset.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from agent_bom.core.asset_types import entity_type_for_asset_type
from agent_bom.evidence.finding_node_ids import _dict, _text
from agent_bom.graph.types import EntityType

_FINDING_ENTITIES = frozenset({EntityType.VULNERABILITY, EntityType.MISCONFIGURATION})
_CLOUD_PREFIX = f"{EntityType.CLOUD_RESOURCE.value}:"


@dataclass(frozen=True, slots=True)
class DeclaredAsset:
    node_id: str
    entity_type: EntityType
    label: str


def row_provider(row: dict[str, Any]) -> str:
    asset = _dict(row.get("asset"))
    return _text(asset.get("provider")) or _text(row.get("provider")) or _text(asset.get("location"))


def declared_asset(row: Any) -> DeclaredAsset | None:
    """The node a finding row declares for its asset, when the declaration is unambiguous."""
    if not isinstance(row, dict):
        return None
    asset = _dict(row.get("asset"))
    node_id = _text(row.get("node_id"))
    asset_entity = entity_type_for_asset_type(_text(asset.get("asset_type")))
    if not node_id or asset_entity is None:
        return None
    try:
        entity = EntityType(_text(row.get("entity_type"))) if _text(row.get("entity_type")) else asset_entity
    except ValueError:
        return None
    if entity in _FINDING_ENTITIES:
        return None
    identifier = _text(asset.get("identifier"))
    # The identifier is itself a namespaced graph id, or a cloud row names its canonical cloud id.
    names_itself = node_id == identifier and ":" in node_id
    names_cloud_id = asset_entity is EntityType.CLOUD_RESOURCE and entity is EntityType.CLOUD_RESOURCE and node_id.startswith(_CLOUD_PREFIX)
    if not (names_itself or names_cloud_id):
        return None
    return DeclaredAsset(node_id, entity, _text(asset.get("name")) or identifier or node_id)


def declared_assets_by_identifier(findings: Iterable[Any] | None) -> dict[tuple[str, str], DeclaredAsset]:
    """``(provider, identifier) -> declared asset``; an identifier declared two ways names nothing."""
    declared: dict[tuple[str, str], DeclaredAsset] = {}
    conflicted: set[tuple[str, str]] = set()
    for row in findings if isinstance(findings, list) else ():
        found = declared_asset(row)
        if found is None:
            continue
        key = (row_provider(row).casefold(), _text(_dict(row.get("asset")).get("identifier")))
        prior = declared.setdefault(key, found)
        if (prior.node_id, prior.entity_type) != (found.node_id, found.entity_type):
            conflicted.add(key)
    for key in conflicted:
        declared.pop(key, None)
    return declared


__all__ = ["DeclaredAsset", "declared_asset", "declared_assets_by_identifier", "row_provider"]
