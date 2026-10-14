"""Shared account anchoring for Snowflake graph lanes."""

from __future__ import annotations

from typing import Any

from agent_bom.graph.cloud_context import _add_account_resource_hierarchy, _add_identity_node
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.types import EntityType


class _SnowflakeLane:
    """Account anchor shared by one Snowflake payload's projected nodes."""

    def __init__(self, graph: UnifiedGraph, account: str, data_sources: list[str], source: str) -> None:
        self.graph = graph
        self.data_sources = data_sources
        self.source = source
        self.account_node_id = ""
        if account:
            self.account_node_id = _add_identity_node(
                graph,
                EntityType.ACCOUNT,
                account,
                "snowflake",
                data_sources,
                label=account or "snowflake",
                account_id=account,
                cloud_provider="snowflake",
                source=source,
            )

    def own(self, node: UnifiedNode) -> str:
        """Add ``node`` and hang it under the account resource hierarchy."""
        self.graph.add_node(node)
        if self.account_node_id:
            _add_account_resource_hierarchy(
                self.graph,
                self.account_node_id,
                node.id,
                evidence={"source": self.source},
            )
        return node.id


def _snowflake_data_store(lane: _SnowflakeLane, node_id: str, label: str, attrs: dict[str, Any]) -> str:
    return lane.own(
        UnifiedNode(
            id=node_id,
            entity_type=EntityType.DATA_STORE,
            label=label,
            attributes={"cloud_provider": "snowflake", "is_data_store": True, **attrs},
            data_sources=lane.data_sources,
            dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
        )
    )


def _snowflake_thin_node(lane: _SnowflakeLane, node_id: str, entity_type: EntityType, label: str, surface: str) -> None:
    if node_id not in lane.graph.nodes:
        lane.graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=entity_type,
                label=label,
                attributes={"cloud_provider": "snowflake"},
                data_sources=lane.data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface=surface),
            )
        )


def _needs_account_scope(node: UnifiedNode, account: str) -> bool:
    """Whether a staged node's id is only unique within its account.

    Accounts and organizations are global; a node whose id already embeds this
    lane's account (``snowflake_account_qualified``) is too.
    """
    if node.entity_type in {EntityType.ACCOUNT, EntityType.ORG}:
        return False
    return not (account and node.attributes.get("snowflake_account_qualified") and node.attributes.get("account_id") == account)
