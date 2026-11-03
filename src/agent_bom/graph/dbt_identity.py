"""Exact Snowflake identifier tuples for static dbt-to-connector references."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType

_TOKEN = r'(?:"(?:[^"]|"")+"|[A-Za-z_][A-Za-z0-9_$]*)'
_QUALIFIED = re.compile(rf"\s*({_TOKEN})\s*\.\s*({_TOKEN})\s*\.\s*({_TOKEN})\s*")


def qualified_parts(value: Any) -> tuple[str, str, str] | None:
    """Quoted case, embedded dots and significant spaces remain distinct."""
    if not isinstance(value, str) or len(value) > 1024:
        return None
    match = _QUALIFIED.fullmatch(value)
    if not match:
        return None
    parts = tuple(token[1:-1].replace('""', '"') if token.startswith('"') else token.upper() for token in match.groups())
    return parts[0], parts[1], parts[2]


def _connector_parts(node: UnifiedNode) -> tuple[str, str, str] | None:
    attrs = node.attributes
    fqn, database, schema = attrs.get("fqn"), attrs.get("database"), attrs.get("schema")
    if not isinstance(fqn, str) or len(fqn) > 1024:
        return None
    # Connector database/schema fields are stored identifiers, not SQL tokens.
    # Their boundaries disambiguate dots inside quoted names without flattening.
    if isinstance(database, str) and database and isinstance(schema, str) and schema:
        prefix = database + "." + schema + "."
        if fqn.startswith(prefix) and fqn[len(prefix) :]:
            return database, schema, fqn[len(prefix) :]
    if '"' in fqn:
        return qualified_parts(fqn)
    parts = fqn.split(".")
    if len(parts) == 3 and all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", p) for p in parts):
        return parts[0], parts[1], parts[2]  # preserve connector-reported stored case
    return None


def connector_index(graph: UnifiedGraph) -> dict[tuple[str, tuple[str, str, str]], list[str]]:
    index: dict[tuple[str, tuple[str, str, str]], list[str]] = defaultdict(list)
    if not graph.tenant_id:
        return index
    for node in graph.nodes.values():
        attrs = node.attributes
        if node.entity_type != EntityType.DATA_STORE or (attrs.get("cloud_provider") or node.dimensions.cloud_provider) != "snowflake":
            continue
        if attrs.get("tenant_id") not in (None, "", graph.tenant_id):
            continue
        account, parts = attrs.get("account_id"), _connector_parts(node)
        if isinstance(account, str) and account and parts is not None:
            index[(account, parts)].append(node.id)
    return index
