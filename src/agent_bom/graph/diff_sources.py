"""Attribute each changed node to the vendor and account its collector recorded.

A scope's label names how the scan was requested (``local-agents``, a repo, a
push); one scan can still collect many vendors. This breakdown reads each
changed node's own ``cloud_provider`` and account, so a change is attributed to
the connector that produced it. Nodes without a recorded vendor are counted as
unattributed, never guessed.
"""

from __future__ import annotations

from typing import Any

from agent_bom.graph.path_vendors import node_vendor

SOURCE_LIMIT = 12
_ACCOUNT_FIELDS = ("account_id", "account_scope", "account", "subscription_id", "project_id")
_CHANGES = ("added", "removed", "changed")


def _account(node: Any) -> str:
    attributes = getattr(node, "attributes", None) or {}
    return next((str(attributes[field]) for field in _ACCOUNT_FIELDS if attributes.get(field)), "")


def changes_by_collected_source(store: Any, tenant: str, old_id: str, new_id: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    node_rows = [row for row in rows if row.get("kind") == "node"]
    wanted = {
        new_id: {row["id"] for row in node_rows if row["change"] != "removed"},
        old_id: {row["id"] for row in node_rows if row["change"] == "removed"},
    }
    nodes: dict[tuple[str, str], Any] = {}
    for scan_id, ids in wanted.items():
        if ids:
            for node in store.nodes_by_ids(tenant_id=tenant, scan_id=scan_id, node_ids=ids):
                nodes[(scan_id, node.id)] = node
    counts: dict[tuple[str, str], dict[str, int]] = {}
    unattributed = dict.fromkeys(_CHANGES, 0)
    for row in node_rows:
        node = nodes.get((old_id if row["change"] == "removed" else new_id, row["id"]))
        vendor = node_vendor(node) if node is not None else ""
        if not vendor:
            unattributed[row["change"]] += 1
            continue
        counts.setdefault((vendor, _account(node)), dict.fromkeys(_CHANGES, 0))[row["change"]] += 1
    ordered = sorted(counts.items(), key=lambda item: (-sum(item[1].values()), item[0]))
    return {
        "unit": "nodes",
        "sources": [{"vendor": vendor, "account": account, **changes} for (vendor, account), changes in ordered[:SOURCE_LIMIT]],
        "omitted_sources": max(0, len(ordered) - SOURCE_LIMIT),
        "unattributed": unattributed,
    }


__all__ = ["changes_by_collected_source"]
