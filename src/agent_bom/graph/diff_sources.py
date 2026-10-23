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


_NODE_HIGHLIGHTS = ("new_critical_findings", "new_credential_reach", "removed_controls")
_PATH_HIGHLIGHTS = ("new_attack_paths", "removed_attack_paths")


def _highlight_rows(highlights: dict[str, Any], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    return [row for key in keys for row in (highlights.get(key) or {}).get("top") or [] if isinstance(row, dict)]


def _vendor_anchor(row: dict[str, Any]) -> list[str]:
    """A node names itself; a relationship or path names its target first, then its source."""
    if row.get("kind") == "node":
        return [str(row.get("id") or "")]
    return [str(row.get("target") or ""), str(row.get("source") or "")]


def attribute_highlight_vendors(store: Any, tenant: str, old_id: str, new_id: str, highlights: dict[str, Any]) -> None:
    """Stamp each highlighted change with the vendor its node's collector recorded; unrecorded stays absent."""
    rows = _highlight_rows(highlights, _NODE_HIGHLIGHTS) + _highlight_rows(highlights, _PATH_HIGHLIGHTS)
    by_scan: dict[str, list[dict[str, Any]]] = {old_id: [], new_id: []}
    for row in rows:
        by_scan[old_id if row.get("change") == "removed" else new_id].append(row)
    for scan_id, scan_rows in by_scan.items():
        ids = {anchor for row in scan_rows for anchor in _vendor_anchor(row)} - {""}
        if not ids:
            continue
        vendors = {node.id: node_vendor(node) for node in store.nodes_by_ids(tenant_id=tenant, scan_id=scan_id, node_ids=ids)}
        for row in scan_rows:
            vendor = next((vendors[anchor] for anchor in _vendor_anchor(row) if vendors.get(anchor)), "")
            if vendor:
                row["vendor"] = vendor


__all__ = ["attribute_highlight_vendors", "changes_by_collected_source"]
