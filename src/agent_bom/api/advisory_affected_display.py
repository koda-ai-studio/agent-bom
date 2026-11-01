"""Name each affected-asset row from the graph nodes the estate already holds.

An image-scoped package occurrence (``pkg:<eco>:<name>@<ver>:image:<digest>``)
reaches the affected answer with nothing but its package label, so fifty rows
read "pyyaml@5.3 · package". The graph knows the image that carries it and
the workload that runs the image; an MCP-server row likewise has an agent and,
when hosting was recorded, a pod or workload. This pass attaches that
presentation (``asset_display``) in two bounded, tenant-scoped graph reads and
never fails the answer: a missing node or an unavailable store leaves the
recorded label in place.

It also names what the answer counts: one row per package occurrence on each
holding asset, which is why the affected total can exceed the grouped
findings total for the same advisory.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from typing import Any

logger = logging.getLogger(__name__)

AFFECTED_COUNT_BASIS = "package_occurrence_per_holding_asset"
AFFECTED_COUNT_BASIS_NOTE = (
    "One row per package occurrence on each holding asset (MCP server, container image or standalone package). "
    "Findings group one occurrence across the servers that hold it, so their total for the same advisory can be lower."
)

_EMPTY: dict[str, Any] = {}


def _text(value: Any, maximum: int = 200) -> str:
    return value.strip()[:maximum] if isinstance(value, str) else ""


def _tags(node: Any) -> Mapping[str, Any]:
    tags = getattr(node, "attributes", _EMPTY).get("tags")
    return tags if isinstance(tags, Mapping) else _EMPTY


def _image_name(node: Any) -> str:
    attrs = getattr(node, "attributes", _EMPTY)
    return _text(attrs.get("image_ref")) or _text(getattr(node, "label", "")).removeprefix("image: ")


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else _EMPTY


def _row_ids(row: Mapping[str, Any]) -> tuple[str, str, str]:
    graph = _mapping(row.get("graph"))
    return _text(row.get("asset_node_id")), _text(graph.get("server_node_id")), _text(graph.get("agent_node_id"))


def _fallback(row: Mapping[str, Any]) -> dict[str, str]:
    asset = _mapping(row.get("asset"))
    return {
        "name": _text(row.get("asset_label")),
        "kind": _text(row.get("asset_type")) or "package",
        "agent": _text(asset.get("agent")),
        "host": "",
    }


def _nodes(store: Any, tenant_id: str, ids: Iterable[str]) -> dict[str, Any]:
    wanted = {i for i in ids if i}
    if not wanted:
        return {}
    return {node.id: node for node in store.nodes_by_ids(tenant_id=tenant_id, scan_id="", node_ids=wanted)}


def _hosts(store: Any, tenant_id: str, server_ids: set[str]) -> dict[str, str]:
    if not server_ids:
        return {}
    edges = store.edges_for_node_ids(tenant_id=tenant_id, scan_id="", node_ids=server_ids, direction="out", relationships={"hosted_on"})
    hosts: dict[str, str] = {}
    for edge in edges:
        source, target = _text(getattr(edge, "source", "")), _text(getattr(edge, "target", ""))
        if source in server_ids and target:
            hosts.setdefault(source, target)
    return hosts


def attach_asset_display(rows: list[dict[str, Any]], *, tenant_id: str, store: Any) -> None:
    """Set ``row["asset_display"]`` on every row; presentation only, never a verdict input."""
    for row in rows:
        row["asset_display"] = _fallback(row)
    try:
        first = _nodes(store, tenant_id, (i for row in rows for i in _row_ids(row)))
        package_rows = [row for row in rows if row["asset_display"]["kind"] == "package"]
        server_hosts = _hosts(store, tenant_id, {_row_ids(row)[1] for row in rows if _row_ids(row)[1]})
        second_ids: set[str] = set(server_hosts.values())
        for row in package_rows:
            tags = _tags(first.get(_row_ids(row)[0]))
            second_ids |= {_text(tags.get("container_image")), _text(tags.get("workload"))}
        second = _nodes(store, tenant_id, second_ids)
    except Exception:  # broad-except: any graph backend error leaves the recorded label in place; the answer must serve
        logger.debug("affected-asset display enrichment skipped", exc_info=True)
        return
    for row in rows:
        asset_id, server_id, agent_id = _row_ids(row)
        display = row["asset_display"]
        if display["kind"] == "package":
            tags = _tags(first.get(asset_id))
            image = second.get(_text(tags.get("container_image")))
            workload = second.get(_text(tags.get("workload")))
            if image is not None:
                display["name"], display["kind"] = _image_name(image), "container_image"
            if workload is not None:
                display["host"] = _text(workload.label)
            continue
        if display["kind"] == "container_image" and asset_id in first:
            display["name"] = _image_name(first[asset_id])
        if server_id in first:
            display["name"] = _text(first[server_id].label) or display["name"]
        if agent_id in first:
            display["agent"] = _text(first[agent_id].label) or display["agent"]
        host = second.get(server_hosts.get(server_id, ""))
        if host is not None:
            display["host"] = _text(host.label)


def label_count_basis(summary: dict[str, Any]) -> dict[str, Any]:
    """Return ``summary`` with the counting basis named, so 52 beside a grouped 51 explains itself."""
    return {**summary, "count_basis": AFFECTED_COUNT_BASIS, "count_basis_note": AFFECTED_COUNT_BASIS_NOTE}


__all__ = ["AFFECTED_COUNT_BASIS", "AFFECTED_COUNT_BASIS_NOTE", "attach_asset_display", "label_count_basis"]
