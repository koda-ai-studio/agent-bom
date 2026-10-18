"""The bounded two-snapshot graph diff behind ``/v1/graph/diff`` and the MCP ``graph_diff`` tool."""

from __future__ import annotations

import hashlib
import json
import threading
from collections import OrderedDict
from dataclasses import replace
from typing import Any

from fastapi import HTTPException, Request

from agent_bom.api.graph_node_alias import resolve_snapshot_node_id
from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.graph.attack_path_queue import attack_path_rank_window
from agent_bom.graph.completeness import graph_completeness
from agent_bom.graph.diff_view import (
    DETAIL_MAX_LIMIT,
    DIFF_VIEWS,
    DiffFilters,
    cursor_scope,
    decode_cursor,
    detail_page,
    diff_rows,
    diff_summary,
    encode_cursor,
    full_view,
    new_attack_paths,
    validate_filters,
)


async def _resolve_pair(store: Any, tenant: str, old: str | None, new: str | None) -> tuple[str, str]:
    if bool(old) != bool(new):
        raise HTTPException(status_code=422, detail="Pass both old and new scan IDs, or neither to compare the latest two snapshots.")
    if old and new:
        resolved_old, resolved_new = await _runtime.require_graph_snapshot_ids(store, tenant, old, new)
        return resolved_old, resolved_new
    latest = await _runtime._graph_store_call(store.list_snapshots, tenant_id=tenant, limit=2)
    if len(latest or []) < 2:
        raise HTTPException(status_code=404, detail="Two graph snapshots are needed to compute a diff.")
    return str(latest[1]["scan_id"]), str(latest[0]["scan_id"])


def _changed_node_meta(store: Any, tenant: str, scan_id: str, node_ids: list[str]) -> dict[str, dict[str, Any]]:
    if not node_ids:
        return {}
    meta: dict[str, dict[str, Any]] = {}
    for node in store.nodes_by_ids(tenant_id=tenant, scan_id=scan_id, node_ids=set(node_ids)):
        kind = getattr(node, "entity_type", "")
        meta[node.id] = {
            "entity_type": str(getattr(kind, "value", kind) or ""),
            "label": getattr(node, "label", "") or node.id,
            "severity": str(getattr(node, "severity", "") or ""),
            "risk_score": float(getattr(node, "risk_score", 0.0) or 0.0),
        }
    return meta


def _stored_paths(store: Any, tenant: str, scan_id: str, window: int) -> tuple[list[Any], int]:
    try:
        effective, _created, paths, total = store.attack_paths(tenant_id=tenant, scan_id=scan_id, offset=0, limit=window)
    except NotImplementedError:
        return [], 0
    if effective != scan_id:
        return [], 0
    return list(paths), int(total or 0)


def _revision(store: Any, tenant: str, old: str, new: str, total: int) -> str:
    identities: list[Any] = []
    for scan_id in (old, new):
        try:
            identities.append(list(store.snapshot_identity(tenant_id=tenant, scan_id=scan_id, for_paging=True)))
        except NotImplementedError:
            identities.append([scan_id])
    return hashlib.sha256(json.dumps([identities, total]).encode()).hexdigest()[:32]


_ROWS_CACHE_SIZE = 8
_rows_cache: OrderedDict[tuple[Any, ...], tuple[dict[str, Any], list[dict[str, Any]]]] = OrderedDict()
_rows_cache_lock = threading.Lock()


def _rows_cache_key(store: Any, tenant: str, old: str, new: str) -> tuple[Any, ...] | None:
    """Both snapshot generations are in the key, so a replaced snapshot is never served stale."""
    try:
        generations = tuple(tuple(store.snapshot_identity(tenant_id=tenant, scan_id=scan, for_paging=True)) for scan in (old, new))
    except NotImplementedError:
        return None
    return (id(store), tenant, old, new, generations)


def _compute_rows(store: Any, tenant: str, old: str, new: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    key = _rows_cache_key(store, tenant, old, new)
    if key is not None:
        with _rows_cache_lock:
            cached = _rows_cache.get(key)
            if cached is not None:
                _rows_cache.move_to_end(key)
                return cached
    diff = store.diff_snapshots(old, new, tenant_id=tenant)
    changed = [str(entry) for entry in diff.get("nodes_changed") or [] if not isinstance(entry, dict)]
    result = (diff, diff_rows(diff, changed_node_meta=_changed_node_meta(store, tenant, new, changed)))
    if key is not None:
        with _rows_cache_lock:
            _rows_cache[key] = result
            while len(_rows_cache) > _ROWS_CACHE_SIZE:
                _rows_cache.popitem(last=False)
    return result


def _resolve_node_filter(store: Any, tenant: str, new_id: str, filters: DiffFilters) -> tuple[DiffFilters, str | None]:
    if not filters.node_id:
        return filters, None
    canonical, resolved_from = resolve_snapshot_node_id(store, tenant_id=tenant, scan_id=new_id, node_id=filters.node_id)
    return replace(filters, node_id=canonical), resolved_from


def _resolution(resolved_from: str | None) -> dict[str, str]:
    return {"resolved_from": resolved_from} if resolved_from else {}


async def graph_diff_read(
    request: Request,
    *,
    old: str | None = None,
    new: str | None = None,
    view: str = "summary",
    change: str | None = None,
    kind: str | None = None,
    entity_type: str | None = None,
    relationship: str | None = None,
    node_id: str | None = None,
    limit: int = 50,
    cursor: str | None = None,
) -> dict[str, Any]:
    """Summary (default), filtered detail page, or capped legacy lists for two snapshots."""
    if view not in DIFF_VIEWS:
        raise HTTPException(status_code=422, detail=f"view must be one of: {', '.join(DIFF_VIEWS)}")
    if not 1 <= limit <= DETAIL_MAX_LIMIT:
        raise HTTPException(status_code=422, detail=f"limit must be between 1 and {DETAIL_MAX_LIMIT}")
    filters = DiffFilters(change=change, kind=kind, entity_type=entity_type, relationship=relationship, node_id=node_id)
    invalid = validate_filters(filters)
    if invalid:
        raise HTTPException(status_code=422, detail=invalid)
    tenant = _runtime._tenant(request)
    store = _runtime._get_graph_store_or_503()
    old_id, new_id = await _resolve_pair(store, tenant, old, new)
    filters, resolved_from = await _runtime._graph_store_call(_resolve_node_filter, store, tenant, new_id, filters)
    diff, rows = await _runtime._graph_store_call(_compute_rows, store, tenant, old_id, new_id)
    base: dict[str, Any] = {"schema_version": "v1", "old": old_id, "new": new_id, "view": view, **_resolution(resolved_from)}

    if view == "full":
        payload = await _runtime._graph_compute_call(full_view, diff, rows)
        payload.update(base)
        payload["summary"] = diff_summary(rows, top_n=0)
        payload["completeness"] = graph_completeness(
            returned=payload["returned_changes"],
            total=len(rows),
            truncated=payload["truncated"],
            reason="full_view_cap" if payload["truncated"] else "",
        )
        return payload

    if view == "summary":
        window = attack_path_rank_window()
        old_paths, old_total = await _runtime._graph_store_call(_stored_paths, store, tenant, old_id, window)
        new_paths, new_total = await _runtime._graph_store_call(_stored_paths, store, tenant, new_id, window)
        summary = diff_summary(rows)
        summary["highlights"]["new_attack_paths"] = new_attack_paths(
            old_paths, new_paths, old_total=old_total, new_total=new_total, window=window
        )
        return {
            **base,
            "summary": summary,
            "completeness": graph_completeness(returned=len(rows), total=len(rows)),
        }

    scope = cursor_scope(tenant, old_id, new_id, filters)
    revision = await _runtime._graph_store_call(_revision, store, tenant, old_id, new_id, len(rows))
    offset = 0
    if cursor:
        try:
            continuation = decode_cursor(cursor, scope)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid graph diff cursor; restart from the first page.") from exc
        if continuation["revision"] != revision:
            raise HTTPException(status_code=409, detail="A compared snapshot changed; restart from the first page.")
        offset = continuation["offset"]
    matched = [row for row in rows if filters.matches(row)]
    page, has_more = detail_page(matched, offset=offset, limit=limit)
    next_cursor = encode_cursor(scope, revision, offset + len(page)) if has_more else None
    return {
        **base,
        "filters": filters.active(),
        "total": len(matched),
        "items": page,
        "pagination": {"offset": offset, "limit": limit, "returned": len(page), "has_more": has_more, "next_cursor": next_cursor},
        "completeness": graph_completeness(
            returned=len(page), total=len(matched), truncated=has_more, reason="page_limit" if has_more else ""
        ),
    }


__all__ = ["graph_diff_read"]
