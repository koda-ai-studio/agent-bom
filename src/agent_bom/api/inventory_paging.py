"""Generation-pinned inventory asset pages shared by ``/v1/inventory/assets`` and MCP ``inventory_list``.

The keyset cursor carries the snapshot generation it continues (the ``g1.``
envelope ``/v1/graph`` uses), so a continuation against a replaced snapshot is
a 409 even when the caller sends only the cursor; a malformed cursor is a 422.
Imports stay free of FastAPI because the MCP server runs without the API extra.
"""

from __future__ import annotations

from typing import Any

from starlette.exceptions import HTTPException

from agent_bom.api.graph_node_cursor import continue_node_cursor, wrap_node_cursor
from agent_bom.api.graph_scan_ids import resolve_graph_scan_id
from agent_bom.api.inventory_service import InventoryError, StoreCall, build_asset_list, default_store_call

_CHANGED = "Graph snapshot changed; restart the query from its first page."


def _decode_cursor(cursor: str | None, snapshot_generation: str | None) -> tuple[str | None, str | None]:
    try:
        return continue_node_cursor(cursor, snapshot_generation)
    except HTTPException as exc:
        raise InventoryError(str(exc.detail), status_code=exc.status_code) from exc


def _identity(store: Any, *, tenant_id: str, scan_id: str) -> tuple[str, str] | None:
    reader = getattr(store, "snapshot_identity", None)
    if not callable(reader):
        return None
    try:
        return reader(tenant_id=tenant_id, scan_id=resolve_graph_scan_id(tenant_id, scan_id), for_paging=True)
    except NotImplementedError:
        return None


async def _pin(
    store: Any, store_call: StoreCall, *, tenant_id: str, scan_id: str, generation: str | None, continuing: bool
) -> tuple[str, str] | None:
    identity = await store_call(_identity, store, tenant_id=tenant_id, scan_id=scan_id)
    if identity is None:
        if continuing or generation is not None:
            raise InventoryError("Generation-pinned pages require SQLite or Postgres.", status_code=501)
        return None
    if continuing and not generation:
        raise InventoryError("Continuation requires snapshot_generation from the first page; restart the query.", status_code=422)
    if generation is not None and generation != identity[1]:
        raise InventoryError(_CHANGED, status_code=409)
    return identity


async def build_pinned_asset_list(
    *,
    store: Any,
    tenant_id: str,
    scan_id: str | None,
    cursor: str | None,
    snapshot_generation: str | None,
    offset: int,
    store_call: StoreCall = default_store_call,
    **filters: Any,
) -> dict[str, Any]:
    """One inventory page pinned to a snapshot generation; its ``next_cursor`` carries that generation."""
    if cursor and offset:
        raise InventoryError("cursor replaces offset; send only the cursor.", status_code=400)
    store_cursor, generation = _decode_cursor(cursor, snapshot_generation)
    identity = await _pin(store, store_call, tenant_id=tenant_id, scan_id=scan_id or "", generation=generation, continuing=bool(cursor))
    body = await build_asset_list(
        store=store,
        tenant_id=tenant_id,
        scan_id=identity[0] if identity else scan_id,
        cursor=store_cursor,
        offset=offset,
        store_call=store_call,
        **filters,
    )
    if identity is None:
        return body
    current = await store_call(_identity, store, tenant_id=tenant_id, scan_id=identity[0])
    if current != identity or (body.get("assets") and not identity[1]):
        raise InventoryError("Graph snapshot changed during the read; restart the query from its first page.", status_code=409)
    body["snapshot_generation"] = body.get("snapshot_generation") or identity[1]
    pagination = body["pagination"]
    pagination["cursor"] = cursor or ""
    pagination["next_cursor"] = wrap_node_cursor(pagination.get("next_cursor") or None, identity[1]) or ""
    return body
