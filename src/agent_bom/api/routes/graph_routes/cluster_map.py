"""``GET /v1/graph/cluster-map``: the grouped full map of one snapshot."""

from __future__ import annotations

import re
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.graph_cluster_index_cache import cluster_index
from agent_bom.api.graph_generation import optional_generation, snapshot_fingerprint, verify_generation
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.graph_cluster_map import GraphClusterMapResponse
from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.api.routes.graph_routes._admission import _GraphAdmissionRoute
from agent_bom.graph.cluster_map import DEFAULT_MEMBER_LIMIT, MAX_EXPANDED, MAX_MEMBER_LIMIT, cluster_map_view

router = APIRouter(route_class=_GraphAdmissionRoute)

_ID_PATTERN = r"^[^\x00]*$"
_PAGE_PATTERN = r"^\d{1,7}:[^\x00]+$"


def _pages(values: list[str]) -> dict[str, int]:
    """``offset:group-id`` pairs; the group id may itself contain colons."""
    pages: dict[str, int] = {}
    for value in values:
        offset, _, group = value.partition(":")
        pages[group] = int(offset)
    return pages


@router.get("/graph/cluster-map", **documented(GraphClusterMapResponse), tags=["graph"])
async def get_graph_cluster_map(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan snapshot ID; latest if omitted", max_length=512, pattern=_ID_PATTERN),
    snapshot_generation: Optional[str] = Query(
        None, max_length=128, description="Generation from an earlier frame; a replaced snapshot answers 409"
    ),
    expand: list[str] = Query(
        default_factory=list,
        max_length=MAX_EXPANDED,
        description="Group ids (from `nodes[].id`) to show expanded: top members by risk plus a '+K more' pager",
    ),
    page: list[str] = Query(
        default_factory=list,
        max_length=MAX_EXPANDED,
        description="Member page of an expanded group as `offset:group-id`, from a '+K more' node's next/prev offset",
    ),
    risky_only: bool = Query(False, description="Only groups on an attack path or holding a critical or high finding"),
    focus: Optional[str] = Query(
        None, max_length=512, pattern=_ID_PATTERN, description="Node id to show: its group opens and the node is drawn"
    ),
    member_limit: int = Query(DEFAULT_MEMBER_LIMIT, ge=1, le=MAX_MEMBER_LIMIT, description="Members shown per expanded group"),
) -> dict:
    """Collapse the snapshot into groups along the estate's tiers and types, with bundled edges.

    Groups follow scope, agents, MCP servers and tools, packages by ecosystem,
    findings by severity, identities and credentials, then cloud and data
    resources by type. Each drawn edge carries the exact count of underlying
    edges per relationship; what is not drawn is counted in ``summary``. The
    first frame draws at most ``summary.element_budget`` nodes plus edges.
    Risky groups (on an attack path, or holding a critical or high finding)
    are ranked first. Read-only and bounded; answered from a per-snapshot
    aggregation built once per generation.
    """
    for value in page:
        if len(value) > 600 or re.match(_PAGE_PATTERN, value) is None:
            raise HTTPException(status_code=422, detail="page must be `offset:group-id`")
    tenant = _runtime._tenant(request)
    graph_store = _runtime._get_graph_store_or_503()
    requested_scan_id = scan_id or ""
    if not requested_scan_id and not await _runtime._graph_store_call(
        graph_store.latest_snapshot_id, tenant_id=tenant, snapshot_kind="scan"
    ):
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")

    identity = await _runtime._graph_store_call(
        optional_generation, graph_store, tenant=tenant, scan_id=requested_scan_id, generation=snapshot_generation, offset=0
    )
    cache_identity = identity or await _runtime._graph_store_call(
        snapshot_fingerprint, graph_store, tenant=tenant, scan_id=requested_scan_id
    )
    resolved_scan_id = cache_identity[0] if cache_identity else requested_scan_id
    # An unexpected failure reaches the app's generic 500 handler, which returns no exception detail.
    index = await _runtime._graph_compute_call(
        cluster_index, graph_store, tenant_id=tenant, scan_id=resolved_scan_id, identity=cache_identity
    )
    if identity is not None:
        await _runtime._graph_store_call(verify_generation, graph_store, tenant=tenant, identity=identity, has_rows=bool(index.ids))
    payload = await _runtime._graph_compute_call(
        cluster_map_view, index, expanded=expand, pages=_pages(page), risky_only=risky_only, focus=focus, member_limit=member_limit
    )
    if not index.ids and not resolved_scan_id:
        raise HTTPException(status_code=404, detail="Graph snapshot not found")
    return {
        "scan_id": resolved_scan_id,
        "tenant_id": tenant,
        "snapshot_generation": identity[1] if identity else None,
        **payload,
    }


__all__ = ["router"]
