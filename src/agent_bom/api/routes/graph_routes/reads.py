"""Graph lookups: impact, search, clusters, agents, node context, history and presets."""

from __future__ import annotations

from typing import Any, Literal, Optional

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.graph_contracts import GraphIdentifier, IncidentEdgePageResponse, PresetCreate
from agent_bom.api.graph_generation import optional_generation, verify_generation
from agent_bom.api.graph_impact_read import read_node_impact
from agent_bom.api.graph_node_alias import resolve_snapshot_node_id
from agent_bom.api.graph_paging import _enforce_node_offset_cap, _page_meta, page_truncated
from agent_bom.api.neptune_graph import NeptuneGraphStore
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.graph import (
    GraphAgentsResponse,
    GraphClustersResponse,
    GraphComplianceResponse,
    GraphEvidenceManifestResponse,
    GraphHistoryResponse,
    GraphImpactResponse,
    GraphNodeContextResponse,
    GraphPresetsResponse,
    GraphSearchResponse,
    GraphSnapshotsResponse,
    documented_list,
)
from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.api.routes.graph_routes._admission import _GraphAdmissionRoute
from agent_bom.api.routes.graph_routes.params import _parse_entity_type_filter
from agent_bom.api.time_window import MAX_WINDOW_DAYS
from agent_bom.graph import SEVERITY_RANK
from agent_bom.graph.completeness import graph_completeness
from agent_bom.graph.semantic_clusters import SEMANTIC_CLUSTER_KINDS
from agent_bom.graph.view_payloads import _semantic_cluster_payload
from agent_bom.security import sanitize_error

search_router = APIRouter(route_class=_GraphAdmissionRoute)
node_router = APIRouter(route_class=_GraphAdmissionRoute)
history_router = APIRouter(route_class=_GraphAdmissionRoute)
preset_router = APIRouter(route_class=_GraphAdmissionRoute)


@search_router.get("/graph/impact", **documented(GraphImpactResponse), tags=["graph"])
async def get_graph_impact(
    request: Request,
    node: str = Query(..., description="Node ID to compute impact for"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    snapshot_generation: Optional[str] = Query(None, max_length=128),
    max_depth: int = Query(4, ge=1, le=10, description="Maximum reverse BFS depth"),
) -> dict:
    """Compute blast radius of a node — what depends on it?"""
    graph_store = _runtime._get_graph_store_or_503()
    tenant_id = _runtime._tenant(request)
    impact = await _runtime._graph_store_call(
        read_node_impact,
        graph_store,
        tenant_id=tenant_id,
        scan_id=scan_id or "",
        node_id=node,
        max_depth=max_depth,
        snapshot_generation=snapshot_generation,
    )
    if impact is None:
        raise HTTPException(status_code=404, detail=f"Node '{node}' not found")
    identity = impact.pop("_identity")
    if identity:
        await _runtime._graph_store_call(verify_generation, graph_store, tenant=tenant_id, identity=identity, has_rows=True)
    return {**impact, "scan_id": identity[0] if identity else scan_id or ""}


@search_router.get("/graph/search", **documented(GraphSearchResponse), tags=["graph"])
async def search_graph(
    request: Request,
    q: str = Query(..., min_length=1, description="Search query"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    entity_types: Optional[str] = Query(None, description="Comma-separated entity types"),
    min_severity: Optional[str] = Query(None, description="Minimum severity (critical/high/medium/low)"),
    compliance_prefixes: Optional[str] = Query(None, description="Comma-separated compliance prefixes"),
    data_sources: Optional[str] = Query(None, description="Comma-separated data sources"),
    snapshot_generation: Optional[str] = Query(None, max_length=128, description="Read revision from the first page"),
    cursor: Optional[str] = Query(None, description="Opaque cursor for keyset search pagination"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
) -> dict:
    """Search graph nodes by label, type, tags, and attributes."""
    _enforce_node_offset_cap(offset, cursor)
    graph_store = _runtime._get_graph_store_or_503()
    tenant_id = _runtime._tenant(request)
    if scan_id:
        (scan_id,) = await _runtime.require_graph_snapshot_ids(graph_store, tenant_id, scan_id)
    identity = await _runtime._graph_store_call(
        optional_generation,
        graph_store,
        tenant=tenant_id,
        scan_id=scan_id or "",
        generation=snapshot_generation,
        offset=offset or int(bool(cursor)),
    )
    if identity is not None:
        scan_id = identity[0]
    entity_type_filters = _parse_entity_type_filter(entity_types)
    min_rank = SEVERITY_RANK.get(min_severity.lower(), 0) if min_severity else 0
    prefix_filters = {value.strip().upper() for value in compliance_prefixes.split(",") if value.strip()} if compliance_prefixes else None
    data_source_filters = {value.strip() for value in data_sources.split(",") if value.strip()} if data_sources else None
    try:
        results, total, next_cursor = await _runtime._graph_store_call(
            graph_store.search_nodes,
            scan_id=scan_id or "",
            tenant_id=_runtime._tenant(request),
            query=q,
            entity_types=entity_type_filters,
            min_severity_rank=min_rank,
            compliance_prefixes=prefix_filters,
            data_sources=data_source_filters,
            cursor=cursor,
            offset=offset,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    if identity is not None:
        await _runtime._graph_store_call(verify_generation, graph_store, tenant=tenant_id, identity=identity, has_rows=bool(results))
    return {
        "snapshot_generation": identity[1] if identity else None,
        "query": q,
        "filters": {
            "scan_id": scan_id or "",
            "entity_types": sorted(entity_type_filters) if entity_type_filters else [],
            "min_severity": min_severity or "",
            "compliance_prefixes": sorted(prefix_filters) if prefix_filters else [],
            "data_sources": sorted(data_source_filters) if data_source_filters else [],
        },
        "results": [n.to_dict() for n in results],
        "pagination": {
            "total": total,
            "offset": offset,
            "limit": limit,
            "cursor": cursor or "",
            "next_cursor": next_cursor or "",
            "has_more": bool(next_cursor) if cursor else offset + limit < total,
        },
        "completeness": graph_completeness(
            returned=len(results),
            total=total,
            truncated=page_truncated(cursor=cursor, next_cursor=next_cursor, offset=offset, returned=len(results), total=total),
            reason="search_page_limit"
            if page_truncated(cursor=cursor, next_cursor=next_cursor, offset=offset, returned=len(results), total=total)
            else "",
        ),
    }


@search_router.get("/graph/clusters", **documented(GraphClustersResponse), tags=["graph"])
async def get_graph_clusters(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan snapshot ID; latest if omitted"),
    kinds: Optional[str] = Query(None, description="Comma-separated semantic cluster kinds"),
    min_members: int = Query(2, ge=1, le=100, description="Minimum members required to emit a cluster"),
    limit: int = Query(250, ge=1, le=1000, description="Maximum clusters to return"),
) -> dict:
    """Return API-backed semantic clusters for graph readability.

    The response is intentionally reversible: each cluster carries member IDs
    and expansion metadata so the dashboard can collapse and expand topology
    without deriving families client-side.
    """

    tenant = _runtime._tenant(request)
    graph_store = _runtime._get_graph_store_or_503()
    requested_scan_id = scan_id or ""
    if not requested_scan_id and not await _runtime._graph_store_call(
        graph_store.latest_snapshot_id,
        tenant_id=tenant,
        snapshot_kind="scan",
    ):
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")

    selected_kinds = {kind.strip() for kind in kinds.split(",") if kind.strip()} if kinds else set(SEMANTIC_CLUSTER_KINDS)
    unknown_kinds = selected_kinds - set(SEMANTIC_CLUSTER_KINDS)
    if unknown_kinds:
        raise HTTPException(status_code=400, detail=f"Unknown semantic cluster kind(s): {', '.join(sorted(unknown_kinds))}")

    graph = await _runtime._graph_store_call(
        graph_store.load_graph,
        scan_id=requested_scan_id,
        tenant_id=tenant,
    )
    return await _runtime._graph_compute_call(
        _semantic_cluster_payload, graph, selected_kinds=selected_kinds, min_members=min_members, limit=limit
    )


@search_router.get("/graph/agents", **documented(GraphAgentsResponse), tags=["graph"])
async def list_graph_agents(
    request: Request,
    q: str = Query("", description="Optional agent label/id search"),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    snapshot_generation: Optional[str] = Query(None, max_length=128, description="Read revision from the first page"),
    cursor: Optional[str] = Query(None, description="Opaque cursor for keyset pagination"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=500, description="Max agents"),
) -> dict:
    """List agent nodes for large-graph selectors without loading the full graph."""
    _enforce_node_offset_cap(offset, cursor)
    graph_store = _runtime._get_graph_store_or_503()
    tenant_id = _runtime._tenant(request)
    identity = await _runtime._graph_store_call(
        optional_generation,
        graph_store,
        tenant=tenant_id,
        scan_id=scan_id or "",
        generation=snapshot_generation,
        offset=offset or int(bool(cursor)),
    )
    if identity is not None:
        scan_id = identity[0]
    query = q.strip()
    if query:
        agents, total, next_cursor = await _runtime._graph_store_call(
            graph_store.search_nodes,
            scan_id=scan_id or "",
            tenant_id=tenant_id,
            query=query,
            entity_types={"agent"},
            cursor=cursor,
            offset=offset,
            limit=limit,
        )
        effective_scan_id = scan_id or await _runtime._graph_store_call(
            graph_store.latest_snapshot_id,
            tenant_id=tenant_id,
            snapshot_kind="scan",
        )
        created_at = ""
    else:
        effective_scan_id, created_at, agents, total, next_cursor = await _runtime._graph_store_call(
            graph_store.page_nodes,
            scan_id=scan_id or "",
            tenant_id=tenant_id,
            entity_types={"agent"},
            cursor=cursor,
            offset=offset,
            limit=limit,
        )
    if identity is not None:
        await _runtime._graph_store_call(verify_generation, graph_store, tenant=tenant_id, identity=identity, has_rows=bool(agents))
    return {
        "snapshot_generation": identity[1] if identity else None,
        "scan_id": effective_scan_id,
        "tenant_id": tenant_id,
        "created_at": created_at,
        "agents": [
            {
                "id": node.id,
                "label": node.label,
                "risk_score": node.risk_score,
                "risk_assessment": node.risk_assessment,
                "severity": node.severity,
                "status": node.status.value if hasattr(node.status, "value") else str(node.status),
                "data_sources": node.data_sources,
                "first_seen": node.first_seen,
                "last_seen": node.last_seen,
            }
            for node in agents
        ],
        "pagination": _page_meta(total, offset, limit, cursor=cursor, next_cursor=next_cursor),
        "completeness": graph_completeness(
            returned=len(agents),
            total=total,
            truncated=(more := page_truncated(cursor=cursor, next_cursor=next_cursor, offset=offset, returned=len(agents), total=total)),
            reason="agent_page_limit" if more else "",
        ),
    }


@node_router.get("/graph/node-context", **documented(GraphNodeContextResponse), tags=["graph"])
@node_router.get("/graph/node/{node_id:path}", **documented(GraphNodeContextResponse), tags=["graph"])
async def get_graph_node(
    request: Request,
    node_id: GraphIdentifier,
    scan_id: Optional[GraphIdentifier] = Query(None, description="Scan ID"),
    snapshot_generation: Optional[str] = Query(None, max_length=128),
) -> dict:
    """Get a single node with its edges, neighbors, and impact stats."""
    graph_store = _runtime._get_graph_store_or_503()
    tenant_id = _runtime._tenant(request)
    identity = await _runtime._graph_store_call(
        optional_generation, graph_store, tenant=tenant_id, scan_id=scan_id or "", generation=snapshot_generation, offset=0
    )
    effective_scan_id = identity[0] if identity else scan_id or ""
    read_id, resolved_from = await _runtime._graph_store_call(
        resolve_snapshot_node_id, graph_store, tenant_id=tenant_id, scan_id=effective_scan_id, node_id=node_id
    )
    node_context = await _runtime._graph_store_call(
        graph_store.node_context,
        scan_id=effective_scan_id,
        tenant_id=tenant_id,
        node_id=read_id,
    )
    if node_context is None:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found")

    if identity:
        await _runtime._graph_store_call(verify_generation, graph_store, tenant=tenant_id, identity=identity, has_rows=True)
    return {
        "scan_id": identity[0] if identity else scan_id or "",
        "tenant_id": tenant_id,
        "snapshot_generation": identity[1] if identity else None,
        "node": node_context["node"].to_dict(),
        "edges_out": [edge.to_dict() for edge in node_context["edges_out"]],
        "edges_in": [edge.to_dict() for edge in node_context["edges_in"]],
        "neighbors": node_context["neighbors"],
        "sources": node_context["sources"],
        "impact": node_context["impact"],
        "completeness": node_context.get("completeness") or graph_completeness(returned=1, total=1),
        "resolved_from": resolved_from,
    }


@node_router.get("/graph/incident-edges", tags=["graph"], response_model=IncidentEdgePageResponse)
async def get_graph_incident_edges(
    request: Request,
    node_id: GraphIdentifier = Query(..., min_length=1, max_length=4096, pattern=r"^[^\x00]*$", description="Exact canonical node ID"),
    scan_id: GraphIdentifier | None = Query(
        None,
        max_length=4096,
        description=(
            "Historical scan ID; omitted selects the current tenant estate. Reuse the returned ID and generation for subsequent pages."
        ),
    ),
    snapshot_generation: str | None = Query(
        None, pattern="^[a-f0-9]{32}$", description="Expected generation returned by the initial page; reuse on every node expansion."
    ),
    direction: Literal["in", "out", "both"] = Query(
        "both", description="Filter recorded target/source endpoints; not effective permissions."
    ),
    limit: int = Query(24, ge=1, le=100, description="Maximum recorded relationships, not distinct neighbors"),
    cursor: str | None = Query(
        None, min_length=1, max_length=8192, description="Opaque next_cursor from the same tenant, snapshot, node and direction"
    ),
) -> dict[str, Any]:
    """Page recorded incident relationships without loading the full neighborhood.

    Reuse scan_id and snapshot_generation on every node expansion; keep node_id and direction fixed while following next_cursor.
    Snapshot replacement invalidates cursors (400: restart). A replaced id resolves to its canonical node, echoed as resolved_from.
    Completeness covers only recorded page rows, never collection, permissions, execution or the estate; the total is unknown.
    """
    store = _runtime._get_graph_store_or_503()
    if isinstance(store, NeptuneGraphStore):
        raise HTTPException(status_code=501, detail="Incident relationship paging is not supported by this graph backend")
    tenant_id = _runtime._tenant(request)
    read_id, resolved_from = await _runtime._graph_store_call(
        resolve_snapshot_node_id, store, tenant_id=tenant_id, scan_id=scan_id or "", node_id=node_id
    )
    try:
        page = await _runtime._graph_store_call(
            store.incident_edges_page,
            tenant_id=tenant_id,
            scan_id=scan_id or "",
            node_id=read_id,
            direction=direction,
            limit=limit,
            cursor=cursor,
            snapshot_generation=snapshot_generation,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid or stale incident relationship page; restart from the first page") from exc
    if page is None:
        return {
            "scan_id": scan_id or "",
            "snapshot_generation": None,
            "node_id": node_id,
            "found": False,
            "direction": direction,
            "limit": limit,
            "node": None,
            "nodes": [],
            "edges": [],
            "next_cursor": None,
            "completeness": {
                **graph_completeness(returned=0, truncated=True, reason="node_or_snapshot_not_found"),
                "scope": "incident_edge_page",
                "missing_endpoint_count": 0,
            },
        }
    return {
        "scan_id": page["scan_id"],
        "evidence_scope": "current_estate" if page["scan_id"].startswith("current-estate:") else "historical_scan",
        "snapshot_generation": page["snapshot_generation"],
        "node_id": read_id,
        "resolved_from": resolved_from,
        "found": True,
        "direction": direction,
        "limit": limit,
        "node": page["node"].to_dict(),
        "nodes": [node.to_dict() for node in page["nodes"]],
        "edges": [edge.to_dict() for edge in page["edges"]],
        "next_cursor": page["next_cursor"],
        "completeness": page["completeness"],
    }


@history_router.get("/graph/snapshots", **documented_list(GraphSnapshotsResponse), tags=["graph"])
async def get_graph_snapshots(
    request: Request,
    limit: int = Query(50, ge=1, le=500, description="Max snapshots"),
    window_days: int | None = Query(None, ge=0, le=MAX_WINDOW_DAYS, description="Default read-window in days; 0 = all retained history"),
) -> list[dict]:
    """List persisted scan snapshots ordered by creation time.

    Defaults to the last ``AGENT_BOM_RETENTION_DAYS`` (≈90d) so the picker shows
    recent, non-stale history; pass ``?window_days=0`` to widen to all retained
    snapshots (#4009).

    A snapshot's ``risk_summary`` is a per-scan count of *graph nodes* carrying
    each severity — a distinct metric from the exec open-finding headline
    (``/v1/overview`` / ``/v1/posture/counts``), which counts deduped findings
    across the estate. Each row is tagged ``severity_basis: "graph_nodes"`` so a
    consumer never mistakes the graph-node tally for the reconciled exec
    severity count (#3961).
    """
    from agent_bom.api import time_window

    since = time_window.window_since_iso(time_window.normalize_window_days(window_days))
    snapshots = await _runtime._graph_store_call(
        _runtime._get_graph_store_or_503().list_snapshots, tenant_id=_runtime._tenant(request), limit=limit, since=since
    )
    for snapshot in snapshots:
        if isinstance(snapshot, dict) and "risk_summary" in snapshot:
            snapshot["severity_basis"] = "graph_nodes"
    return snapshots


@history_router.get("/graph/history", **documented(GraphHistoryResponse), tags=["graph"])
async def get_graph_history(
    request: Request,
    limit: int = Query(50, ge=1, le=500, description="Max snapshots"),
    window_days: int | None = Query(None, ge=0, le=MAX_WINDOW_DAYS, description="Default read-window in days; 0 = all retained history"),
) -> dict:
    """Return retained graph history and adjacent diff summaries for the request tenant.

    Defaults to the last ``AGENT_BOM_RETENTION_DAYS`` (≈90d); the applied window
    is echoed under ``window`` so clients can label it honestly (#4009).
    """
    from agent_bom.api import time_window

    resolved = time_window.normalize_window_days(window_days)
    since = time_window.window_since_iso(resolved)
    history = await _runtime._graph_store_call(
        _runtime._get_graph_store_or_503().graph_history, tenant_id=_runtime._tenant(request), limit=limit, since=since
    )
    if isinstance(history, dict):
        history["window"] = time_window.window_metadata(resolved)
    return history


@history_router.get("/graph/evidence-manifest", **documented(GraphEvidenceManifestResponse), tags=["graph"])
async def get_graph_evidence_manifest(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan snapshot ID; latest if omitted"),
    baseline_scan_id: Optional[str] = Query(None, description="Optional diff baseline scan ID"),
) -> dict:
    """Return a redaction-aware reviewer manifest for a retained graph snapshot."""
    manifest = await _runtime._graph_store_call(
        _runtime._get_graph_store_or_503().evidence_manifest,
        tenant_id=_runtime._tenant(request),
        scan_id=scan_id or "",
        baseline_scan_id=baseline_scan_id or "",
    )
    if not manifest.get("scan_id"):
        raise HTTPException(status_code=404, detail="Graph snapshot not found")
    return manifest


@history_router.get("/graph/compliance", **documented(GraphComplianceResponse), tags=["graph"])
async def get_graph_compliance(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    framework: Optional[str] = Query(None, description="Filter by framework prefix (e.g. OWASP, NIST, MITRE, CIS, SOC2)"),
) -> dict:
    """Compliance posture across all frameworks — aggregated from graph nodes.

    Returns per-framework finding counts, severity breakdown, affected entity
    counts, and the list of tagged findings. Filter by framework to drill down.
    """
    graph_store = _runtime._get_graph_store_or_503()
    tenant = _runtime._tenant(request)
    if scan_id:
        (scan_id,) = await _runtime.require_graph_snapshot_ids(graph_store, tenant, scan_id)
    return await _runtime._graph_store_call(
        graph_store.compliance_summary,
        scan_id=scan_id or "",
        tenant_id=tenant,
        framework=framework or "",
    )


@preset_router.post("/graph/presets", tags=["graph"])
async def create_preset(request: Request, body: PresetCreate) -> dict:
    """Save a named graph filter preset for the current tenant."""
    from agent_bom.graph.util import _now_iso

    tenant = _runtime._tenant(request)
    await _runtime._graph_store_call(
        _runtime._get_graph_store_or_503().save_preset,
        tenant_id=tenant,
        name=body.name,
        description=body.description,
        filters=body.filters,
        created_at=_now_iso(),
    )
    return {"name": body.name, "status": "saved"}


@preset_router.get("/graph/presets", **documented_list(GraphPresetsResponse), tags=["graph"])
async def list_presets(request: Request) -> list[dict]:
    """List saved filter presets for the current tenant."""
    return await _runtime._graph_store_call(_runtime._get_graph_store_or_503().list_presets, tenant_id=_runtime._tenant(request))


@preset_router.delete("/graph/presets/{name}", tags=["graph"])
async def delete_preset(request: Request, name: str) -> dict:
    """Delete a saved filter preset."""
    deleted = await _runtime._graph_store_call(
        _runtime._get_graph_store_or_503().delete_preset, tenant_id=_runtime._tenant(request), name=name
    )
    if not deleted:
        raise HTTPException(status_code=404, detail=f"Preset '{name}' not found")
    return {"name": name, "status": "deleted"}
