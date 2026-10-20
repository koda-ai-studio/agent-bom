"""Graph query API — unified graph data with filters, pagination, RBAC, presets.

Endpoints:
  GET  /v1/graph                — load unified graph (filtered, paginated)
  GET  /v1/graph/diff           — diff between two scan snapshots
  GET  /v1/graph/edges/active   — edge versions active at a timestamp
  GET  /v1/graph/edges/changes  — edge lifecycle changes between scans
  GET  /v1/graph/attack-paths   — global risk-sorted attack path queue
  GET  /v1/graph/exposure-paths — agent-native ExposurePath queue
  POST /v1/graph/should-i-deploy — agent-native deploy decision
  GET  /v1/graph/paths          — attack paths from a source node
  GET  /v1/graph/impact         — blast radius of a node (reverse BFS)
  GET  /v1/graph/rollup         — estate-scale CONTAINS roll-up + drill-down
  GET  /v1/graph/search         — full-text graph search
  GET  /v1/graph/agents         — paginated agent node selector
  GET  /v1/graph/clusters       — semantic cluster rollups
  POST /v1/graph/query          — programmable traversal query
  GET  /v1/graph/node/{id}      — single node detail with edges + impact
  GET  /v1/graph/snapshots      — list persisted scan snapshots
  GET  /v1/graph/history        — retained snapshot history with adjacent diffs
  GET  /v1/graph/evidence-manifest — reviewer manifest for one graph snapshot
  GET  /v1/graph/legend         — entity + relationship legends
  GET  /v1/graph/schema         — canonical entity/edge taxonomy (codegen source)
  POST /v1/graph/presets        — save a filter preset
  GET  /v1/graph/presets        — list saved presets
  DEL  /v1/graph/presets/{name} — delete a preset

This module owns ``router`` and the traversal-heavy routes; the remaining
routes live in ``agent_bom.api.routes.graph_routes`` and are included here in
their original registration order. Every former module-level name stays
importable from this module.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from starlette.responses import Response

from agent_bom.api.graph_contracts import (
    _ATTACK_PATH_ITEM_OPENAPI_SCHEMA as _ATTACK_PATH_ITEM_OPENAPI_SCHEMA,
)
from agent_bom.api.graph_contracts import (
    _ATTACK_PATHS_OPENAPI_RESPONSE as _ATTACK_PATHS_OPENAPI_RESPONSE,
)
from agent_bom.api.graph_contracts import (
    _EXPOSURE_PATH_OPENAPI_SCHEMA as _EXPOSURE_PATH_OPENAPI_SCHEMA,
)
from agent_bom.api.graph_contracts import (
    _FIX_FIRST_VIEW_OPENAPI_RESPONSE as _FIX_FIRST_VIEW_OPENAPI_RESPONSE,
)
from agent_bom.api.graph_contracts import (
    _TECHNIQUE_MAPPING_OPENAPI_SCHEMA as _TECHNIQUE_MAPPING_OPENAPI_SCHEMA,
)
from agent_bom.api.graph_contracts import (
    GraphCompletenessResponse as GraphCompletenessResponse,
)
from agent_bom.api.graph_contracts import (
    GraphDeployDecisionRequest as GraphDeployDecisionRequest,
)
from agent_bom.api.graph_contracts import (
    GraphIdentifier as GraphIdentifier,
)
from agent_bom.api.graph_contracts import (
    GraphScopeDescriptor as GraphScopeDescriptor,
)
from agent_bom.api.graph_contracts import (
    IncidentEdgePageCompleteness as IncidentEdgePageCompleteness,
)
from agent_bom.api.graph_contracts import (
    IncidentEdgePageResponse as IncidentEdgePageResponse,
)
from agent_bom.api.graph_contracts import (
    PresetCreate as PresetCreate,
)
from agent_bom.api.graph_contracts import (
    ScopedGraphCompleteness as ScopedGraphCompleteness,
)
from agent_bom.api.graph_contracts import (
    ScopedGraphResponse as ScopedGraphResponse,
)
from agent_bom.api.graph_generation import optional_generation, snapshot_fingerprint, verify_generation
from agent_bom.api.graph_page_context import page_attack_context, page_context
from agent_bom.api.graph_paging import _coalesce_alias, _enforce_node_offset_cap, _paginate, path_order
from agent_bom.api.graph_presentation import (
    _finding_ids_for_path as _finding_ids_for_path,
)
from agent_bom.api.graph_presentation import (
    _finding_labels_for_path as _finding_labels_for_path,
)
from agent_bom.api.graph_presentation import (
    _first_href_for_agent as _first_href_for_agent,
)
from agent_bom.api.graph_presentation import (
    _fix_first_card_for_path as _fix_first_card_for_path,
)
from agent_bom.api.graph_presentation import (
    _identity_finding_ids_for_path as _identity_finding_ids_for_path,
)
from agent_bom.api.graph_presentation import (
    _next_actions_for_path as _next_actions_for_path,
)
from agent_bom.api.graph_presentation import (
    _node_ids_for_types as _node_ids_for_types,
)
from agent_bom.api.graph_presentation import (
    _node_labels_for_types as _node_labels_for_types,
)
from agent_bom.api.graph_presentation import (
    _path_identity as _path_identity,
)
from agent_bom.api.graph_presentation import (
    _path_matches_focus as _path_matches_focus,
)
from agent_bom.api.graph_presentation import (
    _path_semantic_key as _path_semantic_key,
)
from agent_bom.api.graph_presentation import (
    _risk_reasons_for_path as _risk_reasons_for_path,
)
from agent_bom.api.graph_presentation import (
    _serialize_attack_path as _serialize_attack_path,
)
from agent_bom.api.graph_presentation import (
    _serialize_attack_path_batch as _serialize_attack_path_batch,
)
from agent_bom.api.graph_query import GraphQueryRequest, _filtered_query_graph, query_payload
from agent_bom.api.graph_rollup_prewarm import load_rollup_source, rollup_cache_key
from agent_bom.api.graph_store import containment_drilldown_graph as containment_drilldown_graph
from agent_bom.api.neptune_graph import NeptuneGraphStore
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.graph import GraphNodeNeighborsResponse, GraphPageResponse, GraphPathsResponse, GraphRollupResponse
from agent_bom.api.routes.graph_routes import _runtime, reads, schema_routes, views
from agent_bom.api.routes.graph_routes._admission import _GraphAdmissionRoute
from agent_bom.api.routes.graph_routes._runtime import _get_graph_store_or_503 as _get_graph_store_or_503
from agent_bom.api.routes.graph_routes._runtime import _graph_compute_call as _graph_compute_call
from agent_bom.api.routes.graph_routes._runtime import _graph_store_call as _graph_store_call
from agent_bom.api.routes.graph_routes._runtime import _tenant as _tenant
from agent_bom.api.routes.graph_routes.params import _FILTERED_GRAPH_ATTACK_PATH_LIMIT as _FILTERED_GRAPH_ATTACK_PATH_LIMIT
from agent_bom.api.routes.graph_routes.params import (
    _GRAPH_QUERY_ABSOLUTE_LIMITS,
    _GRAPH_QUERY_DEFAULT_BUDGET,
    _parse_entity_type_filter,
    _parse_relationship_filter,
    _validate_entity_type_list,
    _validate_relationship_list,
)
from agent_bom.api.routes.graph_routes.params import _raise_mcp_error_as_http as _raise_mcp_error_as_http
from agent_bom.api.routes.graph_routes.payloads import (
    _NODE_PAGE_EDGE_LIMIT,
    _encode_node_page,
    _encoded_graph_response,
    _overlay_filter_and_respond,
)
from agent_bom.api.routes.graph_routes.payloads import _filtered_graph_response as _filtered_graph_response
from agent_bom.api.routes.graph_routes.payloads import _fix_first_graph_view_payload as _fix_first_graph_view_payload
from agent_bom.api.routes.graph_routes.payloads import _governance_graph_payload as _governance_graph_payload
from agent_bom.api.routes.graph_routes.schema_routes import _RESERVED_GRAPH_EDGE_KINDS as _RESERVED_GRAPH_EDGE_KINDS
from agent_bom.api.routes.graph_routes.schema_routes import _RESERVED_GRAPH_NODE_KINDS as _RESERVED_GRAPH_NODE_KINDS
from agent_bom.api.stores import _get_graph_store as _get_graph_store
from agent_bom.cloud.runtime_graph_evidence import _enrich_loaded_graph_runtime_evidence as _enrich_loaded_graph_runtime_evidence
from agent_bom.config import GRAPH_INVESTIGATION_NODE_BUDGET
from agent_bom.graph import (
    SEVERITY_RANK,
    GraphFilterOptions,
)
from agent_bom.graph.completeness import graph_completeness
from agent_bom.graph.exposure import _exposure_path_for_attack_path as _exposure_path_for_attack_path
from agent_bom.graph.exposure import _exposure_ref_for_node as _exposure_ref_for_node
from agent_bom.graph.exposure import _finding_ids_for_nodes as _finding_ids_for_nodes
from agent_bom.graph.path_derivation import _derived_attack_paths as _derived_attack_paths
from agent_bom.graph.path_derivation import _derived_governance_attack_paths as _derived_governance_attack_paths
from agent_bom.graph.path_derivation import _derived_toxic_combination_paths as _derived_toxic_combination_paths
from agent_bom.graph.path_derivation import _fusion_signals_for_path as _fusion_signals_for_path
from agent_bom.graph.rollup import ROLLUP_RELATIONSHIPS
from agent_bom.graph.view_payloads import _graph_rollup_payload
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


router = APIRouter(route_class=_GraphAdmissionRoute)


router.include_router(views.compromise_router)


def _bounded_env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return min(max(value, minimum), maximum)


def _graph_query_budget() -> dict[str, int]:
    """Return the deployer-configured graph traversal budget.

    Pydantic keeps absolute request ceilings. This budget is the lower,
    operator-tunable resource control used by the traversal endpoint.
    """
    return {
        key: _bounded_env_int(
            f"AGENT_BOM_GRAPH_QUERY_{key.upper()}",
            default,
            minimum=1 if key != "timeout_ms" else 100,
            maximum=_GRAPH_QUERY_ABSOLUTE_LIMITS[key],
        )
        for key, default in _GRAPH_QUERY_DEFAULT_BUDGET.items()
    }


def _apply_graph_query_budget(body: GraphQueryRequest) -> tuple[GraphQueryRequest, dict[str, int], dict[str, dict[str, int]]]:
    """Clamp a request to the deployment budget and say what was clamped.

    The schema publishes the absolute ceilings; the budget is lower and set per
    deployment, so a request between the two is served at the budget with the
    clamp disclosed in ``budget_applied`` rather than rejected against limits
    the published contract allows.
    """
    budget = _graph_query_budget()
    requested = {
        "max_depth": body.max_depth,
        "max_nodes": body.max_nodes,
        "max_edges": body.max_edges,
        "timeout_ms": body.timeout_ms,
    }
    applied = {key: {"requested": value, "applied": budget[key]} for key, value in requested.items() if value > budget[key]}
    if applied:
        body = body.model_copy(update={key: value["applied"] for key, value in applied.items()})
    return body, budget, applied


@router.get("/graph", **documented(GraphPageResponse), tags=["graph"])
async def get_graph(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Filter by scan ID"),
    scan: Optional[str] = Query(None, description="Alias for scan_id"),
    entity_types: Optional[str] = Query(None, description="Comma-separated entity types"),
    min_severity: Optional[str] = Query(None, description="Minimum severity (critical/high/medium/low)"),
    relationships: Optional[str] = Query(None, description="Comma-separated relationship types"),
    static_only: bool = Query(False, description="Exclude runtime edges"),
    dynamic_only: bool = Query(False, description="Only runtime edges"),
    max_depth: Optional[int] = Query(None, ge=1, le=20, description="Max traversal depth"),
    snapshot_generation: Optional[str] = Query(None, max_length=128, description="Read revision from the first page"),
    cursor: Optional[str] = Query(None, description="Opaque cursor for keyset node pagination"),
    offset: int = Query(0, ge=0, description="Pagination offset for nodes"),
    limit: int = Query(500, ge=1, le=5000, description="Max nodes to return"),
) -> Response:
    """Load the unified graph with filters and pagination.

    Nodes are paginated (offset/limit). ``edges`` carries up to 1,000 edges
    incident to the ranked page, plus containment context. Omitted relationships
    are declared by ``completeness.edges_truncated`` and remain pageable through
    ``/v1/graph/incident-edges`` at the same revision. Edges may reach nodes
    outside the page; this is not the subgraph induced by ``nodes``;
    ``completeness.boundary_edges`` counts the edges that cross the boundary.

    ``stats`` describe the graph this response was computed from, NOT the page:
    ``stats.total_nodes`` is every node that survived loading, and
    ``stats.total_nodes_source`` is the estate total before any load-time node
    budget applied. The two are equal on an unbounded load. Read
    ``completeness`` for whether the load was bounded and why —
    ``completeness.total`` always reconciles with ``stats.total_nodes_source``.
    """
    from agent_bom.graph import SEVERITY_RANK

    _enforce_node_offset_cap(offset, cursor)
    tenant = _runtime._tenant(request)
    graph_store = _runtime._get_graph_store_or_503()
    requested_scan_id = _coalesce_alias(scan_id, scan, primary_name="scan_id", alias_name="scan")

    if not requested_scan_id and not await _runtime._graph_store_call(graph_store.latest_snapshot_id, tenant_id=tenant):
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")

    identity = await _runtime._graph_store_call(
        optional_generation,
        graph_store,
        tenant=tenant,
        scan_id=requested_scan_id,
        generation=snapshot_generation,
        offset=offset or int(bool(cursor)),
    )
    if identity is not None:
        requested_scan_id = identity[0]

    et_set = _parse_entity_type_filter(entity_types)

    min_rank = 0
    if min_severity:
        min_rank = SEVERITY_RANK.get(min_severity.lower(), 0)

    if relationships or static_only or dynamic_only:
        # This branch materializes the whole snapshot. Bound it: at 200k nodes
        # an uncapped load measured ~783 MB and 8.3s, and several of these can
        # run concurrently. The budget keeps the highest-risk nodes and the
        # response declares what was left out.
        graph = await _runtime._load_graph_for_investigation(
            graph_store,
            scan_id=requested_scan_id,
            tenant_id=tenant,
            entity_types=et_set,
            min_severity_rank=min_rank,
            node_budget=GRAPH_INVESTIGATION_NODE_BUDGET,
        )
        rel_set = _parse_relationship_filter(relationships)
        filters = GraphFilterOptions(
            relationship_types=rel_set,
            static_only=static_only,
            dynamic_only=dynamic_only,
            max_depth=max_depth or 6,
        )
        # Governance overlay, scoped-filter derivation, and response
        # serialization are all CPU-bound; fold them into ONE off-loop hop so no
        # heavy work runs between offloaded calls on the event loop.
        payload = await _runtime._graph_compute_call(
            _overlay_filter_and_respond,
            graph,
            tenant=tenant,
            apply_overlay=not et_set,
            filters=filters,
            offset=offset,
            limit=limit,
        )
        receipt = await _runtime._graph_store_call(graph_store.snapshot_stats, tenant_id=tenant, scan_id=requested_scan_id)
        payload["collection_coverage"] = receipt.get("collection_coverage", {"status": "unknown"})
        if identity is not None:
            await _runtime._graph_store_call(
                verify_generation, graph_store, tenant=tenant, identity=identity, has_rows=bool(payload.get("nodes"))
            )
            payload["snapshot_generation"] = identity[1]
        return await _runtime._graph_compute_call(_encoded_graph_response, payload)

    try:
        effective_scan_id, created_at, paged_nodes, total, next_cursor = await _runtime._graph_store_call(
            graph_store.page_nodes,
            scan_id=requested_scan_id,
            tenant_id=tenant,
            entity_types=et_set,
            min_severity_rank=min_rank,
            cursor=cursor,
            offset=offset,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc
    paged_ids = {n.id for n in paged_nodes}
    paged_edges = await _runtime._graph_store_call(
        graph_store.edges_for_node_ids,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        node_ids=paged_ids,
        limit=_NODE_PAGE_EDGE_LIMIT + 1,
    )
    edges_truncated = len(paged_edges) > _NODE_PAGE_EDGE_LIMIT
    paged_edges = paged_edges[:_NODE_PAGE_EDGE_LIMIT]
    source_attack_paths, attack_path_nodes = await page_attack_context(
        graph_store, scan_id=effective_scan_id, tenant_id=tenant, node_ids=paged_ids, call_store=_runtime._graph_store_call
    )
    ancestor_nodes, ancestor_edges, stack_context = await page_context(
        graph_store, scan_id=effective_scan_id, tenant_id=tenant, page_nodes=paged_nodes, call_store=_runtime._graph_store_call
    )
    nodes_by_id = {node.id: node for node in [*paged_nodes, *attack_path_nodes, *ancestor_nodes]}
    snapshot_stats = await _runtime._graph_store_call(
        graph_store.snapshot_stats,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        entity_types=et_set,
        min_severity_rank=min_rank,
    )

    if identity is not None:
        await _runtime._graph_store_call(verify_generation, graph_store, tenant=tenant, identity=identity, has_rows=bool(nodes_by_id))
    return await _runtime._graph_compute_call(
        _encode_node_page,
        snapshot_stats=snapshot_stats,
        total=total,
        paged_nodes=paged_nodes,
        ancestor_nodes=ancestor_nodes,
        paged_edges=paged_edges,
        ancestor_edges=ancestor_edges,
        edges_truncated=edges_truncated,
        next_cursor=next_cursor,
        offset=offset,
        limit=limit,
        identity=identity,
        effective_scan_id=effective_scan_id,
        tenant=tenant,
        created_at=created_at,
        source_attack_paths=source_attack_paths,
        nodes_by_id=nodes_by_id,
        cursor=cursor,
        stack_context=stack_context,
    )


router.include_router(views.investigation_router)


def _paths_truncation_reason(traversal_truncated: bool, page_truncated: bool, depth_limited: bool = False) -> str:
    """Name the *stronger* loss first.

    A traversal budget is a harder limit than a depth cap, which is harder than
    a page limit: paging further cannot recover the nodes the walk never
    reached, and raising ``max_depth`` cannot recover the nodes the node budget
    never let it visit. So the deeper reason must not be masked by the shallower
    one.
    """
    if traversal_truncated:
        return "traversal_budget"
    if depth_limited:
        return "depth_limit"
    return "path_page_limit" if page_truncated else ""


@router.get("/graph/paths", **documented(GraphPathsResponse), tags=["graph"])
async def get_graph_paths(
    request: Request,
    source_id: Optional[str] = Query(None, description="Source node ID (e.g. agent:claude-desktop)"),
    source: Optional[str] = Query(None, include_in_schema=False),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    scan: Optional[str] = Query(None, include_in_schema=False),
    max_depth: int = Query(4, ge=1, le=10, description="Maximum BFS depth"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=1000, description="Max paths"),
) -> dict:
    """Find all attack paths from a source node via BFS."""
    graph_store = _runtime._get_graph_store_or_503()
    source_node_id = _coalesce_alias(source_id, source, primary_name="source_id", alias_name="source")
    if not source_node_id:
        raise HTTPException(status_code=422, detail="Missing required query parameter: source_id")
    requested_scan_id = _coalesce_alias(scan_id, scan, primary_name="scan_id", alias_name="scan")
    tenant = _runtime._tenant(request)
    source_node_id, resolved_from = await _runtime.resolve_node_id(graph_store, tenant, requested_scan_id, source_node_id)
    source_nodes = await _runtime._graph_store_call(
        graph_store.nodes_by_ids, scan_id=requested_scan_id, tenant_id=tenant, node_ids={source_node_id}
    )
    if not source_nodes:
        raise HTTPException(status_code=404, detail=f"Node '{source_node_id}' not found in graph")

    all_paths, reachable, traversal_truncated, depth_limited = await _runtime._graph_store_call(
        graph_store.bfs_paths,
        scan_id=requested_scan_id,
        tenant_id=tenant,
        source=source_node_id,
        max_depth=max_depth,
        traversable_only=True,
    )
    paged_paths, pagination = _paginate(sorted(all_paths, key=path_order), offset, limit)
    attack_paths = await _runtime._graph_store_call(
        graph_store.attack_paths_for_sources, scan_id=requested_scan_id, tenant_id=tenant, source_ids={source_node_id}
    )
    path_node_ids = {source_node_id, *reachable}
    path_edges = await _runtime._graph_store_call(
        graph_store.edges_for_node_ids, scan_id=requested_scan_id, tenant_id=tenant, node_ids=path_node_ids
    )
    path_nodes = await _runtime._graph_store_call(
        graph_store.nodes_by_ids, scan_id=requested_scan_id, tenant_id=tenant, node_ids=path_node_ids
    )
    nodes_by_id = {node.id: node for node in path_nodes}

    result = {
        "source": source_node_id,
        "source_id": source_node_id,
        "max_depth": max_depth,
        "reachable_count": len(reachable),
        "reachable_nodes": sorted(reachable),
        "paths": [{"target": p[-1], "hops": p, "depth": len(p) - 1} for p in paged_paths],
        "attack_paths": _serialize_attack_path_batch(
            [ap for ap in attack_paths if ap.source == source_node_id],
            path_edges,
            nodes_by_id=nodes_by_id,
            scan_id=requested_scan_id,
        ),
        "pagination": pagination,
        "truncated": traversal_truncated,
        "depth_limited": depth_limited,
        # A bounded BFS knows neither the reachable set nor the path count, so
        # it cannot report a total: `len(all_paths)` is the bound, not the
        # answer. Reporting it as `total` told a client that paged to exhaustion
        # it had everything. `max_depth` bounds it exactly as the node budget
        # does — it defaults to 4 and is the server's choice when the caller
        # passes nothing — so a walk that stopped with reachable nodes still
        # unwalked is no more complete than one that ran out of budget.
        "completeness": graph_completeness(
            returned=len(paged_paths),
            total=None if (traversal_truncated or depth_limited) else len(all_paths),
            truncated=traversal_truncated or depth_limited or pagination["has_more"],
            reason=_paths_truncation_reason(traversal_truncated, pagination["has_more"], depth_limited),
        ),
        "resolved_from": resolved_from,
    }
    from agent_bom.db.adoption_events import record_adoption_event_best_effort

    record_adoption_event_best_effort("investigation_started", channel="control_plane")
    return result


router.include_router(reads.search_router)


@router.post("/graph/query", tags=["graph"])
async def query_graph(request: Request, body: GraphQueryRequest) -> dict:
    """Run a bounded programmable traversal over the canonical graph."""
    graph_store = _runtime._get_graph_store_or_503()
    tenant_id = _runtime._tenant(request)
    identity = await _runtime._graph_store_call(
        optional_generation, graph_store, tenant=tenant_id, scan_id=body.scan_id or "", generation=body.snapshot_generation, offset=0
    )
    scan_id = identity[0] if identity else body.scan_id or ""
    body, budget, budget_applied = _apply_graph_query_budget(body)
    body, resolved_roots, missing_roots = await _runtime.resolve_query_roots(graph_store, tenant_id, scan_id, body)
    if missing_roots:
        raise HTTPException(status_code=404, detail={"message": "Root nodes not found", "missing_roots": missing_roots})

    rel_types = _validate_relationship_list(body.relationship_types)
    deadline = time.monotonic() + (body.timeout_ms / 1000)
    traversal_graph, depth_by_node, truncated = await _runtime._graph_store_call(
        graph_store.traverse_subgraph,
        scan_id=scan_id,
        tenant_id=tenant_id,
        roots=body.roots,
        direction=body.direction,
        max_depth=body.max_depth,
        max_nodes=body.max_nodes,
        max_edges=body.max_edges,
        deadline_monotonic=deadline,
        traversable_only=body.traversable_only,
        relationship_types=rel_types,
        static_only=body.static_only,
        dynamic_only=body.dynamic_only,
        include_roots=body.include_roots,
    )

    depth_limited = bool(getattr(traversal_graph.completeness, "depth_limited", False))
    filtered_graph = _filtered_query_graph(
        traversal_graph,
        roots=body.roots,
        entity_types=set(_validate_entity_type_list(body.entity_types)),
        min_severity_rank=SEVERITY_RANK.get(body.min_severity.lower(), 0) if body.min_severity else 0,
        compliance_prefixes={prefix.upper() for prefix in body.compliance_prefixes},
        data_sources=set(body.data_sources),
    )

    attack_paths = []
    if body.include_attack_paths:
        root_attack_paths = await _runtime._graph_store_call(
            graph_store.attack_paths_for_sources,
            scan_id=scan_id,
            tenant_id=tenant_id,
            source_ids=set(body.roots),
        )
        # Keep every path rooted at a queried node, even when intermediate hops
        # were excluded by the traversal limits or the entity/severity/
        # compliance/data-source filters. Dropping a path because one hop is
        # off-graph silently hides real attack paths (same pagination-drop
        # class as the paged sibling above). Backfill the missing hop nodes so
        # exposure-path labels still resolve.
        root_paths = [ap for ap in root_attack_paths if ap.source in body.roots]
        missing_hop_ids = {hop for ap in root_paths for hop in ap.hops} - set(filtered_graph.nodes)
        backfilled_nodes = await _runtime._graph_store_call(
            graph_store.nodes_by_ids,
            scan_id=scan_id,
            tenant_id=tenant_id,
            node_ids=missing_hop_ids,
        )
        nodes_by_id = {**filtered_graph.nodes, **{node.id: node for node in backfilled_nodes}}
        attack_paths = _serialize_attack_path_batch(
            root_paths,
            filtered_graph.edges,
            nodes_by_id=nodes_by_id,
            scan_id=filtered_graph.scan_id,
        )

    if identity:
        await _runtime._graph_store_call(
            verify_generation, graph_store, tenant=tenant_id, identity=identity, has_rows=bool(filtered_graph.nodes)
        )
    payload = query_payload(
        body, filtered_graph, depth_by_node, truncated, depth_limited, attack_paths, budget, rel_types, identity[1] if identity else None
    )
    return {**payload, "budget_applied": budget_applied, "resolved_roots": resolved_roots}


@router.get("/graph/node-neighbors", **documented(GraphNodeNeighborsResponse), tags=["graph"])
@router.get("/graph/node/{node_id:path}/neighbors", **documented(GraphNodeNeighborsResponse), tags=["graph"])
async def get_graph_node_neighbors(
    request: Request,
    node_id: GraphIdentifier,
    scan_id: Optional[GraphIdentifier] = Query(None, description="Scan ID; latest if omitted"),
    limit: int = Query(24, ge=1, le=100, description="Max neighbors returned per expand"),
    direction: str = Query("both", description="out=dependencies, in=dependents, both=either"),
) -> dict:
    """Return a bounded set of a node's direct graph neighbors for inline expand.

    The read side of progressive-disclosure attack-path views: one hop's direct
    neighbors, fan-out capped by ``limit``; ``total_neighbors`` is null when source
    evidence is incomplete, and a fully read high-degree neighborhood reports its
    total with ``truncated`` set ("+N more"). Neighbor metadata travels with the
    payload. A replaced id resolves (``resolved_from``); an unknown id returns 200
    with ``found`` false, so a stale client id degrades quietly in place.
    """
    normalized_direction = direction.strip().lower()
    if normalized_direction not in {"out", "in", "both"}:
        normalized_direction = "both"

    tenant = _runtime._tenant(request)
    store = _runtime._get_graph_store_or_503()
    if isinstance(store, NeptuneGraphStore):
        # Unsupported traversal stays 501 even when the backend has no snapshot.
        # The adapter owns the capability error; the wrapper sanitizes it.
        await _runtime._graph_store_call(store.node_context, scan_id=scan_id or "", tenant_id=tenant, node_id=node_id)
    effective_scan_id = scan_id or await _runtime._graph_store_call(store.latest_snapshot_id, tenant_id=tenant)
    node_id, resolved_from = await _runtime.resolve_node_id(store, tenant, scan_id, node_id) if effective_scan_id else (node_id, None)
    context = (
        await _runtime._graph_store_call(store.node_context, scan_id=effective_scan_id, tenant_id=tenant, node_id=node_id)
        if effective_scan_id
        else None
    )
    if context is None:
        return {
            "node_id": node_id,
            "scan_id": effective_scan_id or "",
            "found": False,
            "direction": normalized_direction,
            "limit": limit,
            "total_neighbors": None,
            "truncated": True,
            "neighbors": [],
            "edges": [],
            # The node was not found, so zero returned neighbors is not proof
            # that the node has a complete zero-degree neighborhood.
            "completeness": graph_completeness(
                returned=0,
                total=None,
                truncated=True,
                reason="node_not_found" if effective_scan_id else "snapshot_not_found",
            ),
            "resolved_from": resolved_from,
        }

    selected_edges: list = []
    if normalized_direction in {"out", "both"}:
        selected_edges.extend(context["edges_out"])
    if normalized_direction in {"in", "both"}:
        selected_edges.extend(context["edges_in"])

    # Deterministic, de-duplicated neighbor ordering keeps the cap stable across
    # repeated expands (same class of pagination-drop guard used elsewhere).
    edges_by_neighbor: dict[str, list] = {}
    neighbor_ids: list[str] = []
    seen: set[str] = set()
    for edge in selected_edges:
        neighbor_id = edge.target if edge.source == node_id else edge.source
        if neighbor_id == node_id:
            continue
        edges_by_neighbor.setdefault(neighbor_id, []).append(edge)
        if neighbor_id not in seen:
            seen.add(neighbor_id)
            neighbor_ids.append(neighbor_id)

    neighbor_ids.sort()
    total_neighbors = len(neighbor_ids)
    bounded_ids = neighbor_ids[:limit]
    truncated = total_neighbors > len(bounded_ids)

    neighbor_nodes = await _runtime._graph_store_call(
        store.nodes_by_ids,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        node_ids=set(bounded_ids),
    )
    nodes_by_id = {node.id: node for node in neighbor_nodes}
    ordered_nodes = [nodes_by_id[node_id_] for node_id_ in bounded_ids if node_id_ in nodes_by_id]
    missing_endpoints = len(ordered_nodes) != len(bounded_ids)
    bounded_edges = [edge for node_id_ in bounded_ids if node_id_ in nodes_by_id for edge in edges_by_neighbor.get(node_id_, [])]
    upstream = context.get("completeness") or {}
    upstream_incomplete = bool(
        upstream.get("truncated")
        or upstream.get("sampled")
        or upstream.get("complete") is False
        or upstream.get("status") in {"truncated", "sampled"}
    )
    total_known = not upstream_incomplete and not missing_endpoints
    truncated = truncated or bool(upstream.get("truncated")) or missing_endpoints
    reason = (
        str(upstream.get("reason") or "upstream_incomplete")
        if upstream_incomplete
        else "missing_neighbor_endpoints"
        if missing_endpoints
        else "neighbor_limit"
        if truncated
        else ""
    )
    completeness = graph_completeness(
        returned=len(ordered_nodes),
        total=total_neighbors if total_known else None,
        truncated=truncated or (upstream_incomplete and not upstream.get("sampled")),
        sampled=bool(upstream.get("sampled")),
        reason=reason,
    )
    if upstream_incomplete:
        completeness["source_completeness"] = upstream
    if missing_endpoints:
        completeness["missing_neighbor_endpoints"] = True

    return {
        "node_id": node_id,
        "scan_id": effective_scan_id or "",
        "found": True,
        "direction": normalized_direction,
        "limit": limit,
        "total_neighbors": total_neighbors if total_known else None,
        "truncated": not completeness["complete"],
        "neighbors": [node.to_dict() for node in ordered_nodes],
        "edges": [edge.to_dict() for edge in bounded_edges],
        "completeness": completeness,
        "resolved_from": resolved_from,
    }


# After the neighbors route: ``/graph/node/{node_id:path}`` would otherwise
# swallow ``.../neighbors`` because node ids may contain "/".
router.include_router(reads.node_router)
router.include_router(reads.history_router)
router.include_router(schema_routes.router)
router.include_router(reads.preset_router)


# Edge load for /v1/graph/rollup (default mode). Taken from the roll-up itself
# rather than restated here, so the set fetched can never be narrower than the
# set rolled up — which is precisely what a containment-only fetch made it: the
# roll-up draws the NON-containment edges, so it received nothing to draw.
_ROLLUP_RELATIONSHIPS = ROLLUP_RELATIONSHIPS
_ROLLUP_DRILLDOWN_DEFAULT_LIMIT = 200
_ROLLUP_DRILLDOWN_MAX_LIMIT = 1000


@router.get("/graph/rollup", **documented(GraphRollupResponse), tags=["graph"])
async def get_graph_rollup(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan snapshot ID; latest if omitted"),
    snapshot_generation: Optional[str] = Query(None, max_length=128, description="Read revision from the first drill-down page"),
    node: Optional[str] = Query(None, description="Drill down into a container node's direct children"),
    min_severity: Optional[str] = Query(None, description="Only roll up descendants at/above this severity"),
    exposed: bool = Query(False, description="Only roll up internet-exposed descendants"),
    toxic: bool = Query(False, description="Only roll up toxic-combination descendants"),
    mode: Literal["rollup", "attack_path"] = Query("rollup", description="rollup (default) or attack_path-first view"),
    offset: int = Query(0, ge=0, le=1_000_000, description="Page offset into the ranked top level, or the drill-down's ranked children"),
    limit: int = Query(
        _ROLLUP_DRILLDOWN_DEFAULT_LIMIT,
        ge=1,
        le=_ROLLUP_DRILLDOWN_MAX_LIMIT,
        description="Maximum top-level entries (or drill-down direct children) returned per page",
    ),
) -> dict:
    """Collapse the estate along ``CONTAINS`` into a small, readable view.

    Rolls the graph up along containment (org -> account/project -> app ->
    resource) so a 1000+ node estate renders as a few top-level containers, each
    with descendant counts, worst severity, a severity histogram and exposure /
    toxic flags. The ranked top level is paged by ``offset``/``limit``
    (``pagination`` carries the ranked total). ``?node=<id>`` (a replaced id
    resolves, echoed as ``resolved_from``) returns one level of direct
    children, paged the same way, with truthful ``completeness``;
    ``?mode=attack_path`` returns materialised attack-path nodes/edges first.
    Read-only.
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

    if min_severity and min_severity.lower() not in SEVERITY_RANK:
        raise HTTPException(status_code=422, detail=f"Unsupported severity: {min_severity}")

    # Cache the small summary, never the hydrated estate; the durable generation stops same-ID replays of older counts.
    from agent_bom.api import graph_rollup_cache

    identity = await _runtime._graph_store_call(
        optional_generation,
        graph_store,
        tenant=tenant,
        scan_id=requested_scan_id,
        generation=snapshot_generation,
        offset=offset if mode == "rollup" else 0,
    )
    cache_identity = identity
    if identity is None and not offset:
        cache_identity = await _runtime._graph_store_call(snapshot_fingerprint, graph_store, tenant=tenant, scan_id=requested_scan_id)
    cache_key = None
    if cache_identity and cache_identity[1]:
        cache_key = rollup_cache_key(
            graph_store,
            tenant,
            cache_identity,
            node=node,
            min_severity=min_severity,
            exposed=exposed,
            toxic=toxic,
            mode=mode,
            offset=offset,
            limit=limit,
        )
        cached = graph_rollup_cache.get(cache_key)
        if cached is not None:
            return cached
        requested_scan_id = cache_identity[0]

    node, resolved_from = await _runtime.resolve_node_id(graph_store, tenant, requested_scan_id, node) if node else (node, None)
    try:
        # A drill-down reads only one container's subtree (its cost tracks the
        # answer, not the estate); the top level uses the store's aggregate-only
        # roll-up projection when it has one; attack-path mode needs the full
        # evidence records.
        graph = await _runtime._graph_store_call(
            load_rollup_source,
            graph_store,
            tenant_id=tenant,
            scan_id=requested_scan_id,
            node=node,
            mode=mode,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=sanitize_error(exc)) from exc

    try:
        payload = await _runtime._graph_compute_call(
            _graph_rollup_payload,
            graph,
            node=node,
            min_severity=(min_severity or "").lower(),
            exposed=exposed,
            toxic=toxic,
            mode=mode,
            offset=offset,
            limit=limit,
            graph_store=graph_store,
        )
        if identity is not None:
            await _runtime._graph_store_call(verify_generation, graph_store, tenant=tenant, identity=identity, has_rows=bool(graph.nodes))
            payload["snapshot_generation"] = identity[1]
        payload.update({"resolved_from": resolved_from} if resolved_from else {})
        if cache_key:
            graph_rollup_cache.put(cache_key, payload)
        return payload
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        # Never leak internal exception detail in the response (CodeQL lesson).
        logger.warning("graph rollup failed", exc_info=False)
        raise HTTPException(status_code=500, detail="Failed to compute graph roll-up") from exc
