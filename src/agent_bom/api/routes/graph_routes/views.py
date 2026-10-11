"""Graph investigation views: compromise, scoped graph, fix-first, diffs, governance, exposure."""

from __future__ import annotations

import json
from typing import Any, Literal, Optional, cast

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.graph_compromise import GraphCompromiseRequest, GraphCompromiseResponse, assess_snapshot
from agent_bom.api.graph_contracts import (
    _ATTACK_PATHS_OPENAPI_RESPONSE,
    _FIX_FIRST_VIEW_OPENAPI_RESPONSE,
    GraphDeployDecisionRequest,
    ScopedGraphResponse,
)
from agent_bom.api.graph_generation import pin_generation, verify_generation
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.graph import (
    GraphActiveEdgesResponse,
    GraphDiffResponse,
    GraphEdgeChangesResponse,
    GraphExposurePathsResponse,
    GraphGovernanceResponse,
    GraphNhiGovernanceResponse,
    documented_list,
)
from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.api.routes.graph_routes._admission import _GraphAdmissionRoute
from agent_bom.api.routes.graph_routes.params import (
    _GOVERNANCE_ATTACK_PATH_LIMIT,
    _GOVERNANCE_EDGE_LIMIT,
    _candidate_to_string,
    _raise_mcp_error_as_http,
    _tag_diff_change_kinds,
)
from agent_bom.api.routes.graph_routes.payloads import (
    _derived_attack_path_page,
    _fix_first_graph_view_payload,
    _governance_graph_payload,
    _scoped_graph_response,
    _serialize_attack_path_queue,
)
from agent_bom.config import GRAPH_INVESTIGATION_NODE_BUDGET
from agent_bom.graph.completeness import graph_completeness
from agent_bom.graph.scope import GraphScopeKind

compromise_router = APIRouter(route_class=_GraphAdmissionRoute)
investigation_router = APIRouter(route_class=_GraphAdmissionRoute)


@compromise_router.post("/graph/compromise", response_model=GraphCompromiseResponse, tags=["graph"])
async def post_graph_compromise(request: Request, body: GraphCompromiseRequest) -> GraphCompromiseResponse:
    """Assess explicit control assumptions against one authorized immutable revision."""
    try:
        return await _runtime._graph_compute_call(
            assess_snapshot, _runtime._get_graph_store_or_503(), body, tenant_id=_runtime._tenant(request)
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(503, "Compromise assessment is temporarily unavailable.") from exc


@compromise_router.get(
    "/graph/scoped",
    tags=["graph"],
    response_model=ScopedGraphResponse,
)
async def get_scoped_graph(
    request: Request,
    scope: GraphScopeKind = Query(..., description="Observed graph scope"),
    scope_id: str | None = Query(
        None,
        max_length=512,
        description="Observed account, repository, environment, or root-node identifier",
    ),
    scan_id: str | None = Query(None, description="Persisted graph snapshot ID"),
    max_depth: int = Query(4, ge=1, le=10, description="Investigation traversal depth"),
    limit: int = Query(500, ge=1, le=5000, description="Maximum nodes in the scoped working set"),
) -> dict[str, Any]:
    """Return a bounded graph scope backed only by persisted UnifiedGraph evidence."""
    from agent_bom.api.managed_trial import managed_trial_enabled

    if scope != "estate" and not scope_id:
        raise HTTPException(status_code=422, detail="scope_id is required for this graph scope")
    if managed_trial_enabled() and scope != "account":
        raise HTTPException(status_code=403, detail="Managed trial graph scopes are account-scoped.")

    tenant = _runtime._tenant(request)
    graph_store = _runtime._get_graph_store_or_503()
    if not scan_id and not await _runtime._graph_store_call(
        graph_store.latest_snapshot_id,
        tenant_id=tenant,
        snapshot_kind="scan",
    ):
        raise HTTPException(status_code=503, detail="Graph snapshots not found. Run a scan first.")
    graph = await _runtime._load_graph_for_investigation(
        graph_store,
        scan_id=scan_id,
        tenant_id=tenant,
        node_budget=GRAPH_INVESTIGATION_NODE_BUDGET,
    )
    return await _runtime._graph_compute_call(
        _scoped_graph_response,
        graph,
        scope=scope,
        scope_id=scope_id,
        max_depth=max_depth,
        limit=limit,
    )


@investigation_router.get("/graph/views/fix-first", tags=["graph"], responses={200: _FIX_FIRST_VIEW_OPENAPI_RESPONSE})
async def get_fix_first_graph_view(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan snapshot ID; latest if omitted"),
    cve: str = Query("", description="Optional finding focus"),
    package: str = Query("", description="Optional package focus"),
    agent: str = Query("", description="Optional agent or identity focus"),
    limit: int = Query(8, ge=1, le=25, description="Maximum ranked path cards to return"),
) -> dict:
    """Return a fix-first security graph view model.

    This endpoint is intentionally more product-shaped than `/v1/graph`: it
    ranks persisted attack paths and attaches the operator context needed for
    a fix-first remediation cockpit. The full topology remains available
    through `/v1/graph`; this view answers "what should I inspect first?"
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

    graph = await _runtime._load_graph_for_investigation(
        graph_store,
        scan_id=requested_scan_id,
        tenant_id=tenant,
    )
    return await _runtime._graph_compute_call(_fix_first_graph_view_payload, graph, cve=cve, package=package, agent=agent, limit=limit)


@investigation_router.get("/graph/diff", **documented(GraphDiffResponse), tags=["graph"])
async def get_graph_diff(
    request: Request,
    old: str = Query(..., description="Old scan ID"),
    new: str = Query(..., description="New scan ID"),
) -> dict:
    """Diff two scan snapshots — nodes/edges added, removed, changed."""
    diff = await _runtime._graph_store_call(
        _runtime._get_graph_store_or_503().diff_snapshots, old, new, tenant_id=_runtime._tenant(request)
    )
    diff = _tag_diff_change_kinds(diff)
    diff["completeness"] = graph_completeness(returned=1, total=1)
    return diff


@investigation_router.get("/graph/edges/active", **documented_list(GraphActiveEdgesResponse), tags=["graph"])
async def get_active_graph_edges(
    request: Request,
    at: str = Query(..., description="ISO timestamp for replay lookup"),
) -> list[dict]:
    """Return edge versions active at a timestamp for replay views."""
    edges = await _runtime._graph_store_call(_runtime._get_graph_store_or_503().active_edges_at, at, tenant_id=_runtime._tenant(request))
    # Preserve the historical list response shape; callers receive all edges
    # selected by the timestamp query and no page-level sampling is applied.
    return edges


@investigation_router.get("/graph/edges/changes", **documented(GraphEdgeChangesResponse), tags=["graph"])
async def get_graph_edge_changes(
    request: Request,
    old: str = Query(..., description="Old scan ID"),
    new: str = Query(..., description="New scan ID"),
) -> dict:
    """Return edge lifecycle changes between two scan snapshots."""
    changes = await _runtime._graph_store_call(
        _runtime._get_graph_store_or_503().changed_edges_between_scans, old, new, tenant_id=_runtime._tenant(request)
    )
    if isinstance(changes, dict):
        changes["completeness"] = graph_completeness(returned=1, total=1)
    return changes


@investigation_router.get("/graph/attack-paths", tags=["graph"], responses={200: _ATTACK_PATHS_OPENAPI_RESPONSE})
async def get_graph_attack_paths(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    snapshot_generation: Optional[str] = Query(
        None, max_length=128, description="Generation from the first page; required for continuation"
    ),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(100, ge=1, le=1000, description="Max attack paths"),
    min_severity: Optional[Literal["critical", "high", "medium", "low"]] = Query(
        None, description="Only paths whose worst on-path finding is at least this severity"
    ),
    has_credential: Optional[bool] = Query(None, description="Only paths that do (true) or do not (false) expose a credential"),
    source_type: Optional[str] = Query(None, max_length=64, description="Only paths whose entrypoint node has this entity type"),
) -> dict:
    """Return the global attack-path queue independent of node pagination.

    `/v1/graph` intentionally windows nodes and therefore cannot be the source
    of truth for fix-first triage. This endpoint ranks paths across the whole
    snapshot by on-path exploitability evidence, then stored composite risk
    (see ``graph.attack_path_queue_rank``), and hydrates only the hop nodes
    needed to render the selected queue page.
    """
    from agent_bom.api.attack_path_queue import AttackPathFilters, ranked_persisted_path_page

    tenant = _runtime._tenant(request)
    graph_store = _runtime._get_graph_store_or_503()
    identity = await _runtime._graph_store_call(
        pin_generation, graph_store, tenant=tenant, scan_id=scan_id or "", generation=snapshot_generation, offset=offset
    )
    filters = AttackPathFilters(min_severity=min_severity, has_credential=has_credential, source_type=source_type)
    page_args = {"offset": offset, "limit": limit, "filters": filters}
    ranked = await _runtime._graph_store_call(ranked_persisted_path_page, graph_store, scan_id=identity[0], tenant_id=tenant, **page_args)
    materialized_paths, derived_paths, path_source = ranked.snapshot_total, 0, "persisted_graph_paths"
    if ranked.snapshot_total == 0:
        graph = await _runtime._load_graph_for_investigation(graph_store, scan_id=ranked.scan_id, tenant_id=tenant)
        ranked = await _runtime._graph_compute_call(_derived_attack_path_page, graph, **page_args)
        derived_paths, path_source = ranked.snapshot_total, "derived_graph_paths"
    effective_scan_id = ranked.scan_id
    hop_ids = {hop for path in ranked.paths for hop in path.hops}
    nodes = await _runtime._graph_store_call(
        graph_store.nodes_by_ids,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        node_ids=hop_ids,
    )
    path_edges = await _runtime._graph_store_call(
        graph_store.edges_for_node_ids,
        scan_id=effective_scan_id,
        tenant_id=tenant,
        node_ids=hop_ids,
    )
    stats = await _runtime._graph_store_call(
        graph_store.snapshot_stats,
        scan_id=effective_scan_id,
        tenant_id=tenant,
    )
    payload = await _runtime._graph_compute_call(
        _serialize_attack_path_queue,
        scan_id=effective_scan_id,
        tenant=tenant,
        created_at=ranked.created_at,
        nodes=nodes,
        path_edges=path_edges,
        paths=ranked.paths,
        total=ranked.total,
        offset=offset,
        limit=limit,
        stats=stats,
        path_source=path_source,
        materialized_paths=materialized_paths,
        derived_paths=derived_paths,
        ranked=ranked,
        filters=filters.active(),
    )

    await _runtime._graph_store_call(verify_generation, graph_store, tenant=tenant, identity=identity, has_rows=bool(nodes or ranked.paths))
    payload["snapshot_generation"] = identity[1]
    return payload


@investigation_router.get("/graph/governance", **documented(GraphGovernanceResponse), tags=["graph"])
async def get_graph_governance(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    limit: int = Query(2000, ge=1, le=10000, description="Max nodes to return"),
    edge_limit: int = Query(_GOVERNANCE_EDGE_LIMIT, ge=1, le=25_000, description="Max governance edges to return"),
    attack_path_limit: int = Query(
        _GOVERNANCE_ATTACK_PATH_LIMIT,
        ge=1,
        le=1000,
        description="Max governance attack paths to embed",
    ),
) -> dict:
    """Return the agent-identity governance subgraph projected onto the inventory.

    Loads the latest unified graph, overlays the live governance control plane
    (managed identities, JIT grants, conditional-access policies, drift
    incidents) from the identity/drift stores, and returns the governance nodes
    plus the agent/tool nodes they connect to — making
    `agent → identity → grant → tool → vulnerable package` and `agent ↔ drift`
    traversable for headless agents, the API, and the UI cockpits.
    """
    from agent_bom.graph.governance_overlay import apply_governance_overlay

    tenant = _runtime._tenant(request)
    graph_store = _runtime._get_graph_store_or_503()
    graph = await _runtime._graph_store_call(graph_store.load_graph, scan_id=scan_id or "", tenant_id=tenant)
    overlay_stats = apply_governance_overlay(graph, tenant_id=tenant)
    return await _runtime._graph_compute_call(
        _governance_graph_payload,
        graph,
        tenant_id=tenant,
        overlay_stats=overlay_stats,
        node_limit=limit,
        edge_limit=edge_limit,
        attack_path_limit=attack_path_limit,
    )


@investigation_router.get("/graph/nhi/governance", **documented(GraphNhiGovernanceResponse), tags=["graph"])
async def get_nhi_governance(
    request: Request,
    scan_id: Optional[str] = Query(None, description="Scan ID"),
) -> dict:
    """Return the non-human-identity governance posture for the latest graph.

    Loads the latest unified graph, projects the live governance control plane
    and resolves effective permissions, then computes the three core NHI governance
    analytics — usage-based right-sizing, dormant/orphaned detection, and the
    0-100 per-identity risk score — and returns a non-secret posture ranked
    worst risk first. Right-sizing here uses the durable `last_used_at` markers
    in the graph (no caller usage map is accepted over the API).
    """
    from agent_bom.graph.effective_permissions import apply_effective_permissions
    from agent_bom.graph.governance_overlay import apply_governance_overlay
    from agent_bom.graph.nhi_governance import describe_nhi_governance_posture

    tenant = _runtime._tenant(request)
    graph_store = _runtime._get_graph_store_or_503()
    graph = await _runtime._graph_store_call(graph_store.load_graph, scan_id=scan_id or "", tenant_id=tenant)
    apply_governance_overlay(graph, tenant_id=tenant)
    apply_effective_permissions(graph)
    posture = describe_nhi_governance_posture(graph)
    posture["scan_id"] = graph.scan_id
    posture["tenant_id"] = tenant
    return posture


@investigation_router.get("/graph/exposure-paths", **documented(GraphExposurePathsResponse), tags=["graph"])
async def get_graph_exposure_paths(
    request: Request,
    tenant_id: Optional[str] = Query(None, include_in_schema=False),
    scan_id: Optional[str] = Query(None, description="Scan ID"),
    limit: int = Query(5, ge=1, le=100, description="Maximum ExposurePaths"),
    min_risk: float = Query(0.0, ge=0, le=100, description="Minimum ExposurePath risk score"),
    cursor: Optional[str] = Query(None, max_length=4096, description="Continuation cursor pinned to the snapshot and risk filter"),
) -> dict:
    """Return the MCP-compatible ExposurePath queue over REST for SDK consumers."""
    del tenant_id  # SDK compatibility only; request tenant scope is authoritative.
    from agent_bom.mcp_tools.graph import exposure_paths_for_tenant

    graph_store = _runtime._get_graph_store_or_503()
    raw = await exposure_paths_for_tenant(
        tenant_id=_runtime._tenant(request),
        scan_id=scan_id,
        limit=limit,
        min_risk=min_risk,
        cursor=cursor,
        _get_graph_store=lambda: graph_store,
        _truncate_response=lambda value: value,
    )
    payload = json.loads(raw)
    _raise_mcp_error_as_http(payload)
    return cast("dict[str, Any]", payload)


@investigation_router.post("/graph/should-i-deploy", tags=["graph"])
async def post_graph_should_i_deploy(request: Request, body: GraphDeployDecisionRequest) -> dict:
    """Return the MCP-compatible allow/warn/block deploy decision over REST."""
    _ = (body.tenant_id, body.context)  # SDK compatibility/future policy context; request tenant scope is authoritative today.
    from agent_bom.mcp_tools.graph import deploy_decision_for_tenant

    candidate = _candidate_to_string(body.candidate)
    if not candidate:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT",
                "category": "validation",
                "message": "candidate must not be empty",
                "details": {"argument": "candidate"},
            },
        )
    if body.warn_risk > body.block_risk:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT",
                "category": "validation",
                "message": "warn_risk and block_risk must be ordered thresholds between 0 and 100",
                "details": {"warn_risk": body.warn_risk, "block_risk": body.block_risk},
            },
        )

    graph_store = _runtime._get_graph_store_or_503()
    raw = await deploy_decision_for_tenant(
        candidate=candidate,
        tenant_id=_runtime._tenant(request),
        scan_id=body.scan_id,
        limit=body.limit,
        warn_risk=body.warn_risk,
        block_risk=body.block_risk,
        _get_graph_store=lambda: graph_store,
        _truncate_response=lambda value: value,
    )
    payload = json.loads(raw)
    _raise_mcp_error_as_http(payload)
    return cast("dict[str, Any]", payload)
