"""Multi-agent harness architecture of a snapshot, paged by harness with a generation-pinned cursor."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query, Request

from agent_bom.api.graph_agent_architecture import read_agent_architecture
from agent_bom.api.graph_generation import pin_generation, verify_generation
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.graph_agent_architecture import GraphAgentArchitectureResponse
from agent_bom.api.request_contract import reject_unknown_query_params
from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.api.routes.graph_routes._admission import _GraphAdmissionRoute
from agent_bom.api.routes.graph_routes.path_cursor import path_continuation, path_cursor_scope, path_page_cursors

router = APIRouter(route_class=_GraphAdmissionRoute)

MAX_LIMIT = 50


@router.get(
    "/graph/agent-architecture",
    **documented(GraphAgentArchitectureResponse),
    tags=["graph"],
    dependencies=[Depends(reject_unknown_query_params)],
)
async def get_agent_architecture(
    request: Request,
    scan_id: Optional[str] = Query(None, max_length=256, description="Scan ID; omit for the current estate"),
    snapshot_generation: Optional[str] = Query(
        None, max_length=128, description="Generation from the first page; required for continuation"
    ),
    offset: int = Query(0, ge=0, le=100_000, description="Harness offset"),
    limit: int = Query(20, ge=1, le=MAX_LIMIT, description="Max harnesses per page"),
    cursor: Optional[str] = Query(None, max_length=1024, description="next_cursor from the previous page (replaces offset)"),
) -> dict:
    """Multi-agent harnesses declared in source: layers, flow edges, unresolved routes and the security overlay.

    A harness is the tree of framework agents joined by declared delegation or
    crew membership. Each agent carries its role (harness, orchestrator,
    subgraph, sub_agent), its layer below the harness root, literal model
    references, and what the graph records for it: severity, risk score,
    findings it is vulnerable to and outgoing reach. Flow edges keep their
    ``declared`` provenance; routes the scanner could not resolve are listed,
    never dropped. ``coverage.gaps`` names what is not modelled yet.
    """
    tenant = _runtime._tenant(request)
    graph_store = _runtime._get_graph_store_or_503()
    scope = path_cursor_scope("agent-architecture", tenant, scan_id, {})
    if cursor:
        offset, snapshot_generation = path_continuation(cursor, scope, offset=offset, generation=snapshot_generation)
    identity = await _runtime._graph_store_call(
        pin_generation, graph_store, tenant=tenant, scan_id=scan_id or "", generation=snapshot_generation, offset=offset
    )
    payload = await _runtime._graph_store_call(
        read_agent_architecture, graph_store, tenant_id=tenant, scan_id=identity[0], offset=offset, limit=limit
    )
    await _runtime._graph_store_call(verify_generation, graph_store, tenant=tenant, identity=identity, has_rows=bool(payload["harnesses"]))
    payload["snapshot_generation"] = identity[1]
    page = payload["pagination"]
    page.update(path_page_cursors(scope, identity[1], offset, page["returned"], page["total"], cursor))
    return payload
