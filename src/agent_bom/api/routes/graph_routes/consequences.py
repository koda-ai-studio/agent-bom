"""Authenticated, read-only experimental consequence assessments."""

from fastapi import APIRouter, HTTPException, Request

from agent_bom.api.graph_consequence import GraphConsequenceRequest, GraphConsequenceResponse, assess_snapshot_consequences
from agent_bom.api.routes.graph_routes import _runtime
from agent_bom.api.routes.graph_routes._admission import _GraphAdmissionRoute

router = APIRouter(route_class=_GraphAdmissionRoute)


@router.post("/graph/consequences", response_model=GraphConsequenceResponse, tags=["graph"])
async def post_graph_consequences(request: Request, body: GraphConsequenceRequest) -> GraphConsequenceResponse:
    """Trace recorded action consequences; missing authority evidence fails closed."""
    try:
        return await _runtime._graph_compute_call(
            assess_snapshot_consequences, _runtime._get_graph_store_or_503(), body, tenant_id=_runtime._tenant(request)
        )
    except HTTPException:
        raise
    except Exception as exc:  # broad-except: Pluggable storage failures must not leak secrets through HTTP.
        raise HTTPException(503, "Consequence assessment is temporarily unavailable.") from exc
