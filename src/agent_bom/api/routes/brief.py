"""Authenticated, tenant-scoped executive summary."""

from typing import Annotated, Any, cast

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from agent_bom.api.exec_brief import DEFAULT_EXPOSURE_LIMIT, build_executive_brief
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.brief import ExecutiveBriefResponse
from agent_bom.api.request_contract import reject_unknown_query_params
from agent_bom.api.routes.compliance_routes.common import SEEDING_GUARD
from agent_bom.demo_estate import demo_estate_enabled
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(dependencies=[cast(Any, require_authenticated_permission("read"))])


@router.get(
    "/brief", **documented(ExecutiveBriefResponse), tags=["overview"], dependencies=[SEEDING_GUARD, Depends(reject_unknown_query_params)]
)
async def get_executive_brief(
    request: Request,
    limit: Annotated[int, Query(ge=1, le=25)] = DEFAULT_EXPOSURE_LIMIT,
) -> dict:
    """Current posture, remediation priorities, ranked paths and scoped scan history."""
    if str(getattr(request.state, "auth_method", "") or "") in {"", "anonymous", "no_auth"} and not demo_estate_enabled():
        raise HTTPException(status_code=401, detail="Authentication required for the executive brief")
    return await build_executive_brief(request, limit=limit)
