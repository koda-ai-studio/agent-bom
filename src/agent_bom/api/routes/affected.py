"""``GET /v1/affected``: am I affected by this advisory or package, where, since when, and what does it reach."""

from __future__ import annotations

import anyio
from fastapi import APIRouter, Depends, Query, Request

from agent_bom.api.affected_read import read_affected
from agent_bom.api.current_graph import refuse_unpinned_read_while_seeding
from agent_bom.api.read_models._base import documented
from agent_bom.api.read_models.affected import AffectedResponse
from agent_bom.api.request_contract import reject_unknown_query_params
from agent_bom.api.request_tenant import require_request_tenant_id

router = APIRouter()


@router.get("/affected", **documented(AffectedResponse), tags=["findings"], dependencies=[Depends(reject_unknown_query_params)])
async def get_affected(
    request: Request,
    q: str = Query(
        ..., min_length=2, max_length=256, description="An advisory id (CVE-2024-3094, GHSA-...) or a package as name or name@version"
    ),
) -> dict:
    """Every current and past finding for the advisory or package, its exposure window and what the affected hosts reach.

    Findings match exactly on advisory id or package name and version, across
    every scan and ingest the findings queue merges. Reach is the latest graph
    snapshot's recorded topology from the matched advisories, not proof of exploitation.
    """
    tenant_id = require_request_tenant_id(request)
    refuse_unpinned_read_while_seeding("", tenant_id)
    return await anyio.to_thread.run_sync(read_affected, request, tenant_id, q)
