"""Which of the tenant's stored assets an advisory affects.

Endpoint:
    GET /v1/intel/advisories/{advisory_id}/affected

The advisory is the tenant's operator declaration (id or alias), else the
local feed record, NVD CPE ranges included. Rows page with a cursor that
carries the answer's generation: a cursor from a different answer is 409, a
malformed one 422. ``summary`` always describes the whole answer.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

import anyio
from fastapi import APIRouter, HTTPException, Path, Query, Request

from agent_bom.api.advisory_affected_read import tenant_affected_answer
from agent_bom.api.current_graph import refuse_unpinned_read_while_seeding
from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.scanners.advisory_affected import DEFAULT_LIMIT, MAX_LIMIT, AffectedCursorError, page_answer

router = APIRouter()
_TAGS: list[str | Any] = ["intel"]
VerdictFilter = Literal["all", "affected", "possibly_affected", "not_affected"]


def advisory_affected_page(
    tenant_id: str, advisory_id: str, *, verdict: str = "all", q: str | None = None, limit: int = DEFAULT_LIMIT, cursor: str | None = None
) -> dict[str, Any]:
    """Transport-neutral page read; HTTP status semantics are the contract MCP maps to typed errors."""
    answer = tenant_affected_answer(tenant_id, advisory_id)
    if answer is None:
        raise HTTPException(status_code=404, detail="Advisory not found in this tenant's declarations or the local feed")
    try:
        return page_answer(answer, tenant_id=tenant_id, verdict=verdict, q=q, limit=limit, cursor=cursor)
    except AffectedCursorError as exc:
        raise HTTPException(status_code=409 if exc.kind == "stale" else 422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get("/intel/advisories/{advisory_id}/affected", tags=_TAGS)
async def get_advisory_affected_assets(
    request: Request,
    advisory_id: Annotated[str, Path(min_length=3, max_length=96, pattern=r"^[A-Za-z][A-Za-z0-9._:-]+$")],
    verdict: VerdictFilter = "all",
    q: Annotated[str | None, Query(max_length=128)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_LIMIT)] = DEFAULT_LIMIT,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
) -> dict:
    """Affected / possibly affected (distro) / not affected assets for one advisory, with patch targets and graph node ids."""
    tenant_id = require_request_tenant_id(request)
    refuse_unpinned_read_while_seeding("", tenant_id)
    return await anyio.to_thread.run_sync(
        lambda: advisory_affected_page(tenant_id, advisory_id, verdict=verdict, q=q, limit=limit, cursor=cursor)
    )
