"""Authenticated collection routes; provider/network failures never advance checkpoints."""

import sqlite3
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Request
from starlette.concurrency import run_in_threadpool

from agent_bom.api.request_tenant import require_request_tenant_id
from agent_bom.api.trace_collection import service
from agent_bom.api.trace_collection.admission import run_collection
from agent_bom.api.trace_collection.contracts import CollectionConflictError, CollectionReceipt, CollectionRequest

try:
    from psycopg import Error as PostgresError
except ImportError:
    PostgresError = sqlite3.Error  # type: ignore[misc,assignment]

router = APIRouter()


def _invoke(request: Request, body: CollectionRequest, *, advance: bool) -> CollectionReceipt:
    tenant = require_request_tenant_id(request)
    actor = getattr(request.state, "api_key_name", "") or "authenticated-user"
    try:
        return (service.collect if advance else service.status)(tenant, body.connection_id, actor=actor)
    except CollectionConflictError as exc:
        raise HTTPException(
            status_code=409, detail="Collection is busy, cooling down, or its scope changed. Inspect collection status before retrying."
        ) from exc
    except HTTPException:
        raise
    except (OSError, sqlite3.Error, PostgresError, RuntimeError) as exc:
        # Storage availability must fail closed, with no ephemeral fallback.
        raise HTTPException(status_code=503, detail="Collection storage is unavailable. Retry from the saved checkpoint.") from exc


@router.post(
    "/traces/connectors/langfuse/collect",
    response_model=CollectionReceipt,
    tags=["observability"],
)
async def collect_trace_page(request: Request, body: CollectionRequest) -> CollectionReceipt:
    return await run_collection(lambda: _invoke(request, body, advance=True))


@router.get(
    "/traces/connectors/langfuse/collection",
    response_model=CollectionReceipt,
    tags=["observability"],
)
async def collection_status(request: Request, connection_id: Annotated[str, Query(pattern=r"^[a-zA-Z0-9_-]{1,80}$")]) -> CollectionReceipt:
    # Keep credential/audit/SQL work off-loop while validating this bounded
    # receipt without an additional trip through the shared worker queue.
    return await run_in_threadpool(_invoke, request, CollectionRequest(connection_id=connection_id), advance=False)
