"""Request-path helpers for ``POST /v1/results/push`` that keep the event loop free.

The body is parsed and validated in a worker thread (a 100+ MB report takes
seconds of CPU), idempotency fingerprints and claims run off-loop, and a key
that another request is still committing answers ``202`` with ``Retry-After``
instead of parking the caller behind that commit.
"""

from __future__ import annotations

import asyncio
import math
import re
from typing import Any, cast

import pydantic_core
from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from starlette.responses import JSONResponse

from agent_bom.api.middleware_body import BODY_OWNER_SCOPE_KEY
from agent_bom.api.models import JobStatus, PushPayload, ScanJob
from agent_bom.api.observability_push_receipts import _pushed_job_has_persisted_graph, _pushed_job_receipt
from agent_bom.api.push_ingest import (
    PUSH_RETRY_AFTER_SECONDS,
    accepted_push_receipt,
    failed_push_receipt,
    push_status_url,
    redispatch_pending_push,
)
from agent_bom.api.stores import _get_store

#: The route reads the raw body itself so validation runs off the event loop;
#: the published request contract is unchanged.
PUSH_REQUEST_BODY_OPENAPI: dict[str, Any] = {
    "requestBody": {
        "required": True,
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/PushPayload"}}},
    }
}
PUSH_ACCEPTED_RESPONSES: dict[int | str, dict[str, Any]] = {
    202: {
        "description": (
            "Accepted for asynchronous ingest (``Prefer: respond-async``), or an identical push is still "
            "being committed. Poll ``status_url`` after ``Retry-After`` seconds."
        )
    }
}
_ACTIVE_STATUSES = {JobStatus.PENDING.value, JobStatus.RUNNING.value}
# A parse that refuses NaN/Infinity literals still overflows a huge number to
# infinity: a 3+ figure positive exponent or a 309+ figure run. Only a body
# with such a token is walked.
_OVERFLOW_CANDIDATE = re.compile(rb"(?<![0-9A-Za-z.])-?\d+(?:\.\d*)?[eE]\+?\d{3,}(?![0-9A-Za-z])|\d{309,}")


def _non_finite_path(value: Any) -> tuple[int | str, ...] | None:
    """Location of the first NaN or infinity in a parsed JSON tree, depth first."""
    stack: list[tuple[Any, tuple[int | str, ...]]] = [(value, ())]
    while stack:
        node, path = stack.pop()
        if isinstance(node, float):
            if not math.isfinite(node):
                return path
        elif isinstance(node, dict):
            stack.extend((child, (*path, key)) for key, child in reversed(list(node.items())))
        elif isinstance(node, list):
            stack.extend((child, (*path, index)) for index, child in reversed(list(enumerate(node))))
    return None


def _reject_non_finite(parsed: Any) -> None:
    path = _non_finite_path(parsed)
    if path is None:
        return
    raise ValidationError.from_exception_data(
        PushPayload.__name__, [{"type": "finite_number", "loc": path, "input": None}], input_type="json"
    )


def _parse_finite_json(raw: bytes) -> Any:
    """Parse JSON, rejecting NaN and infinity: JSON has no such numbers and storage cannot encode them."""
    try:
        parsed = pydantic_core.from_json(raw, allow_inf_nan=False)
    except ValueError:
        _reject_non_finite(pydantic_core.from_json(raw))
        raise
    if _OVERFLOW_CANDIDATE.search(raw):
        _reject_non_finite(parsed)
    return parsed


def _validate_push_body(raw: bytes) -> PushPayload:
    """Parse once with the validator's own JSON parser, then validate the parsed report.

    A model validated from parsed Python data shares its strings and nested
    containers, so a 200-agent report costs one parsed copy (78 MiB) instead of
    a JSON-validated model (203 MiB) plus the admission dump (153 MiB). The
    parser is the one ``model_validate_json`` uses: the same NaN, duplicate-key
    and surrogate handling. Rejected input is validated again as JSON so a 422
    keeps the JSON validator's wording ("valid array", "an object"). NaN and
    infinity are rejected as ``finite_number`` at their location.
    """
    try:
        parsed = _parse_finite_json(raw)
        body = PushPayload.model_validate(parsed)
    except ValidationError as exc:
        if any(error.get("type") == "finite_number" for error in exc.errors()):
            raise
        return PushPayload.model_validate_json(raw)
    except ValueError:
        return PushPayload.model_validate_json(raw)
    if isinstance(parsed, dict):
        body._parsed_body = parsed
    return body


def _release_buffered_body(request: Request) -> None:
    """Drop every cached copy of a body the route has consumed; both live until the response otherwise."""
    request.__dict__.pop("_body", None)
    owner_ref = request.scope.get(BODY_OWNER_SCOPE_KEY)
    owner = owner_ref() if callable(owner_ref) else None
    if owner is not None:
        owner.__dict__.pop("_body", None)


async def parse_push_payload(request: Request) -> PushPayload:
    """Validate the buffered body in a worker thread; 422s keep FastAPI's error shape."""

    raw = await request.body()
    _release_buffered_body(request)
    try:
        return await asyncio.to_thread(_validate_push_body, raw or b"{}")
    except ValidationError as exc:
        errors = [{**error, "loc": ("body", *error.get("loc", ()))} for error in exc.errors(include_url=False)]
        raise RequestValidationError(errors) from None


def accepted_response(receipt: dict[str, Any], *, status_code: int = 202) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=receipt,
        headers={"Retry-After": str(PUSH_RETRY_AFTER_SECONDS), "Location": receipt["status_url"]},
    )


def in_flight_response(job_id: str, *, source_id: str) -> JSONResponse:
    """An identical push holds the key: tell the caller where to look, never wait on it."""

    return accepted_response(accepted_push_receipt(job_id, source_id=source_id, ingest="committing"))


def durable_job_status(job_id: str, tenant_id: str) -> str | None:
    """Status of a job without decoding its (possibly 100 MB) result."""

    store = _get_store()
    view = getattr(store, "get_status_view", None)
    if callable(view):
        row = view(job_id, tenant_id)
        return str(row.get("status")) if isinstance(row, dict) else None
    job = store.get(job_id, tenant_id=tenant_id)
    return job.status.value if job is not None else None


def _load_job(job_id: str, tenant_id: str) -> ScanJob | None:
    return cast(ScanJob | None, _get_store().get(job_id, tenant_id=tenant_id))


async def committed_push_response(job_id: str, *, tenant_id: str, source_id: str) -> dict | JSONResponse | None:
    """Answer a replay of a committed key from the durable job, or ``None`` to re-admit.

    ``done`` replays the original stored receipt; ``pending``/``running`` returns
    the accepted receipt (and re-offers the job, which is idempotent); ``failed``
    returns ``None`` so the caller re-admits the same deterministic job. So does
    a job retention or deletion removed: the key outlives the data it answered
    for, and the same content pushed again is new evidence to store.
    """

    status = await asyncio.to_thread(durable_job_status, job_id, tenant_id)
    if status is None:
        return None
    if status == JobStatus.DONE.value:
        job = await asyncio.to_thread(_load_job, job_id, tenant_id)
        if job is None:  # pragma: no cover - deleted between the two reads
            return None
        # Older writers published DONE before graph commit. Missing completion
        # evidence must remain retryable, never become a successful replay.
        if not _pushed_job_has_persisted_graph(job):
            return None
        return _pushed_job_receipt(job)
    if status in _ACTIVE_STATUSES:
        job = await asyncio.to_thread(_load_job, job_id, tenant_id)
        if job is not None:
            await asyncio.to_thread(redispatch_pending_push, job)
        return accepted_response(accepted_push_receipt(job_id, source_id=source_id, ingest=status))
    return None


async def push_status_receipt(job_id: str, *, tenant_id: str) -> dict:
    """Receipt for ``GET /v1/results/push/{job_id}``; tenant-scoped, 404 when absent."""

    status = await asyncio.to_thread(durable_job_status, job_id, tenant_id)
    if status is None:
        raise HTTPException(status_code=404, detail="Pushed result not found")
    if status in _ACTIVE_STATUSES:
        return accepted_push_receipt(job_id, source_id="", ingest=status)
    job = await asyncio.to_thread(_load_job, job_id, tenant_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Pushed result not found")
    result = job.result if isinstance(job.result, dict) else {}
    if not result.get("pushed"):
        raise HTTPException(status_code=404, detail="Pushed result not found")
    if job.status is JobStatus.DONE and _pushed_job_has_persisted_graph(job):
        receipt = _pushed_job_receipt(job)
        receipt["status_url"] = push_status_url(job_id)
        return receipt
    return failed_push_receipt(job_id, source_id=job.source_id or "")
