"""Request-level admission for graph routes: one backpressure reservation per request."""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Callable

from fastapi import HTTPException, Request
from fastapi.routing import APIRoute
from starlette.responses import Response

from agent_bom.api.current_graph import CURRENT_PREFIX
from agent_bom.api.finding_read_context import finding_read_scope
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.core.estate_read_boundary import estate_read_boundary

_graph_request_admitted: ContextVar[bool] = ContextVar("graph_request_admitted", default=False)


class EstateReadRoute(APIRoute):
    """A route whose unpinned reads of the current estate refuse while the demo seed lands."""

    def get_route_handler(self) -> Callable[[Request], Any]:
        handler = super().get_route_handler()

        async def bounded_handler(request: Request) -> Response:
            with estate_read_boundary():
                return await handler(request)

        return bounded_handler


async def _require_addressed_snapshot(request: Request) -> None:
    """A read addressed to an unknown snapshot is 404, not an empty page marked complete.

    Current-estate ids are left to the route: a retired generation is a 409.
    """
    from agent_bom.api.routes.graph_routes import _runtime

    scan_id = request.query_params.get("scan_id") or request.query_params.get("scan") or ""
    if scan_id and not scan_id.startswith(CURRENT_PREFIX):
        await _runtime.require_graph_snapshot_ids(_runtime._get_graph_store_or_503(), _runtime._tenant(request), scan_id)


class _GraphAdmissionRoute(APIRoute):
    """Reserve capacity for the whole request, before any graph work starts.

    Per-operation admission could reject serialization after a slow store read
    had already consumed the expensive work. Nested store/compute calls reuse
    this request's reservation; subsequent requests are rejected before reads.
    Authentication and tenant enforcement remain in the existing middleware
    and route dependencies.
    """

    def get_route_handler(self) -> Callable[[Request], Any]:
        handler = super().get_route_handler()

        async def admitted_handler(request: Request) -> Response:
            try:
                async with adaptive_backpressure("graph"):
                    token = _graph_request_admitted.set(True)
                    try:
                        with finding_read_scope(), estate_read_boundary():
                            await _require_addressed_snapshot(request)
                            return await handler(request)
                    finally:
                        _graph_request_admitted.reset(token)
            except BackpressureRejectedError as exc:
                raise HTTPException(status_code=429, detail=exc.to_dict(), headers={"Retry-After": str(exc.retry_after_seconds)}) from exc

        return admitted_handler
