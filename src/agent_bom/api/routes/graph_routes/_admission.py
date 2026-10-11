"""Request-level admission for graph routes: one backpressure reservation per request."""

from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Callable

from fastapi import HTTPException, Request
from fastapi.routing import APIRoute
from starlette.responses import Response

from agent_bom.api.finding_read_context import finding_read_scope
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure

_graph_request_admitted: ContextVar[bool] = ContextVar("graph_request_admitted", default=False)


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
                        with finding_read_scope():
                            return await handler(request)
                    finally:
                        _graph_request_admitted.reset(token)
            except BackpressureRejectedError as exc:
                raise HTTPException(status_code=429, detail=exc.to_dict(), headers={"Retry-After": str(exc.retry_after_seconds)}) from exc

        return admitted_handler
