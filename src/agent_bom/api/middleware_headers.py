"""Api middleware headers helpers."""

from __future__ import annotations

import logging
import sys
import time
import uuid
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response

from agent_bom import __version__
from agent_bom.api.dashboard_csp import dashboard_csp_header, describe_dashboard_csp_posture
from agent_bom.api.error_envelope import (
    _build_error_envelope,
)
from agent_bom.api.storage_schema import postgres_deployment_configured
from agent_bom.api.tracing import configure_otel_tracing, make_request_trace, record_request_exception
from agent_bom.core.settings import TRUTHY, env_raw, env_str

_logger = logging.getLogger("agent_bom.api.middleware")

_API_CSP = "default-src 'self'"

# /docs (Swagger UI) and /redoc serve HTML shells that load swagger-ui /
# redoc bundles + a favicon from public CDNs (cdn.jsdelivr.net,
# fastapi.tiangolo.com). The strict default-src 'self' API CSP blocks
# them, leaving a blank page. We narrowly relax CSP for these two
# documentation routes — they remain disable-able via
# AGENT_BOM_DISABLE_DOCS for production deployments per the
# _EXEMPT_PATHS toggle below.
_DOCS_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    # Favicon is served from /brand/mark.svg (self); keep jsdelivr for swagger assets.
    "img-src 'self' data: https://cdn.jsdelivr.net; "
    "font-src 'self' data: https://cdn.jsdelivr.net; "
    "worker-src 'self' blob:; "
    "connect-src 'self'"
)


def _content_security_policy(path: str, content_type: str) -> str:
    """Return a route-aware CSP that keeps the API strict and the dashboard usable."""
    if path in {"/docs", "/redoc"} and "text/html" in content_type:
        return _DOCS_CSP
    if "text/html" in content_type and not path.startswith(("/v1/", "/docs", "/redoc", "/openapi.json")):
        return dashboard_csp_header()
    return _API_CSP


def _hsts_max_age_seconds() -> int:
    raw = (env_raw("AGENT_BOM_HSTS_MAX_AGE_SECONDS") or "31536000").strip()
    try:
        return max(0, int(raw))
    except ValueError:
        return 31_536_000


def hsts_header_value() -> str:
    """Return the configured Strict-Transport-Security header value.

    ``preload`` is intentionally opt-in because browser preload enrollment is
    sticky and must be a deliberate operator decision for the deployment domain.
    """

    value = f"max-age={_hsts_max_age_seconds()}; includeSubDomains"
    if env_str("AGENT_BOM_HSTS_PRELOAD").lower() in TRUTHY:
        value += "; preload"
    return value


def describe_security_header_posture() -> dict[str, object]:
    """Return non-secret security-header posture for operator policy surfaces."""

    return {
        "hsts": {
            "header": hsts_header_value(),
            "max_age_seconds": _hsts_max_age_seconds(),
            "include_subdomains": True,
            "preload": (env_str("AGENT_BOM_HSTS_PRELOAD").lower() in TRUTHY),
            "preload_env": "AGENT_BOM_HSTS_PRELOAD",
            "max_age_env": "AGENT_BOM_HSTS_MAX_AGE_SECONDS",
            "preload_guidance": ("Only enable preload after confirming HTTPS is permanent for the domain and every subdomain."),
        },
        "csp": {"api": _API_CSP, "dashboard": describe_dashboard_csp_posture()},
    }


def _is_hashed_build_asset(method: str, path: str, status_code: int) -> bool:
    return method in {"GET", "HEAD"} and status_code in {200, 304} and path.startswith("/_next/static/") and ".." not in path


def _cache_control(method: str, path: str, status_code: int, is_event_stream: bool) -> str:
    if is_event_stream:
        return "no-store, no-transform"
    if _is_hashed_build_asset(method, path, status_code):
        # Public, content-hashed build output: a new build changes the URL, so
        # browsers may keep it instead of refetching every chunk on every page.
        return "public, max-age=31536000, immutable"
    return "no-store"


class TrustHeadersMiddleware(BaseHTTPMiddleware):
    """Add trust + standard security headers to every response."""

    async def dispatch(self, request: StarletteRequest, call_next: RequestResponseEndpoint) -> Response:
        trace_meta = make_request_trace(dict(request.headers))
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        request.state.request_id = request_id
        # A percent-encoded NUL in a path parameter is decoded before routing and
        # then handed to psycopg as a text value, which raises `DataError:
        # PostgreSQL text fields cannot contain NUL (0x00) bytes` deep inside a
        # store and surfaces as a bare 500. Reject the whole request here so the
        # class is closed for every route rather than one path id at a time.
        if "\x00" in request.url.path:
            return _build_error_envelope(
                status_code=400,
                detail="Request path contains a NUL (0x00) byte",
                correlation_id=request_id,
            )
        # Same failure through query parameters (scan_id, node, q, source, ...):
        # 422 matches the per-route identifier validators that predate this.
        if any("\x00" in key or "\x00" in value for key, value in request.query_params.multi_items()):
            return _build_error_envelope(
                status_code=422,
                detail="Query parameter contains a NUL (0x00) byte",
                correlation_id=request_id,
            )
        request.state.trace_id = trace_meta["trace_id"]
        request.state.span_id = trace_meta["span_id"]
        request.state.parent_span_id = trace_meta["parent_span_id"]
        request.state.traceparent = trace_meta["traceparent"]
        request.state.tracestate = trace_meta["tracestate"]
        request.state.baggage = trace_meta["baggage"]
        if not hasattr(request.state, "tenant_id"):
            request.state.tenant_id = "default"
        response = await _dispatch_traced_request(request, call_next, request_id, trace_meta)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Trace-ID"] = str(trace_meta["trace_id"])
        response.headers["X-Span-ID"] = str(trace_meta["span_id"])
        response.headers["traceparent"] = str(trace_meta["traceparent"])
        if trace_meta["parent_span_id"]:
            response.headers["X-Parent-Span-ID"] = str(trace_meta["parent_span_id"])
        if trace_meta["tracestate"]:
            response.headers["tracestate"] = str(trace_meta["tracestate"])
        if trace_meta["baggage"]:
            response.headers["baggage"] = str(trace_meta["baggage"])
        response.headers["X-Agent-Bom-Read-Only"] = "true"
        response.headers["X-Agent-Bom-No-Credential-Storage"] = "true"
        response.headers["X-Agent-Bom-Version"] = __version__
        # Standard security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        # SSE must reach clients before connection renewal. Keep the security
        # no-store policy while disabling intermediary compression/buffering.
        is_event_stream = response.headers.get("content-type", "").split(";", 1)[0].strip().lower() == "text/event-stream"
        response.headers["Cache-Control"] = _cache_control(request.method, request.url.path, response.status_code, is_event_stream)
        response.headers["Content-Security-Policy"] = _content_security_policy(
            request.url.path,
            response.headers.get("content-type", ""),
        )
        response.headers["Strict-Transport-Security"] = hsts_header_value()
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-API-Version"] = "v1"
        return response


async def _dispatch_traced_request(
    request: StarletteRequest, call_next: RequestResponseEndpoint, request_id: str, trace_meta: dict[str, Any]
) -> Response:
    tenant_token = None
    otel_cm = None
    span = None
    start = time.perf_counter()
    try:
        if configure_otel_tracing():
            from opentelemetry import trace

            tracer = trace.get_tracer("agent_bom.api")
            # Disable SDK defaults that export raw exception messages and tracebacks.
            otel_cm = tracer.start_as_current_span(
                f"{request.method} {request.url.path}", record_exception=False, set_status_on_exception=False
            )
            span = otel_cm.__enter__()
            span.set_attribute("http.request.method", request.method)
            span.set_attribute("url.path", request.url.path)
            span.set_attribute("agent_bom.request_id", request_id)
            span.set_attribute("agent_bom.trace_id", str(trace_meta["trace_id"]))
            span.set_attribute("agent_bom.span_id", str(trace_meta["span_id"]))
            span.set_attribute("agent_bom.incoming_traceparent", bool(trace_meta["incoming_traceparent"]))
            if trace_meta["parent_span_id"]:
                span.set_attribute("agent_bom.parent_span_id", str(trace_meta["parent_span_id"]))
            if trace_meta["tracestate"]:
                span.set_attribute("agent_bom.tracestate_present", True)
            if trace_meta["baggage"]:
                span.set_attribute("agent_bom.baggage_present", True)
        if postgres_deployment_configured():
            from agent_bom.api.postgres_common import set_current_tenant

            tenant_token = set_current_tenant(getattr(request.state, "tenant_id", "default"))
        response = await call_next(request)
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        _logger.info(
            "api request complete method=%s path=%s status=%s request_id=%s trace_id=%s span_id=%s tenant_id=%s duration_ms=%s",
            request.method,
            request.url.path,
            getattr(response, "status_code", "unknown"),
            request_id,
            trace_meta["trace_id"],
            trace_meta["span_id"],
            getattr(request.state, "tenant_id", "default"),
            elapsed_ms,
        )
        if span is not None:
            span.set_attribute("http.response.status_code", int(getattr(response, "status_code", 500)))
            span.set_attribute("agent_bom.tenant_id", str(getattr(request.state, "tenant_id", "default")))
            span.set_attribute("agent_bom.duration_ms", elapsed_ms)
            span.set_attribute("http.route", str(request.scope.get("path", request.url.path)))
            if getattr(request.state, "api_key_role", None):
                span.set_attribute("agent_bom.auth.role", str(request.state.api_key_role))
            if getattr(request.state, "api_key_name", None):
                span.set_attribute("agent_bom.auth.subject", str(request.state.api_key_name))
            if request.client and request.client.host:
                span.set_attribute("client.address", str(request.client.host))
    except Exception as exc:
        if span is not None:
            record_request_exception(span, exc)
        raise
    finally:
        if tenant_token is not None:
            from agent_bom.api.postgres_common import reset_current_tenant

            reset_current_tenant(tenant_token)
        if otel_cm is not None:
            otel_cm.__exit__(*sys.exc_info())
    return response
