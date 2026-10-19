"""Proxy trace propagation and sanitized span creation."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from agent_bom.api.tracing import (
    build_traceparent,
    get_tracer,
    inject_current_trace_headers,
    inject_trace_headers,
    parse_baggage,
    parse_traceparent,
    parse_tracestate,
    sanitized_span,
)
from agent_bom.runtime.trace_metadata import inject_jsonrpc_trace_meta as _inject_jsonrpc_trace_meta

_PROXY_TRACER = get_tracer("agent_bom.proxy")


@contextmanager
def proxy_span(name: str) -> Iterator[Any]:
    """Keep all proxy transports on the same sanitized tracing boundary."""
    with sanitized_span(_PROXY_TRACER, name) as span:
        yield span


def _proxy_request_headers(
    headers: dict[str, str] | None = None,
    *,
    traceparent: str | None = None,
    tracestate: str | None = None,
    baggage: str | None = None,
) -> dict[str, str]:
    if traceparent or tracestate or baggage:
        return inject_trace_headers(
            headers,
            traceparent=traceparent,
            tracestate=tracestate,
            baggage=baggage,
        )
    return inject_current_trace_headers(headers)


def _extract_jsonrpc_trace_meta(message: dict[str, object]) -> dict[str, str]:
    """Return bounded W3C trace metadata carried in JSON-RPC `_meta`.

    stdio JSON-RPC has no native header channel, so `_meta` is the least
    surprising place to preserve trace context across proxy boundaries.
    """
    raw_meta = message.get("_meta")
    if not isinstance(raw_meta, dict):
        return {}
    trace_meta: dict[str, str] = {}
    traceparent = parse_traceparent(str(raw_meta.get("traceparent", "")).strip())
    if traceparent:
        trace_meta["traceparent"] = build_traceparent(
            traceparent["trace_id"],
            traceparent["parent_span_id"],
            traceparent["trace_flags"],
        )
    tracestate = parse_tracestate(str(raw_meta.get("tracestate", "")).strip())
    if tracestate:
        trace_meta["tracestate"] = tracestate
    baggage = parse_baggage(str(raw_meta.get("baggage", "")).strip())
    if baggage:
        trace_meta["baggage"] = baggage
    return trace_meta


def _stitch_jsonrpc_trace_meta(
    message: dict[str, object],
    fallback_trace_meta: dict[str, str] | None,
) -> dict[str, object]:
    """Preserve response trace metadata or rehydrate it from the paired request."""
    response_trace_meta = _extract_jsonrpc_trace_meta(message)
    merged = {
        "traceparent": response_trace_meta.get("traceparent") or (fallback_trace_meta or {}).get("traceparent"),
        "tracestate": response_trace_meta.get("tracestate") or (fallback_trace_meta or {}).get("tracestate"),
        "baggage": response_trace_meta.get("baggage") or (fallback_trace_meta or {}).get("baggage"),
    }
    return _inject_jsonrpc_trace_meta(
        message,
        traceparent=merged["traceparent"],
        tracestate=merged["tracestate"],
        baggage=merged["baggage"],
    )


def _control_plane_headers(token: str | None, etag: str | None = None) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if etag:
        headers["If-None-Match"] = etag
    return inject_current_trace_headers(headers)
