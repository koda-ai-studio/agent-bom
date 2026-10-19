"""Api middleware body helpers."""

from __future__ import annotations

import asyncio
import io
import time
import zlib
from collections import deque
from collections.abc import Callable
from functools import partial
from typing import Any

import anyio.to_thread
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from agent_bom.api.error_envelope import (
    with_middleware_error_envelope,
)
from agent_bom.core.settings import env_raw


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Reject oversized bodies and enforce read deadline + throughput floor (slowloris mitigation).

    Three-layer protection:
    1. Content-Length fast-path: reject before reading if header exceeds limit.
    2. Streaming body drain with asyncio timeout: covers chunked/streaming uploads
       that omit Content-Length — a common slowloris vector.
    3. Throughput floor (audit-5 PR-C): even within the 30s deadline an attacker
       can keep a connection alive indefinitely by trickling just enough bytes
       per second to avoid the timeout. Once the body reaches a small warmup
       threshold, the middleware tracks bytes/second over a rolling window and
       aborts the request when sustained throughput drops below the floor.
       Tunable via env so legitimate slow clients in restricted environments
       can keep working.
    """

    _BODY_TIMEOUT_SECONDS = 30
    """Hard read deadline; covers slow legitimate clients but bounds slowloris attacks."""

    _THROUGHPUT_WINDOW_SECONDS = 5.0
    """Rolling window for the throughput floor."""

    _THROUGHPUT_WARMUP_BYTES = 4096
    """Don't enforce the floor until the body crosses this many bytes —
    protects tiny POSTs from being penalised by the connect/TLS handshake delay."""

    _DEFAULT_THROUGHPUT_FLOOR_BPS = 256
    """Bytes/second floor over the rolling window once warmup is past."""

    def __init__(self, app: ASGIApp, max_bytes: int = 10 * 1024 * 1024, path_limits: dict[str, int] | None = None):
        super().__init__(app)
        self._max_bytes = max_bytes
        self._path_limits = path_limits or {}

    @classmethod
    def _throughput_floor_bps(cls) -> int:
        """Read the throughput floor from env so operators can tune it."""
        raw = (env_raw("AGENT_BOM_BODY_MIN_BPS") or "").strip()
        if not raw:
            return cls._DEFAULT_THROUGHPUT_FLOOR_BPS
        try:
            value = int(raw)
        except ValueError:
            return cls._DEFAULT_THROUGHPUT_FLOOR_BPS
        # 0 disables the floor entirely (debug/load-test escape hatch).
        return max(0, value)

    @with_middleware_error_envelope
    async def dispatch(self, request: StarletteRequest, call_next: RequestResponseEndpoint) -> Response:
        path = getattr(request, "scope", {}).get("path", "")
        max_bytes = self._path_limits.get(path, self._max_bytes) if request.method == "POST" else self._max_bytes

        def too_large() -> JSONResponse:
            return JSONResponse(
                status_code=413,
                content={
                    "detail": f"Request body too large: exceeds the configured upload budget ({max_bytes} bytes)",
                    "max_bytes": max_bytes,
                },
            )

        encoding = request.headers.get("content-encoding", "identity").strip().lower()
        compressed = encoding == "gzip" and path in self._path_limits and request.method == "POST"
        if encoding != "identity" and not compressed:
            return JSONResponse(status_code=415, content={"detail": "Unsupported request Content-Encoding"})
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                cl = int(content_length)
                if cl < 0:
                    raise ValueError
            except (ValueError, OverflowError):
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header"})
            if cl > max_bytes:
                return too_large()
        if request.method in ("POST", "PUT", "PATCH") or content_length or compressed:
            error = await _read_limited_body(self, request, max_bytes, compressed, too_large)
            if error is not None:
                return error

        return await call_next(request)


def _append_body_chunk(buffer: io.BytesIO, decoder: Any, max_bytes: int, chunk: bytes) -> bool:
    if decoder is None:
        buffer.write(chunk)
        return buffer.tell() <= max_bytes
    # Bound each inflation allocation independently of compression
    # ratio. Reject concatenated members/trailing bytes and bombs.
    remaining = chunk
    while remaining:
        decoded = decoder.decompress(remaining, min(65536, max_bytes - buffer.tell() + 1))
        buffer.write(decoded)
        if buffer.tell() > max_bytes:
            return False
        if decoder.unused_data:
            raise zlib.error("Trailing gzip data")
        remaining = decoder.unconsumed_tail
    return True


async def _read_limited_body(
    self: MaxBodySizeMiddleware, request: StarletteRequest, max_bytes: int, compressed: bool, too_large: Callable[[], JSONResponse]
) -> JSONResponse | None:
    # Drain every body under the same deadline, including clients that
    # provide Content-Length. BytesIO avoids retaining a chunk list plus
    # a second full-size joined copy. Reuse the cached body downstream.
    min_bps = self._throughput_floor_bps()
    window = self._THROUGHPUT_WINDOW_SECONDS
    warmup = self._THROUGHPUT_WARMUP_BYTES
    chunk_history: deque[tuple[float, int]] = deque()
    buffer = io.BytesIO()
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if compressed else None
    total = 0

    append_chunk = partial(_append_body_chunk, buffer, decoder, max_bytes)

    try:
        start_monotonic = time.monotonic()
        async with asyncio.timeout(self._BODY_TIMEOUT_SECONDS):
            async for chunk in request.stream():
                total += len(chunk)
                if total > max_bytes:
                    return too_large()
                if decoder is not None:
                    within_budget = await anyio.to_thread.run_sync(append_chunk, chunk)
                else:
                    within_budget = append_chunk(chunk)
                if not within_budget:
                    return too_large()
                now_monotonic = time.monotonic()
                chunk_history.append((now_monotonic, len(chunk)))
                if min_bps > 0 and total >= warmup and (now_monotonic - start_monotonic) >= window:
                    cutoff = now_monotonic - window
                    while chunk_history and chunk_history[0][0] < cutoff:
                        chunk_history.popleft()
                    window_bytes = sum(size for _ts, size in chunk_history)
                    elapsed = now_monotonic - chunk_history[0][0] if chunk_history else 0.0
                    if elapsed > 0 and window_bytes / elapsed < min_bps:
                        return JSONResponse(status_code=408, content={"detail": "Request body throughput below configured floor"})
        if decoder is not None and not decoder.eof:
            return JSONResponse(status_code=400, content={"detail": "Incomplete gzip request body"})
    except TimeoutError:
        return JSONResponse(status_code=408, content={"detail": "Request body read timed out"})
    except zlib.error:
        return JSONResponse(status_code=400, content={"detail": "Invalid gzip request body"})

    body = buffer.getvalue()
    request._body = body
    if compressed:
        # Downstream parsers see the decoded representation.
        request.scope["headers"] = [
            (key, value) for key, value in request.scope["headers"] if key.lower() not in {b"content-encoding", b"content-length"}
        ] + [(b"content-length", str(len(body)).encode("ascii"))]
        if hasattr(request, "_headers"):
            del request._headers
    return None
