"""Fail-closed authentication throttling and bounded failure receipts."""

from __future__ import annotations

import asyncio
import contextvars
import logging
import math
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from agent_bom.api import audit_log
from agent_bom.api.auth_failure_store import PostgresAuthFailureStore, SQLiteAuthFailureStore
from agent_bom.api.forwarded_identity import resolve_forwarded_client_ip, trusted_proxy_hops, trusted_proxy_networks
from agent_bom.api.middleware_limits import RateLimitMiddleware, _build_rate_limit_store
from agent_bom.api.rate_limit_store import PostgresRateLimitStore
from agent_bom.core.settings import env_raw

_AUTH_WORKERS = ThreadPoolExecutor(max_workers=8, thread_name_prefix="auth-state")


def _positive_setting(name: str, default: int, maximum: int) -> int:
    value = int(env_raw(name) or str(default))
    if not 1 <= value <= maximum:
        raise ValueError(f"{name} must be between 1 and {maximum}")
    return value


class AuthProtectionUnavailableError(RuntimeError):
    """Authentication cannot proceed without its shared protection state."""


class AuthFailurePolicy:
    def __init__(self) -> None:
        self._outstanding = 0
        self._source_work: dict[str, int] = {}
        self._source_cache: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._source_reads: dict[str, asyncio.Task[int | None]] = {}
        self._source_waiters: dict[str, int] = {}
        self._proxy_warning_emitted = False
        self._unavailable_until = 0.0
        self.limit = _positive_setting("AGENT_BOM_AUTH_FAILURE_LIMIT", 10, 1000)
        self.base = _positive_setting("AGENT_BOM_AUTH_BACKOFF_SECONDS", 30, 3600)
        self.maximum = _positive_setting("AGENT_BOM_AUTH_MAX_BACKOFF_SECONDS", 900, 3600)
        if self.maximum < self.base:
            raise ValueError("Authentication maximum backoff must be at least its base")
        rate_store = _build_rate_limit_store(60)
        sqlite_path = env_raw("AGENT_BOM_DB")
        auth_path = sqlite_path + ".auth-limits.db" if sqlite_path and sqlite_path != ":memory:" else ":memory:"
        self.store = (
            PostgresAuthFailureStore(rate_store) if isinstance(rate_store, PostgresRateLimitStore) else SQLiteAuthFailureStore(auth_path)
        )
        if env_raw("AGENT_BOM_TRUST_PROXY_AUTH") or env_raw("AGENT_BOM_TRUSTED_PROXY_HOPS") or env_raw("AGENT_BOM_TRUSTED_PROXY_CIDRS"):
            self._warn_ignored_forwarding()

    def _warn_ignored_forwarding(self) -> None:
        if self._proxy_warning_emitted or (trusted_proxy_hops() and trusted_proxy_networks()):
            return
        self._proxy_warning_emitted = True
        logging.getLogger(__name__).warning(
            "Forwarded client addresses are ignored without both AGENT_BOM_TRUSTED_PROXY_CIDRS and "
            "AGENT_BOM_TRUSTED_PROXY_HOPS. Clients behind one proxy share source backoff, including valid credentials."
        )

    def source(self, request) -> str:
        if request.headers.get("x-forwarded-for"):
            self._warn_ignored_forwarding()
        return resolve_forwarded_client_ip(
            peer_host=request.client.host if request.client else "unknown",
            forwarded_for=request.headers.get("x-forwarded-for", ""),
        )

    @staticmethod
    def denied(seconds: int):
        return JSONResponse(
            {"detail": "Authentication attempts temporarily limited for this source"},
            status_code=429,
            headers={"Retry-After": str(seconds), "X-RateLimit-Scope": "auth-source"},
        )

    @staticmethod
    def unavailable():
        return JSONResponse({"detail": "Authentication protection unavailable"}, status_code=503, headers={"Retry-After": "5"})

    async def _call(self, function, *args, admission_source: str = "", **kwargs):
        if time.monotonic() < self._unavailable_until:
            raise AuthProtectionUnavailableError("Authentication state temporarily unavailable")
        source = admission_source or str(args[0] if args else "unknown")
        if self._outstanding >= 8 or self._source_work.get(source, 0) >= 2:
            raise AuthProtectionUnavailableError("Authentication source capacity exhausted")
        self._outstanding += 1
        self._source_work[source] = self._source_work.get(source, 0) + 1

        def release(completed):
            self._outstanding -= 1
            self._source_work[source] -= 1
            if not self._source_work[source]:
                del self._source_work[source]
            if completed is not None and not completed.cancelled():
                completed.exception()  # Consume failures after a response timed out.

        def work():
            value = function(*args, **kwargs)
            return value, time.monotonic()

        try:
            deadline = time.monotonic() + 0.5
            pending = None
            try:
                async with asyncio.timeout(0.5):
                    pending = _AUTH_WORKERS.submit(contextvars.copy_context().run, work)
                    task = asyncio.wrap_future(pending)
                    task.add_done_callback(release)
                    # A timed-out request retains its slot until the SQL exits.
                    value, completed_at = await asyncio.shield(task)
                    if completed_at > deadline:
                        raise TimeoutError
                    return value
            except TimeoutError:
                # A busy event loop can deliver a completed store read after
                # its timer. Use the worker's completion time, never stale state.
                if pending is not None and pending.done():
                    value, completed_at = pending.result()
                    if completed_at <= deadline:
                        return value
                raise
        except TimeoutError as exc:
            # Slow work or local overload is scoped to this request. It cannot
            # trip an outage circuit for unrelated sources.
            raise AuthProtectionUnavailableError("Authentication operation deadline exceeded") from exc
        except Exception as exc:  # broad-except: Any backend or audit failure must close the authentication boundary.
            logging.getLogger(__name__).warning("Authentication state unavailable (%s); failing closed", type(exc).__name__)
            self._source_cache.clear()
            self._unavailable_until = time.monotonic() + 5
            raise AuthProtectionUnavailableError("Authentication protection unavailable") from exc
        finally:
            if pending is None:
                release(None)

    async def before(self, request):
        now, source = time.monotonic(), self.source(request)
        if now < self._unavailable_until:
            return self.unavailable()
        cached = self._source_cache.get(source)
        if cached and cached[0] > now:
            self._source_cache.move_to_end(source)
            remaining = max(0, math.ceil(cached[1] - now))
            return self.denied(remaining) if remaining else None
        task = self._source_reads.get(source)
        if task is None:
            if len(self._source_reads) >= 8:
                return self.unavailable()
            task = asyncio.create_task(self._read_source(source))
            self._source_reads[source] = task
            task.add_done_callback(lambda _finished: self._source_reads.pop(source, None))
        if self._source_waiters.get(source, 0) >= 64:
            return self.unavailable()
        self._source_waiters[source] = self._source_waiters.get(source, 0) + 1
        try:
            result = await asyncio.shield(task)
        finally:
            self._source_waiters[source] -= 1
            if not self._source_waiters[source]:
                del self._source_waiters[source]
        if result is None:
            return self.unavailable()
        return self.denied(result) if result else None

    async def _read_source(self, source: str) -> int | None:
        try:
            remaining = await self._call(self.store.remaining, source, time.time())
        except AuthProtectionUnavailableError:
            return None
        self._source_cache[source] = (time.monotonic() + 1, time.monotonic() + remaining)
        self._source_cache.move_to_end(source)
        while len(self._source_cache) > 4096:
            self._source_cache.popitem(last=False)
        return remaining

    async def after(self, request, response):
        # Cookies and generic validation/authorization errors are not evidence
        # of failed authentication. Protocol handlers mark non-401 rejections.
        failed = response.status_code == 401 or (
            response.status_code in {400, 403} and getattr(request.state, "authentication_failed", False)
        )
        if not failed:
            return response
        source, now = self.source(request), time.time()
        self._source_cache.pop(source, None)
        try:
            remaining = await self._call(self.store.record, source, now, limit=self.limit, base=self.base, maximum=self.maximum)
            if await self._call(self.store.audit_allowed, source, now):
                credential = request.headers.get("x-api-key") or request.headers.get("authorization") or request.headers.get("cookie") or ""
                fingerprint = getattr(request.state, "auth_credential_fingerprint", None) or (
                    audit_log.fingerprint_auth_credential(credential) if credential else "absent"
                )
                await self._call(
                    audit_log.log_action,
                    "auth.failed",
                    admission_source=source,
                    actor="unauthenticated",
                    resource="authentication",
                    tenant_id=audit_log.AUTH_FAILURE_AUDIT_TENANT,
                    source=source,
                    hmac_sha256=fingerprint,
                    status_code=response.status_code,
                    reason_code="auth_source_throttled" if remaining else "authentication_failed",
                )
        except AuthProtectionUnavailableError:
            return self.unavailable()
        return self.denied(remaining) if remaining else response


class AuthFailureMiddleware(BaseHTTPMiddleware):
    """Apply the same authentication boundary to standalone MCP HTTP apps."""

    def __init__(self, app):
        super().__init__(app)
        self.policy = AuthFailurePolicy()

    async def dispatch(self, request, call_next):
        if request.url.path in RateLimitMiddleware._HEALTH_EXEMPT_PATHS or RateLimitMiddleware._is_dashboard_static_asset(
            request.url.path, request.method
        ):
            return await call_next(request)
        if request.method == "OPTIONS":
            return await call_next(request)
        if denied := await self.policy.before(request):
            return denied
        return await self.policy.after(request, await call_next(request))
