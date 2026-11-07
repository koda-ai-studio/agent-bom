"""Fail-closed authentication throttling and bounded failure receipts."""

from __future__ import annotations

import asyncio
import contextvars
import hashlib
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from agent_bom.api import audit_log
from agent_bom.api.auth_failure_store import PostgresAuthFailureStore, SQLiteAuthFailureStore
from agent_bom.api.forwarded_identity import resolve_forwarded_client_ip
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
        self._work_slots = asyncio.Semaphore(8)
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

    @staticmethod
    def source(request) -> str:
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

    async def _call(self, function, *args, **kwargs):
        if time.monotonic() < self._unavailable_until:
            raise AuthProtectionUnavailableError("Authentication state temporarily unavailable")

        def release(completed):
            self._work_slots.release()
            if not completed.cancelled():
                completed.exception()  # Consume failures after a response timed out.

        try:
            async with asyncio.timeout(0.5):
                await self._work_slots.acquire()
                work = partial(function, *args, **kwargs)
                task = asyncio.get_running_loop().run_in_executor(_AUTH_WORKERS, contextvars.copy_context().run, work)
                task.add_done_callback(release)
                # A timed-out request retains its slot until the SQL exits.
                return await asyncio.shield(task)
        except Exception as exc:  # broad-except: Any backend or audit failure must close the authentication boundary.
            logging.getLogger(__name__).warning("Authentication state unavailable (%s); failing closed", type(exc).__name__)
            self._unavailable_until = time.monotonic() + 5
            raise AuthProtectionUnavailableError("Authentication protection unavailable") from exc

    async def before(self, request):
        try:
            remaining = await self._call(self.store.remaining, self.source(request), time.time())
        except AuthProtectionUnavailableError:
            return self.unavailable()
        return self.denied(remaining) if remaining else None

    async def after(self, request, response):
        # 403 with an authenticated identity is authorization, not bad auth.
        # OAuth token/callback failures also use 400 per their protocol.
        failed = response.status_code == 401 or (
            not getattr(request.state, "auth_method", None)
            and response.status_code in {400, 403}
            and (request.url.path.startswith(("/oauth/", "/v1/auth/")) or request.cookies)
        )
        if not failed:
            return response
        source, now = self.source(request), time.time()
        try:
            remaining = await self._call(self.store.record, source, now, limit=self.limit, base=self.base, maximum=self.maximum)
            if await self._call(self.store.audit_allowed, source, now):
                credential = request.headers.get("x-api-key") or request.headers.get("authorization") or request.headers.get("cookie") or ""
                fingerprint = getattr(request.state, "auth_credential_fingerprint", None) or (
                    hashlib.sha256(credential.encode()).hexdigest() if credential else "absent"
                )
                await self._call(
                    audit_log.log_action,
                    "auth.failed",
                    actor="unauthenticated",
                    resource="authentication",
                    tenant_id="default",
                    source=source,
                    payload_sha256=fingerprint,
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
