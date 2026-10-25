"""Api middleware limits helpers."""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from collections.abc import Callable
from datetime import datetime
from datetime import datetime as _dt
from datetime import timezone as _tz
from functools import lru_cache
from typing import Any

import anyio.to_thread
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from agent_bom.api.error_envelope import (
    with_middleware_error_envelope,
)
from agent_bom.api.rate_limit_store import FailOpenRateLimitStore, record_rate_limit_hit
from agent_bom.api.rate_limit_store import InMemoryRateLimitStore as InMemoryRateLimitStore
from agent_bom.api.rate_limit_store import PostgresRateLimitStore as PostgresRateLimitStore
from agent_bom.api.storage.deployment import (
    _configured_api_replicas,
    _production_or_clustered_control_plane,
    clustered_control_plane_required,
)
from agent_bom.api.storage_schema import postgres_deployment_configured
from agent_bom.core.settings import env_raw

_logger = logging.getLogger("agent_bom.api.middleware")

_RATE_LIMIT_FINGERPRINT_FALLBACK = secrets.token_bytes(32)

_TENANT_SCOPED_AUTH_METHODS = {
    "api_key",
    "browser_session",
    "browser_session_static_api_key",
    "oidc",
    "proxy_header",
    "saml",
    "scim_bearer",
    "static_api_key",
}

# Auth methods whose ``request.state.tenant_id`` was set from a KeyStore-verified
# ApiKey. Re-verifying the same raw key can only return the same tenant, so the
# rate limiter reads the state instead of paying a second scrypt derivation.
# Deliberately narrow: "static_api_key" is NOT here because the static key never
# reaches the KeyStore, so its verify returns None and buckets differently.
_API_KEY_VERIFIED_AUTH_METHODS = {"api_key", "saml"}

DEFAULT_SCAN_RATE_LIMIT_RPM = 600

# Anonymous / unidentified read budget. Kept where it was so raising the
# authenticated budget below does not widen the pre-auth abuse surface.
DEFAULT_READ_RATE_LIMIT_RPM = DEFAULT_SCAN_RATE_LIMIT_RPM * 5

# Reads on a bucket we resolved to a tenant or API key. A cursor walk of a
# large tenant is thousands of requests, so a connector or SIEM doing a full
# sync through the public API was being 429'd partway through a legitimate
# paginated read. Still bounded, and still under the coarse per-IP ceiling.
DEFAULT_AUTHENTICATED_READ_RATE_LIMIT_RPM = DEFAULT_READ_RATE_LIMIT_RPM * 2

MAX_RATE_LIMIT_RPM = 60_000

# Coarse per-client-IP ceiling enforced OUTERMOST (before authentication) so an
# unauthenticated flood is capped regardless of auth outcome. Deliberately much
# higher than the per-tenant read budget so it never trips legitimate
# single-tenant traffic; it exists to bound abuse from a single source address.
DEFAULT_GLOBAL_IP_RATE_LIMIT_RPM = DEFAULT_READ_RATE_LIMIT_RPM * 4


def _build_rate_limit_store(window_seconds: int) -> InMemoryRateLimitStore | PostgresRateLimitStore:
    """Build the shared/in-memory limiter store with fail-closed semantics."""
    if postgres_deployment_configured():
        try:
            return PostgresRateLimitStore(window_seconds=window_seconds)
        except Exception as exc:
            raise RuntimeError(
                f"Configured Postgres rate limiter could not initialize: {str(exc).rstrip('.')}. "
                "Refusing to fall back to process-local state."
            ) from exc
    if _shared_rate_limit_required():
        raise RuntimeError(
            "Shared rate limiting is required for multi-replica or fail-closed deployments. "
            "Configure AGENT_BOM_POSTGRES_URL before starting the API."
        )
    return InMemoryRateLimitStore(window_seconds=window_seconds)


def _build_admission_rate_limit_store(window_seconds: int) -> InMemoryRateLimitStore | FailOpenRateLimitStore:
    """Request-path limiter: a shared store outage degrades to local limits instead of failing requests."""
    store = _build_rate_limit_store(window_seconds)
    if isinstance(store, InMemoryRateLimitStore):
        return store
    return FailOpenRateLimitStore(store, window_seconds=window_seconds)


def global_ip_rate_limit_rpm() -> int:
    """Resolve the coarse per-IP ceiling, honoring an operator override."""
    raw = (env_raw("AGENT_BOM_GLOBAL_IP_RATE_LIMIT_RPM") or "").strip()
    if raw:
        try:
            return _validate_rate_limit("global_ip_rpm", int(raw), max_rpm=MAX_RATE_LIMIT_RPM * 5)
        except ValueError:
            _logger.warning("Invalid AGENT_BOM_GLOBAL_IP_RATE_LIMIT_RPM=%r; using default", raw)
    return DEFAULT_GLOBAL_IP_RATE_LIMIT_RPM


def _validate_rate_limit(name: str, value: int, *, max_rpm: int) -> int:
    try:
        rpm = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if rpm < 1:
        raise ValueError(f"{name} must be at least 1")
    if rpm > max_rpm:
        raise ValueError(f"{name} must be <= {max_rpm}")
    return rpm


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Tenant-aware sliding window rate limiter with bounded memory.

    Write / ingest POSTs (scan jobs and CWPP runtime-evidence ingest) share the
    tighter ``scan_rpm`` bucket. Everything else uses ``read_rpm``.
    """

    # Health/readiness/liveness probes must never self-throttle: orchestrators
    # (k8s, ELB, uptime monitors) hit these on short intervals and a probe storm
    # would otherwise consume the per-tenant/IP read budget and 429 the probes.
    # GlobalRateLimitMiddleware exempts them as well: they are constant-cost,
    # unauthenticated handlers that must answer even when the shared limiter
    # backend is unavailable.
    _HEALTH_EXEMPT_PATHS = frozenset(
        {
            "/health",
            "/healthz",
            "/livez",
            "/readyz",
            "/ping",
        }
    )
    # Write/ingest doors that must not burn the generous read RPM budget.
    _WRITE_RATE_LIMIT_PATHS = frozenset(
        {
            "/v1/cloud/runtime-evidence/ingest",
            "/v1/cloud/connections/events/ingest",
        }
    )

    def __init__(
        self,
        app: ASGIApp,
        scan_rpm: int = DEFAULT_SCAN_RATE_LIMIT_RPM,
        read_rpm: int = DEFAULT_READ_RATE_LIMIT_RPM,
        authenticated_read_rpm: int = DEFAULT_AUTHENTICATED_READ_RATE_LIMIT_RPM,
        *,
        get_key_store: Callable[[], Any],
    ):
        super().__init__(app)
        self._get_key_store = get_key_store
        self._scan_rpm = _validate_rate_limit("scan_rpm", scan_rpm, max_rpm=MAX_RATE_LIMIT_RPM)
        self._read_rpm = _validate_rate_limit("read_rpm", read_rpm, max_rpm=MAX_RATE_LIMIT_RPM * 5)
        self._authenticated_read_rpm = _validate_rate_limit(
            "authenticated_read_rpm", authenticated_read_rpm, max_rpm=MAX_RATE_LIMIT_RPM * 10
        )
        self._window = 60
        self._store = self._build_store()

    def _build_store(self) -> InMemoryRateLimitStore | FailOpenRateLimitStore:
        return _build_admission_rate_limit_store(self._window)

    async def _resolve_tenant_scope(self, request: StarletteRequest, raw_key: str) -> str | None:
        tenant_id = getattr(request.state, "tenant_id", "").strip() or None
        auth_method = str(getattr(request.state, "auth_method", "") or "")
        # APIKeyMiddleware sets ``tenant_id`` and ``auth_method`` together from
        # the very ApiKey it just verified, so for these methods the state IS the
        # answer and re-deriving it is pure waste — a second ~21.5ms scrypt on
        # every authenticated request. The broader check below deliberately
        # excludes "default", which is exactly the single-tenant and hosted-demo
        # case, so without this clause the common path paid the cost every time.
        if tenant_id and auth_method in _API_KEY_VERIFIED_AUTH_METHODS:
            return tenant_id
        if tenant_id and tenant_id != "default" and auth_method in _TENANT_SCOPED_AUTH_METHODS:
            return tenant_id
        if raw_key:
            # ``verify`` runs the same ~21ms scrypt (or a blocking DB read) as the
            # auth middleware. When APIKeyMiddleware has already authenticated the
            # request the guard above short-circuits, but in the anonymous/demo
            # deployment (APIKeyMiddleware removed) this is the only verify on the
            # request path — offload it so rate-limit bucketing never stalls the
            # event loop.
            resolved = await anyio.to_thread.run_sync(self._get_key_store().verify, raw_key)
            if resolved and resolved.tenant_id:
                return resolved.tenant_id
        return None

    async def _bucket_key(self, request: StarletteRequest, is_scan: bool) -> str:
        bucket_type = "scan" if is_scan else "read"
        auth = request.headers.get("authorization", "")
        raw_key = auth[7:] if auth.startswith("Bearer ") else request.headers.get("x-api-key", "")
        tenant_scope = await self._resolve_tenant_scope(request, raw_key)
        if tenant_scope:
            scope = f"tenant:{tenant_scope}"
        elif raw_key:
            auth_hash = _rate_limit_fingerprint(raw_key)
            scope = f"auth:{auth_hash}"
        else:
            client_ip = request.client.host if request.client else "unknown"
            scope = f"ip:{client_ip}"
        return f"{scope}:{bucket_type}"

    @staticmethod
    def _is_dashboard_static_asset(path: str, method: str) -> bool:
        if method not in {"GET", "HEAD"}:
            return False
        if path.startswith("/_next/"):
            return True
        if path in {"/favicon.ico", "/robots.txt", "/manifest.json", "/apple-touch-icon.png"}:
            return True
        return False

    @classmethod
    def _is_write_rate_limited(cls, path: str, method: str) -> bool:
        """True when the request should consume the tighter scan/write RPM bucket."""
        if method != "POST":
            return False
        if path.startswith("/v1/scan"):
            return True
        if path.startswith("/v1/cloud/connections"):
            return True
        return path in cls._WRITE_RATE_LIMIT_PATHS

    @with_middleware_error_envelope
    async def dispatch(self, request: StarletteRequest, call_next: RequestResponseEndpoint) -> Response:
        if self._is_dashboard_static_asset(request.url.path, request.method):
            return await call_next(request)

        if request.url.path in self._HEALTH_EXEMPT_PATHS:
            return await call_next(request)

        now = time.time()

        is_scan = self._is_write_rate_limited(request.url.path, request.method)
        key = await self._bucket_key(request, is_scan)
        if is_scan:
            limit = self._scan_rpm
        elif key.startswith("ip:"):
            # No tenant and no API key resolved — the anonymous budget, which
            # is deliberately tighter than the authenticated one below.
            limit = self._read_rpm
        else:
            limit = self._authenticated_read_rpm

        hit_count, reset_at = await record_rate_limit_hit(self._store, key, now)
        remaining = max(0, limit - hit_count)

        if hit_count > limit:
            retry_after = max(int(reset_at - now), 1)
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_at),
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_at)
        return response


class GlobalRateLimitMiddleware(BaseHTTPMiddleware):
    """Coarse per-client-IP request ceiling enforced OUTERMOST.

    Mounted before :class:`APIKeyMiddleware` so an unauthenticated flood is
    capped regardless of auth outcome — a rejected (401) request never reaches
    the inner tenant/auth-scoped :class:`RateLimitMiddleware`, so without this
    backstop an anonymous attacker could pound the auth layer without being
    throttled. Keyed on the transport peer address; the inner limiter keeps
    fine-grained per-tenant budgets.
    """

    def __init__(self, app: ASGIApp, rpm: int = DEFAULT_GLOBAL_IP_RATE_LIMIT_RPM):
        super().__init__(app)
        self._rpm = _validate_rate_limit("global_ip_rpm", rpm, max_rpm=MAX_RATE_LIMIT_RPM * 5)
        self._window = 60
        self._store = _build_admission_rate_limit_store(self._window)

    def _bucket_key(self, request: StarletteRequest) -> str:
        client_ip = request.client.host if request.client else "unknown"
        return f"global-ip:{client_ip}"

    @with_middleware_error_envelope
    async def dispatch(self, request: StarletteRequest, call_next: RequestResponseEndpoint) -> Response:
        if RateLimitMiddleware._is_dashboard_static_asset(request.url.path, request.method):
            return await call_next(request)
        # Probes are unauthenticated, constant-cost handlers; they must keep
        # answering when the shared limiter backend is slow or down.
        if request.url.path in RateLimitMiddleware._HEALTH_EXEMPT_PATHS:
            return await call_next(request)

        now = time.time()
        key = self._bucket_key(request)
        hit_count, reset_at = await record_rate_limit_hit(self._store, key, now)
        if hit_count > self._rpm:
            retry_after = max(int(reset_at - now), 1)
            return JSONResponse(
                status_code=429,
                content={"detail": "Global rate limit exceeded"},
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Scope": "global-ip",
                },
            )
        return await call_next(request)


def _shared_rate_limit_required() -> bool:
    return clustered_control_plane_required()


def get_rate_limit_runtime_status() -> dict[str, object]:
    """Report whether API rate limiting is shared across replicas."""
    postgres_configured = postgres_deployment_configured()
    replicas = _configured_api_replicas()
    shared_required = _shared_rate_limit_required()
    backend = "postgres_shared" if postgres_configured else "inmemory_single_process"
    return {
        "backend": backend,
        "postgres_configured": postgres_configured,
        "configured_api_replicas": replicas,
        "shared_required": shared_required,
        "shared_across_replicas": postgres_configured,
        "fail_closed": postgres_configured or shared_required,
        "message": (
            "Rate limiting uses Postgres-backed shared state across replicas."
            if postgres_configured
            else (
                "Rate limiting is process-local only because the API is configured for a single replica. "
                "Multi-replica deployments must configure AGENT_BOM_POSTGRES_URL."
            )
        ),
    }


def _rate_limit_fingerprint_key() -> bytes:
    from agent_bom.api.secret_source import resolve_secret

    key = resolve_secret("AGENT_BOM_RATE_LIMIT_KEY")
    return key.encode() if key else _RATE_LIMIT_FINGERPRINT_FALLBACK


@lru_cache(maxsize=4096)
def _rate_limit_fingerprint(raw_key: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        raw_key.encode(),
        _rate_limit_fingerprint_key(),
        200_000,
        dklen=8,
    ).hex()


def get_rate_limit_key_status(now: "datetime | None" = None) -> dict:
    """Report rate-limit fingerprint key configuration and rotation status.

    Returns a structured dict suitable for surfacing in /v1/auth/policy and
    operator dashboards. Status values:

    - "ephemeral":         no key configured; using process-local random key
    - "ok":                key configured and within rotation interval
    - "rotation_due":      key age past AGENT_BOM_RATE_LIMIT_KEY_ROTATION_DAYS
    - "max_age_exceeded":  key age past AGENT_BOM_RATE_LIMIT_KEY_MAX_AGE_DAYS
    - "unknown_age":       key configured but no last-rotated timestamp set
    """
    from agent_bom.api.secret_source import resolve_secret
    from agent_bom.config import (
        RATE_LIMIT_KEY_LAST_ROTATED,
        RATE_LIMIT_KEY_MAX_AGE_DAYS,
        RATE_LIMIT_KEY_ROTATION_DAYS,
    )

    raw_key = resolve_secret("AGENT_BOM_RATE_LIMIT_KEY")
    fallback_source = None

    if not raw_key:
        return _ephemeral_rate_limit_key_status(RATE_LIMIT_KEY_ROTATION_DAYS, RATE_LIMIT_KEY_MAX_AGE_DAYS)

    if not RATE_LIMIT_KEY_LAST_ROTATED:
        return {
            "status": "unknown_age",
            "rotation_days": RATE_LIMIT_KEY_ROTATION_DAYS,
            "max_age_days": RATE_LIMIT_KEY_MAX_AGE_DAYS,
            "fallback_source": fallback_source,
            "last_rotated": None,
            "age_days": None,
            "message": (
                "Rate-limit key is configured but AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED is "
                "unset. Set it to an ISO-8601 timestamp when the key was last rotated to "
                "enable rotation tracking."
            ),
        }

    try:
        rotated = _dt.fromisoformat(RATE_LIMIT_KEY_LAST_ROTATED)
    except ValueError:
        return {
            "status": "unknown_age",
            "rotation_days": RATE_LIMIT_KEY_ROTATION_DAYS,
            "max_age_days": RATE_LIMIT_KEY_MAX_AGE_DAYS,
            "fallback_source": fallback_source,
            "last_rotated": RATE_LIMIT_KEY_LAST_ROTATED,
            "age_days": None,
            "message": (
                "AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED is set but is not a valid ISO-8601 "
                "timestamp. Use a value like '2026-04-17T00:00:00+00:00'."
            ),
        }

    if rotated.tzinfo is None:
        rotated = rotated.replace(tzinfo=_tz.utc)
    current = now or _dt.now(_tz.utc)
    age_days = max(0, int((current - rotated).total_seconds() // 86400))

    status, message = _rate_limit_age_status(age_days, RATE_LIMIT_KEY_MAX_AGE_DAYS, RATE_LIMIT_KEY_ROTATION_DAYS)

    return {
        "status": status,
        "rotation_days": RATE_LIMIT_KEY_ROTATION_DAYS,
        "max_age_days": RATE_LIMIT_KEY_MAX_AGE_DAYS,
        "fallback_source": fallback_source,
        "last_rotated": rotated.isoformat(),
        "age_days": age_days,
        "message": message,
    }


def _ephemeral_rate_limit_key_status(rotation_days: int, max_age_days: int) -> dict:
    production_or_clustered = _production_or_clustered_control_plane()
    return {
        "status": "ephemeral",
        "severity": "warning" if production_or_clustered else "info",
        "production_or_clustered": production_or_clustered,
        "rotation_days": rotation_days,
        "max_age_days": max_age_days,
        "fallback_source": None,
        "last_rotated": None,
        "age_days": None,
        "message": (
            (
                "No AGENT_BOM_RATE_LIMIT_KEY configured. Rate-limit fingerprints use a "
                "process-local random key that resets on restart and breaks shared bucket "
                "scoping across replicas. Set AGENT_BOM_RATE_LIMIT_KEY for production."
            )
            if production_or_clustered
            else (
                "No AGENT_BOM_RATE_LIMIT_KEY configured. Rate-limit fingerprints use a "
                "process-local random key that resets on restart; this is acceptable for "
                "single-process local development."
            )
        ),
    }


def _rate_limit_age_status(age_days: int, max_age_days: int, rotation_days: int) -> tuple[str, str]:
    if age_days >= max_age_days:
        status = "max_age_exceeded"
        message = (
            f"Rate-limit key is {age_days} days old, exceeding the configured maximum "
            f"({max_age_days} days). Rotate AGENT_BOM_RATE_LIMIT_KEY now and "
            "update AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED."
        )
    elif age_days >= rotation_days:
        status = "rotation_due"
        message = f"Rate-limit key is {age_days} days old, past the rotation interval ({rotation_days} days). Schedule a rotation."
    else:
        status = "ok"
        message = f"Rate-limit key is {age_days} days old; rotation interval is {rotation_days} days."

    return status, message
