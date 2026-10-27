"""API middleware — authentication, rate limiting, body size, trust headers."""

from __future__ import annotations

import hmac
import logging
import os
import secrets
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import anyio.to_thread

from agent_bom.api.auth import get_key_store
from agent_bom.api.auth_posture import _AUTH_POSTURE as _AUTH_POSTURE
from agent_bom.api.auth_posture import _AUTH_RUNTIME_STATUS as _AUTH_RUNTIME_STATUS
from agent_bom.api.auth_posture import _EMPTY_AUTH_POSTURE as _EMPTY_AUTH_POSTURE
from agent_bom.api.auth_posture import _TRUSTED_PROXY_SECRET_MIN_BYTES as _TRUSTED_PROXY_SECRET_MIN_BYTES
from agent_bom.api.auth_posture import AuthPosture as AuthPosture
from agent_bom.api.auth_posture import AuthPostureError as AuthPostureError
from agent_bom.api.auth_posture import _configured_listener_host, _env_flag, _is_loopback_listener, get_trusted_proxy_auth_status
from agent_bom.api.auth_posture import _secret_min_bytes as _secret_min_bytes
from agent_bom.api.auth_posture import _trusted_proxy_secret_is_strong as _trusted_proxy_secret_is_strong
from agent_bom.api.auth_posture import apply_auth_posture as apply_auth_posture
from agent_bom.api.auth_posture import configure_auth_runtime as configure_auth_runtime
from agent_bom.api.auth_posture import derive_auth_posture as derive_auth_posture
from agent_bom.api.auth_posture import get_auth_posture as get_auth_posture
from agent_bom.api.auth_posture import get_auth_runtime_status as get_auth_runtime_status
from agent_bom.api.auth_posture import trusted_proxy_auth_usable as trusted_proxy_auth_usable
from agent_bom.api.auth_posture import validate_auth_posture as validate_auth_posture
from agent_bom.api.browser_session import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    BrowserSessionError,
    verify_browser_session_token,
    verify_csrf,
)
from agent_bom.api.error_envelope import (
    _with_middleware_error_envelope as _with_middleware_error_envelope,
)
from agent_bom.api.error_envelope import install_error_envelope as install_error_envelope
from agent_bom.api.error_envelope import (
    with_middleware_error_envelope,
)
from agent_bom.api.host_guard import browser_origin_trusted
from agent_bom.api.middleware_body import (
    MaxBodySizeMiddleware as MaxBodySizeMiddleware,
)
from agent_bom.api.middleware_headers import (
    _API_CSP as _API_CSP,
)
from agent_bom.api.middleware_headers import (
    TrustHeadersMiddleware as TrustHeadersMiddleware,
)
from agent_bom.api.middleware_headers import (
    _cache_control as _cache_control,
)
from agent_bom.api.middleware_headers import (
    _content_security_policy as _content_security_policy,
)
from agent_bom.api.middleware_headers import (
    _hsts_max_age_seconds as _hsts_max_age_seconds,
)
from agent_bom.api.middleware_headers import (
    _is_hashed_build_asset as _is_hashed_build_asset,
)
from agent_bom.api.middleware_headers import (
    describe_security_header_posture as describe_security_header_posture,
)
from agent_bom.api.middleware_headers import (
    hsts_header_value as hsts_header_value,
)
from agent_bom.api.middleware_limits import (
    _API_KEY_VERIFIED_AUTH_METHODS as _API_KEY_VERIFIED_AUTH_METHODS,
)
from agent_bom.api.middleware_limits import (
    _RATE_LIMIT_FINGERPRINT_FALLBACK as _RATE_LIMIT_FINGERPRINT_FALLBACK,
)
from agent_bom.api.middleware_limits import (
    _TENANT_SCOPED_AUTH_METHODS as _TENANT_SCOPED_AUTH_METHODS,
)
from agent_bom.api.middleware_limits import (
    DEFAULT_AUTHENTICATED_READ_RATE_LIMIT_RPM as DEFAULT_AUTHENTICATED_READ_RATE_LIMIT_RPM,
)
from agent_bom.api.middleware_limits import (
    DEFAULT_GLOBAL_IP_RATE_LIMIT_RPM as DEFAULT_GLOBAL_IP_RATE_LIMIT_RPM,
)
from agent_bom.api.middleware_limits import (
    DEFAULT_READ_RATE_LIMIT_RPM as DEFAULT_READ_RATE_LIMIT_RPM,
)
from agent_bom.api.middleware_limits import (
    DEFAULT_SCAN_RATE_LIMIT_RPM as DEFAULT_SCAN_RATE_LIMIT_RPM,
)
from agent_bom.api.middleware_limits import (
    MAX_RATE_LIMIT_RPM as MAX_RATE_LIMIT_RPM,
)
from agent_bom.api.middleware_limits import (
    GlobalRateLimitMiddleware as GlobalRateLimitMiddleware,
)
from agent_bom.api.middleware_limits import (
    RateLimitMiddleware as _RateLimitMiddleware,
)
from agent_bom.api.middleware_limits import (
    _build_rate_limit_store as _build_rate_limit_store,
)
from agent_bom.api.middleware_limits import (
    _rate_limit_fingerprint as _rate_limit_fingerprint,
)
from agent_bom.api.middleware_limits import (
    _rate_limit_fingerprint_key as _rate_limit_fingerprint_key,
)
from agent_bom.api.middleware_limits import (
    _shared_rate_limit_required as _shared_rate_limit_required,
)
from agent_bom.api.middleware_limits import (
    _validate_rate_limit as _validate_rate_limit,
)
from agent_bom.api.middleware_limits import (
    get_rate_limit_key_status as get_rate_limit_key_status,
)
from agent_bom.api.middleware_limits import (
    get_rate_limit_runtime_status as get_rate_limit_runtime_status,
)
from agent_bom.api.middleware_limits import (
    global_ip_rate_limit_rpm as global_ip_rate_limit_rpm,
)
from agent_bom.api.rate_limit_store import InMemoryRateLimitStore as InMemoryRateLimitStore
from agent_bom.api.rate_limit_store import PostgresRateLimitStore as PostgresRateLimitStore
from agent_bom.api.route_policy import (
    PUBLIC_OPERATIONS,
    ROLE_RULES,
    SCOPE_RULES,
    public_operation,
    request_scopes_allow,
    required_role,
    required_scope,
    scope_catalog,
)
from agent_bom.api.storage.deployment import _production_or_clustered_control_plane as _production_or_clustered_control_plane
from agent_bom.api.storage.deployment import clustered_control_plane_required
from agent_bom.api.storage_schema import postgres_deployment_configured
from agent_bom.core.settings import env_raw

if TYPE_CHECKING:
    from agent_bom.api.auth import Role
    from agent_bom.api.oidc import OIDCConfig

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from agent_bom.security import sanitize_text

_logger = logging.getLogger(__name__)


def static_api_key_allowed() -> bool:
    """Static API keys are a single-tenant pilot shortcut, not clustered auth."""
    return not clustered_control_plane_required()


def static_api_key_rejection_message() -> str:
    return (
        "AGENT_BOM_API_KEY static-key auth is disabled for clustered control planes. "
        "Use tenant-scoped API keys, OIDC, SAML, or trusted proxy auth instead."
    )


@dataclass(frozen=True)
class Resolved:
    """A resolver authenticated a principal; ``response`` is the downstream result.

    The resolver has already applied the per-route authorization/tenant policy
    and dispatched (or produced the terminal authz rejection for) the request.
    """

    response: Response


@dataclass(frozen=True)
class Invalid:
    """A resolver saw a credential it could not accept.

    Terminal: a presented-but-invalid credential is returned as-is and never
    falls through to a later resolver or the anonymous fallback.
    """

    response: Response


@dataclass(frozen=True)
class Absent:
    """No credential this resolver can act on — the pipeline tries the next one."""


Resolution = Resolved | Invalid | Absent


async def run_resolver_chain(resolvers: Iterable[Callable[[], Awaitable[Resolution]]]) -> Response | None:
    """Run an ordered authentication resolver chain: first non-Absent result wins.

    This is the single place that expresses the pipeline's control-flow
    invariant — ``Absent`` continues to the next resolver, while both
    ``Resolved`` and ``Invalid`` are terminal and return their response
    immediately. Returns ``None`` only when every resolver is ``Absent`` (the
    production chain ends in a terminal resolver, so that never happens there;
    it is meaningful for unit tests exercising the loop directly).
    """
    for resolver in resolvers:
        result = await resolver()
        if isinstance(result, Absent):
            continue
        return result.response
    return None


# Only mounted dashboard files establish public SPA routes. Without a mounted
# export (including REST-only mode), these paths remain behind authentication.
_DASHBOARD_SPA_ROUTES: frozenset[str] = frozenset()
_DASHBOARD_PUBLIC_FILES: frozenset[str] = frozenset()


def dashboard_spa_routes_from_files(relative_paths: Iterable[str]) -> frozenset[str]:
    """Derive the public SPA first-segment allowlist from exported file paths.

    ``relative_paths`` are the dashboard-relative keys the SPA catch-all
    resolves against (``overview/index.html``, ``findings.html``, …).
    """
    routes: set[str] = set()
    for relative in relative_paths:
        normalized = relative.strip("/")
        if not normalized or normalized.startswith("_next"):
            continue
        first_segment, separator, _ = normalized.partition("/")
        if separator:
            routes.add(first_segment)
        elif first_segment.lower().endswith(".html"):
            routes.add(first_segment.rsplit(".", 1)[0])
    if "index" in routes:
        # ``index.html`` is the SPA shell: it backs both ``/`` and every
        # client-side route the export did not pre-render as its own file.
        routes.add("")
    return frozenset(routes)


def register_dashboard_spa_routes(relative_paths: Iterable[str]) -> None:
    """Publish the SPA route allowlist discovered while mounting the dashboard."""
    global _DASHBOARD_SPA_ROUTES, _DASHBOARD_PUBLIC_FILES  # noqa: PLW0603 — process-wide startup registry
    paths = tuple(relative_paths)
    _DASHBOARD_SPA_ROUTES = dashboard_spa_routes_from_files(paths)
    _DASHBOARD_PUBLIC_FILES = frozenset("/" + path.strip("/") for path in paths)


def dashboard_spa_routes() -> frozenset[str]:
    """Return the currently registered public SPA first-segment allowlist."""
    return _DASHBOARD_SPA_ROUTES


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Optional API key authentication via Bearer token or X-API-Key header.

    Supports two modes:
    - Simple mode: single static API key (backward compatible)
    - RBAC mode: role-based access control via KeyStore with per-endpoint role checks
    """

    # Set AGENT_BOM_DISABLE_DOCS=1 in production to block /docs and /redoc
    _DOCS_DISABLED = os.environ.get("AGENT_BOM_DISABLE_DOCS", "").strip() in ("1", "true", "yes")
    _EXEMPT_PATHS = {path for _method, path in PUBLIC_OPERATIONS}
    if _DOCS_DISABLED:
        _EXEMPT_PATHS -= {"/docs", "/redoc", "/openapi.json"}

    @staticmethod
    def _is_dashboard_public_request(path: str, method: str) -> bool:
        if method not in {"GET", "HEAD"}:
            return False
        if path.startswith(("/v1/", "/metrics")):
            return False
        if path.startswith(("/scim/", "/docs", "/redoc", "/openapi.json")):
            return False
        if path in _DASHBOARD_PUBLIC_FILES:
            return True
        if path.startswith("/_next/"):
            return True
        if path in {
            "/favicon.ico",
            "/robots.txt",
            "/manifest.json",
            "/apple-touch-icon.png",
            "/brand/mark.svg",
        }:
            return True
        if path.startswith("/brand/"):
            return True
        dashboard_routes = _DASHBOARD_SPA_ROUTES
        normalized = path.strip("/")
        first_segment = normalized.split("/", 1)[0] if normalized else ""
        public_suffixes = (
            ".html",
            ".css",
            ".js",
            ".mjs",
            ".map",
            ".woff",
            ".woff2",
            ".png",
            ".jpg",
            ".jpeg",
            ".webp",
            ".svg",
            ".ico",
            ".txt",
        )
        if path.lower().endswith(public_suffixes):
            return first_segment in dashboard_routes or ("/" not in normalized and normalized.rsplit(".", 1)[0] in dashboard_routes)
        # Client-side dashboard routes are served by the SPA fallback. The set
        # is derived from the shipped dashboard files (see
        # ``register_dashboard_spa_routes``) so it can neither drift from the
        # real pages nor allowlist a route the SPA does not serve.
        return first_segment in dashboard_routes

    _ROLE_RULES = ROLE_RULES

    _SCOPE_RULES = SCOPE_RULES

    @classmethod
    def scope_catalog(cls) -> list[dict[str, str]]:
        return scope_catalog()

    def __init__(self, app: ASGIApp, api_key: str, allow_unauthenticated: bool = False) -> None:
        super().__init__(app)
        if api_key and not static_api_key_allowed():
            raise RuntimeError(static_api_key_rejection_message())
        self._validate_exempt_paths_against_role_rules()
        self._api_key = api_key
        # When the operator explicitly opts in, a request that presents NO
        # credential at all is served as the configured NO_AUTH_ROLE (default
        # viewer) instead of being rejected with 401; a present-but-invalid
        # credential is still rejected. This is driven solely by the value
        # ``configure_api`` resolves (explicit flag combined with
        # AGENT_BOM_ALLOW_UNAUTHENTICATED_API) and passes in — the middleware
        # deliberately does NOT re-read the env itself, so it fails closed
        # unless an operator's configured posture explicitly enables it.
        self._allow_unauthenticated = bool(allow_unauthenticated)
        self._trusted_proxy_auth = _env_flag("AGENT_BOM_TRUST_PROXY_AUTH")
        from agent_bom.api.secret_source import resolve_secret

        self._trusted_proxy_secret = resolve_secret("AGENT_BOM_TRUST_PROXY_AUTH_SECRET")
        self._trusted_proxy_issuer = os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH_ISSUER", "").strip()
        # OIDC config loaded lazily from env on first request
        self._oidc_config: OIDCConfig | None = None
        self._oidc_checked = False

    @classmethod
    def _validate_exempt_paths_against_role_rules(cls) -> None:
        # An exact-path entry in _EXEMPT_PATHS bypasses the entire dispatch chain.
        # An exact-path entry in _ROLE_RULES (no trailing slash, no broader prefix)
        # would silently grant unauthenticated access. Fail at startup if both lists
        # ever name the same exact path.
        role_paths = {path for _method, path, _role in cls._ROLE_RULES if not path.endswith("/")}
        overlap = sorted(cls._EXEMPT_PATHS & role_paths)
        if overlap:
            raise RuntimeError("APIKeyMiddleware exempt-paths overlap with role-rule paths: " + ", ".join(overlap))

    def _required_role(self, method: str, path: str) -> str:
        return required_role(method, path)

    def _required_scope(self, method: str, path: str) -> str | None:
        return required_scope(method, path)

    @staticmethod
    def _role_allows(actual: Role, required: Role) -> bool:
        from agent_bom.rbac import role_rank

        return role_rank(actual) >= role_rank(required)

    @staticmethod
    def _record_scim_role_state(request: StarletteRequest, *, user_id: str | None, user_name: str | None) -> None:
        request.state.auth_role_source = "scim"
        request.state.scim_user_id = user_id
        request.state.scim_user_name = user_name

    async def _resolve_runtime_role(
        self,
        request: StarletteRequest,
        *,
        tenant_id: str,
        upstream_role: Role | None,
        subjects: tuple[object, ...],
    ) -> tuple[Role | None, JSONResponse | None]:
        from agent_bom.api.auth import resolve_scim_user_role_async

        resolution = await resolve_scim_user_role_async(tenant_id, *subjects)
        if not resolution.matched:
            return upstream_role, None
        if not resolution.active:
            return None, JSONResponse(status_code=401, content={"detail": "Unauthorized — SCIM user is inactive"})
        if resolution.role is None:
            return None, JSONResponse(status_code=403, content={"detail": "Forbidden — SCIM user has no runtime role"})
        self._record_scim_role_state(request, user_id=resolution.user_id, user_name=resolution.user_name)
        if resolution.user_id:
            request.state.scim_subject_id = resolution.user_id
        return resolution.role, None

    @staticmethod
    def _credential_presented(request: StarletteRequest, auth_header: str) -> bool:
        """Return true when the caller presented *any* credential material.

        Distinguishes "no credential presented" (eligible for the anonymous
        NO_AUTH_ROLE fallback when opted in) from "credential presented but
        we could not turn it into a valid identity" (must be rejected, never
        silently downgraded to anonymous). A non-empty Authorization header in
        any scheme, or a non-empty X-API-Key header, counts as presented. The
        session-cookie and trusted-proxy paths are handled by their own
        branches before this is consulted.
        """
        if auth_header.strip():
            return True
        if request.headers.get("x-api-key", "").strip():
            return True
        # Proxy identity headers are credential material only when the trusted
        # proxy resolver validates its shared attestation.  If that resolver is
        # disabled or misconfigured, their presence must still be terminal:
        # silently downgrading a spoofed/wrong-secret proxy identity to the
        # anonymous NO_AUTH_ROLE would hide a broken auth boundary (and can
        # unexpectedly elevate it on a local no-auth admin deployment).
        if any(
            request.headers.get(name, "").strip()
            for name in (
                "x-agent-bom-role",
                "x-agent-bom-tenant-id",
                "x-agent-bom-subject",
                "x-agent-bom-proxy-secret",
                "x-forwarded-email",
                "x-auth-request-email",
            )
        ):
            return True
        return False

    async def _serve_anonymous(self, request: StarletteRequest, call_next: RequestResponseEndpoint) -> Response:
        """Serve a credential-less request as the configured NO_AUTH_ROLE.

        The anonymous identity is subject to the exact same per-route role gate
        as any other identity, so an anonymous viewer still gets 403 on
        analyst/admin routes. DEMO_ESTATE clamps NO_AUTH_ROLE to viewer inside
        ``_no_auth_role`` and remains authoritative here.
        """
        from agent_bom.api.auth import Role
        from agent_bom.rbac import effective_no_auth_role

        role = effective_no_auth_role(credentials_configured=bool(self._api_key or get_key_store().has_keys()))
        # Combined mode: when credentials (a static API key or any stored keys)
        # are also configured, the anonymous fallback is strictly read-only —
        # otherwise NO_AUTH_ROLE=admin would hand an unauthenticated caller admin
        # (they could mint admin keys). NO_AUTH_ROLE elevation only applies to a
        # pure no-auth deployment with no credentials configured at all.
        required = Role(self._required_role(request.method, request.url.path))
        if not self._role_allows(role, required):
            return JSONResponse(
                status_code=403,
                content={"detail": f"Forbidden — requires {required.value} role, anonymous access has {role.value}"},
            )
        request.state.api_key_name = "anonymous"
        request.state.api_key_role = role.value
        request.state.tenant_id = getattr(request.state, "tenant_id", None) or "default"
        request.state.auth_method = "anonymous"
        return await self._call_with_tenant_context(request, call_next)

    @with_middleware_error_envelope
    async def dispatch(self, request: StarletteRequest, call_next: RequestResponseEndpoint) -> Response:
        if self._DOCS_DISABLED and request.url.path in {"/docs", "/redoc", "/openapi.json"}:
            return JSONResponse(status_code=404, content={"detail": "Not Found"})
        # CORS preflight MUST bypass auth: browsers omit Authorization headers
        # (Fetch §3.2.2). A 401 here prevents the actual cross-origin request.
        # CORSMiddleware supplies Access-Control-Allow-* for configured origins;
        # authentication still applies to the subsequent application request.
        if request.method == "OPTIONS" and "origin" in request.headers and "access-control-request-method" in request.headers:
            return await call_next(request)
        from agent_bom.api.managed_trial import managed_trial_enabled, managed_trial_route_allowed

        if managed_trial_enabled() and not managed_trial_route_allowed(request.method, request.url.path):
            return JSONResponse(status_code=403, content={"detail": "This API route is disabled in managed trial mode."})
        if request.url.path in self._EXEMPT_PATHS and public_operation(request.method, request.url.path):
            return await call_next(request)
        if self._is_dashboard_public_request(request.url.path, request.method):
            return await call_next(request)

        if postgres_deployment_configured():
            from agent_bom.api.postgres_common import is_tenant_rls_bypassed

            if is_tenant_rls_bypassed():
                _logger.critical("Rejecting request while Postgres tenant RLS bypass context is active")
                return JSONResponse(status_code=500, content={"detail": "Tenant isolation guard is not clean"})

        return await self.resolve_principal(request, call_next)

    async def resolve_principal(self, request: StarletteRequest, call_next: RequestResponseEndpoint) -> Response:
        """Decide authentication for a request through one ordered resolver chain.

        This is the single authentication decision point. Each credential source
        (SCIM bearer, browser session, trusted proxy, static key, OIDC bearer,
        API key, anonymous fallback) is a resolver returning ``Resolved`` (a
        principal was authenticated), ``Invalid`` (a credential was presented and
        rejected — terminal, never falls through), or ``Absent`` (nothing to act
        on — try the next resolver). The order and per-resolver semantics are
        exactly those of the previous inline dispatch chain; see the individual
        ``_resolve_*`` methods. The final resolver is always terminal.
        """
        session_token = request.cookies.get(SESSION_COOKIE_NAME, "")
        # Extract raw key from headers for CLI and service clients.
        auth = request.headers.get("authorization", "")
        raw_key = auth[7:] if auth.startswith("Bearer ") else ""
        if not raw_key:
            raw_key = request.headers.get("x-api-key", "")

        resolvers: tuple[Callable[[], Awaitable[Resolution]], ...] = (
            lambda: self._resolve_scim_bearer(request, call_next),
            lambda: self._resolve_browser_session(request, call_next, session_token),
            lambda: self._resolve_trusted_proxy(request, call_next, raw_key),
            lambda: self._resolve_static_key(request, call_next, raw_key),
            lambda: self._resolve_oidc_bearer(request, call_next, raw_key, auth),
            lambda: self._resolve_api_key(request, call_next, raw_key),
            lambda: self._resolve_terminal(request, call_next, raw_key, auth),
        )
        response = await run_resolver_chain(resolvers)
        if response is not None:
            return response
        # Unreachable: the terminal resolver never returns Absent. Fail closed.
        return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

    @staticmethod
    def _classify_terminal(request: StarletteRequest, response: Response) -> Resolution:
        """Tag a terminal helper Response as Resolved or Invalid.

        The SCIM / browser-session / trusted-proxy helpers set
        ``request.state.auth_method`` only once a principal is established; an
        auth rejection returns a JSONResponse without it. Both outcomes are
        terminal, so the distinction is purely semantic (and sets up the
        post-resolution policy point), never a control-flow change.
        """
        if getattr(request.state, "auth_method", None):
            return Resolved(response)
        return Invalid(response)

    async def _resolve_scim_bearer(self, request: StarletteRequest, call_next: RequestResponseEndpoint) -> Resolution:
        if not self._is_scim_path(request.url.path):
            return Absent()
        return self._classify_terminal(request, await self._try_scim_bearer_auth(request, call_next))

    async def _resolve_browser_session(
        self, request: StarletteRequest, call_next: RequestResponseEndpoint, session_token: str
    ) -> Resolution:
        if not session_token:
            return Absent()
        return self._classify_terminal(request, await self._try_browser_session_auth(request, call_next, session_token))

    async def _resolve_trusted_proxy(self, request: StarletteRequest, call_next: RequestResponseEndpoint, raw_key: str) -> Resolution:
        # Trusted-proxy headers are consulted only when no API key was presented,
        # preserving the previous ``if not raw_key`` gate.
        if raw_key:
            return Absent()
        proxy_response = await self._try_proxy_header_auth(request, call_next)
        if proxy_response is None:
            return Absent()
        return self._classify_terminal(request, proxy_response)

    async def _resolve_static_key(self, request: StarletteRequest, call_next: RequestResponseEndpoint, raw_key: str) -> Resolution:
        # Simple mode: single static key (backward compatible, all access)
        if not raw_key:
            return Absent()
        if self._api_key and secrets.compare_digest(raw_key, self._api_key):
            from agent_bom.api.auth import Role
            from agent_bom.api.dev_auth_state import get_dev_api_key, get_dev_api_role

            role = get_dev_api_role() if get_dev_api_key() == self._api_key else Role.ADMIN
            required = Role(self._required_role(request.method, request.url.path))
            if not self._role_allows(role, required):
                return Resolved(JSONResponse(status_code=403, content={"detail": "Forbidden — insufficient role"}))
            request.state.api_key_name = "static-key"
            request.state.api_key_role = role.value
            request.state.tenant_id = "default"
            request.state.auth_method = "static_api_key"
            return Resolved(await self._call_with_tenant_context(request, call_next))
        return Absent()

    async def _resolve_oidc_bearer(
        self, request: StarletteRequest, call_next: RequestResponseEndpoint, raw_key: str, auth: str
    ) -> Resolution:
        # OIDC mode: try JWT verification when AGENT_BOM_OIDC_ISSUER is set
        if not raw_key:
            return Absent()
        if not self._oidc_checked:
            from agent_bom.api.oidc import OIDCConfig

            self._oidc_config = OIDCConfig.from_env()
            self._oidc_checked = True

        oidc_cfg = self._oidc_config
        if oidc_cfg is None or not getattr(oidc_cfg, "enabled", False) or not auth.startswith("Bearer "):
            return Absent()

        from agent_bom.api.oidc import OIDCError, record_oidc_decode_failure, token_is_jwt_shaped
        from agent_bom.api.shared_auth_state import AuthStateUnavailable

        try:
            # ``verify`` can fetch JWKS over the network (``urlopen`` in
            # api/oidc.py) on a cache miss or key rotation, so it must not run
            # on the event loop — this path is reached before authentication.
            _claims, oidc_role = await anyio.to_thread.run_sync(oidc_cfg.verify, raw_key)
            required = self._required_role(request.method, request.url.path)
            from agent_bom.api.auth import Role

            tenant_id = oidc_cfg.resolve_tenant(_claims)
            subject = _claims.get("email") or _claims.get("preferred_username") or _claims.get("sub", "oidc-user")
            upstream_role = Role(oidc_role)
            effective_role, scim_error = await self._resolve_runtime_role(
                request,
                tenant_id=tenant_id,
                upstream_role=upstream_role,
                subjects=(subject, _claims.get("email"), _claims.get("preferred_username"), _claims.get("upn"), _claims.get("sub")),
            )
            if scim_error is not None:
                return Invalid(scim_error)
            required_role = Role(required)
            if effective_role is not None and self._role_allows(effective_role, required_role):
                request.state.api_key_name = subject
                request.state.api_key_role = effective_role.value
                request.state.tenant_id = tenant_id
                request.state.auth_method = "oidc"
                request.state.verified_oidc_claims = dict(_claims)
                # Short issuer suffix helps operators recognize which IdP
                # resolved the token without leaking the full URL to all
                # request-scoped log fields.
                issuer = str(_claims.get("iss") or "")
                request.state.auth_issuer = issuer.rsplit("/", 1)[-1][:64] if issuer else None
                return Resolved(await self._call_with_tenant_context(request, call_next))
            actual_role = effective_role.value if effective_role else oidc_role
            return Invalid(
                JSONResponse(
                    status_code=403,
                    content={"detail": f"Forbidden — requires {required} role, OIDC session has {actual_role}"},
                )
            )
        except AuthStateUnavailable:
            return Invalid(JSONResponse(status_code=503, content={"detail": "Authentication state unavailable"}))
        except OIDCError as exc:
            record_oidc_decode_failure()
            _logger.debug("OIDC verification failed: %s", sanitize_text(exc))
            # PR2 decision (#4274): distinguish a presented-but-invalid OIDC
            # credential from a bearer that simply is not an OIDC token.
            #
            # A JWT-shaped bearer (header.payload.signature with an ``alg``
            # header) that fails verification — bad signature, wrong issuer /
            # audience, expired, unconfigured issuer, replay, malformed claims —
            # WAS presented as an OIDC token. It is terminal ``Invalid`` (a hard
            # 401) and must never be silently retried against the API-key store.
            #
            # A bearer that is not JWT-shaped is not an OIDC token at all (e.g. a
            # raw opaque API key sent as ``Authorization: Bearer``). It stays
            # ``Absent`` so the API-key resolver can still authenticate it,
            # preserving the legitimate key-as-bearer path.
            if token_is_jwt_shaped(raw_key):
                return Invalid(
                    JSONResponse(
                        status_code=401,
                        content={"detail": "Unauthorized — OIDC bearer token verification failed"},
                    )
                )
            return Absent()

    async def _resolve_api_key(self, request: StarletteRequest, call_next: RequestResponseEndpoint, raw_key: str) -> Resolution:
        # RBAC mode: check against KeyStore
        if not raw_key:
            return Absent()
        from agent_bom.api.auth import Role, get_key_store

        store = get_key_store()
        if not store.has_keys():
            return Absent()
        # ``store.verify`` runs a ~21ms scrypt derivation (in-memory store) or
        # a blocking DB read (Postgres store); offload it to a worker thread so
        # it never stalls the async event loop while unrelated requests wait.
        api_key = await anyio.to_thread.run_sync(store.verify, raw_key)
        if not api_key:
            return Absent()
        required = self._required_role(request.method, request.url.path)
        required_role = Role(required)
        effective_role = api_key.role
        if api_key.name.startswith("saml:") or api_key.scim_subject_id:
            subjects = [api_key.name.removeprefix("saml:"), api_key.name]
            if api_key.scim_subject_id:
                subjects.append(api_key.scim_subject_id)
            resolved_role, scim_error = await self._resolve_runtime_role(
                request,
                tenant_id=api_key.tenant_id,
                upstream_role=api_key.role,
                subjects=tuple(subjects),
            )
            if scim_error is not None:
                return Invalid(scim_error)
            effective_role = resolved_role or api_key.role
        if not self._role_allows(effective_role, required_role):
            return Invalid(
                JSONResponse(
                    status_code=403,
                    content={"detail": f"Forbidden — requires {required} role, you have {effective_role.value}"},
                )
            )
        required_scope = self._required_scope(request.method, request.url.path)
        if not request_scopes_allow(api_key.scopes, request.method, request.url.path):
            return Invalid(
                JSONResponse(
                    status_code=403,
                    content={
                        "detail": f"Forbidden — requires scope {required_scope}"
                        if required_scope
                        else "Forbidden — operation has no scope grant"
                    },
                )
            )
        request.state.api_key_name = api_key.name
        request.state.api_key_role = effective_role.value
        request.state.tenant_id = api_key.tenant_id
        request.state.api_key_id = api_key.key_id
        request.state.api_key_scopes = list(api_key.scopes)
        if api_key.scim_subject_id:
            request.state.scim_subject_id = api_key.scim_subject_id
        # Carry the stable principal binding into the request so authz/tenant
        # context is keyed to the subject's id, not its display name.
        if api_key.principal_id:
            request.state.principal_id = api_key.principal_id
        # SAML-minted keys are named "saml:<subject>" — surface that
        # as a distinct auth method so operators can trace who came
        # in via which IdP path even after the key has been issued.
        request.state.auth_method = "saml" if api_key.name.startswith("saml:") else "api_key"
        return Resolved(await self._call_with_tenant_context(request, call_next))

    async def _resolve_terminal(self, request: StarletteRequest, call_next: RequestResponseEndpoint, raw_key: str, auth: str) -> Resolution:
        """Final resolver: anonymous fallback (opt-in) or a hard 401.

        Reached only after every credential source returned Absent.
        """
        if not raw_key:
            # No API key, no session cookie, no trusted-proxy attestation. If the
            # operator opted into anonymous read-only access AND no credential
            # was presented in any form, serve the request as NO_AUTH_ROLE
            # instead of 401. A present-but-malformed credential (e.g. an
            # unsupported Authorization scheme) must NOT silently downgrade to
            # anonymous — it is treated as a presented credential and rejected.
            if self._allow_unauthenticated and not self._credential_presented(request, auth):
                return Resolved(await self._serve_anonymous(request, call_next))
            return Invalid(
                JSONResponse(
                    status_code=401,
                    content={"detail": "Unauthorized — provide API key via Authorization: Bearer <key> or X-API-Key header"},
                )
            )
        return Invalid(
            JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized — invalid API key"},
            )
        )

    def _is_scim_path(self, path: str) -> bool:
        from agent_bom.api.scim import scim_base_path

        base = scim_base_path()
        return path == base or path.startswith(base + "/")

    async def _try_scim_bearer_auth(self, request: StarletteRequest, call_next: RequestResponseEndpoint) -> Response:
        """Authenticate dedicated SCIM provisioning traffic.

        SCIM uses its own bearer token and tenant binding so IdP lifecycle
        traffic cannot be hijacked through dashboard sessions or general API
        keys, and tenant routing cannot be supplied by the inbound payload.
        """
        auth = request.headers.get("authorization", "")
        raw_key = auth[7:] if auth.startswith("Bearer ") else ""

        from agent_bom.api.scim import SCIMConfigurationError, resolve_scim_bearer_token

        try:
            binding = resolve_scim_bearer_token(raw_key)
        except SCIMConfigurationError:
            return JSONResponse(
                status_code=503,
                content={"detail": "SCIM bearer token configuration is invalid"},
            )
        if binding is None:
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized — SCIM bearer token required"},
            )

        request.state.api_key_name = "scim-provisioner"
        request.state.api_key_role = "admin"
        request.state.tenant_id = binding.tenant_id
        request.state.scim_token_source = binding.source
        request.state.scim_token_id = binding.token_id
        request.state.api_key_scopes = ["auth.scim:read", "auth.scim:write"]
        request.state.auth_method = "scim_bearer"
        return await self._call_with_tenant_context(request, call_next)

    async def _try_browser_session_auth(self, request: StarletteRequest, call_next: RequestResponseEndpoint, token: str) -> Response:
        from agent_bom.api.auth import Role
        from agent_bom.api.shared_auth_state import AuthStateUnavailable

        try:
            payload = await anyio.to_thread.run_sync(verify_browser_session_token, token)
            session_role = Role(str(payload.get("role", "")).lower())
        except AuthStateUnavailable:
            return JSONResponse(status_code=503, content={"detail": "Authentication state unavailable"})
        except (BrowserSessionError, ValueError):
            return JSONResponse(status_code=401, content={"detail": "Unauthorized — invalid browser session"})

        subject = str(payload.get("sub") or "browser-session")
        tenant_id = str(payload.get("tenant_id") or "default")
        auth_method = str(payload.get("auth_method") or "browser_session")
        if auth_method == "managed_trial_oidc":
            from agent_bom.api.tenant_lifecycle import tenant_access_active

            if not await anyio.to_thread.run_sync(tenant_access_active, tenant_id):
                return JSONResponse(status_code=401, content={"detail": "Unauthorized — managed trial is inactive"})
        effective_role = session_role
        if auth_method == "browser_session_dev_key":
            from agent_bom.api.dev_auth_state import get_dev_api_key, get_dev_api_role

            if get_dev_api_key() is None or session_role != get_dev_api_role():
                return JSONResponse(status_code=401, content={"detail": "Unauthorized — loopback session is no longer active"})
        if auth_method in {"oidc", "saml"} or subject.startswith("saml:"):
            resolved_role, scim_error = await self._resolve_runtime_role(
                request,
                tenant_id=tenant_id,
                upstream_role=session_role,
                subjects=(subject.removeprefix("saml:"), subject),
            )
            if scim_error is not None:
                return scim_error
            effective_role = resolved_role or session_role

        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            if not browser_origin_trusted(request.headers):
                return JSONResponse(status_code=403, content={"detail": "Forbidden — untrusted request origin"})
            csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME, "")
            csrf_header = request.headers.get(CSRF_HEADER_NAME, "")
            if not verify_csrf(payload, csrf_cookie, csrf_header):
                return JSONResponse(status_code=403, content={"detail": "Forbidden — missing or invalid CSRF token"})

        from fastapi import HTTPException

        from agent_bom.api.session_authorization import authorize_browser_session_async as authorize_browser_session

        key_id = str(payload.get("key_id") or "")
        try:
            effective_role, session_scopes = await authorize_browser_session(
                role=effective_role,
                scopes=list(payload.get("scopes") or []),
                tenant_id=tenant_id,
                key_id=key_id,
                auth_method=auth_method,
                method=request.method,
                path=request.url.path,
            )
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

        request.state.api_key_name = subject
        request.state.api_key_role = effective_role.value
        request.state.tenant_id = tenant_id
        request.state.api_key_id = key_id or None
        request.state.api_key_scopes = session_scopes
        request.state.auth_method = auth_method
        return await self._call_with_tenant_context(request, call_next)

    async def _try_proxy_header_auth(self, request: StarletteRequest, call_next: RequestResponseEndpoint) -> Response | None:
        if not self._trusted_proxy_auth:
            return None

        role_header = request.headers.get("x-agent-bom-role", "").strip().lower()
        tenant_id = request.headers.get("x-agent-bom-tenant-id", "").strip()
        subject = (
            request.headers.get("x-agent-bom-subject")
            or request.headers.get("x-forwarded-email")
            or request.headers.get("x-auth-request-email")
            or ""
        )
        if not role_header and not subject:
            return None
        if not self._trusted_proxy_secret:
            _logger.error("AGENT_BOM_TRUST_PROXY_AUTH is enabled without AGENT_BOM_TRUST_PROXY_AUTH_SECRET")
            return JSONResponse(
                status_code=503,
                content={"detail": "Trusted proxy authentication is not securely configured"},
            )
        if not _trusted_proxy_secret_is_strong(self._trusted_proxy_secret):
            _logger.error("AGENT_BOM_TRUST_PROXY_AUTH_SECRET is too short for trusted proxy authentication")
            return JSONResponse(
                status_code=503,
                content={"detail": "Trusted proxy authentication is not securely configured"},
            )
        presented_secret = request.headers.get("x-agent-bom-proxy-secret", "").strip()
        if not hmac.compare_digest(presented_secret, self._trusted_proxy_secret):
            return JSONResponse(status_code=401, content={"detail": "Unauthorized — invalid trusted proxy attestation"})
        presented_issuer = request.headers.get("x-agent-bom-auth-issuer", "").strip()
        if self._trusted_proxy_issuer and not hmac.compare_digest(presented_issuer, self._trusted_proxy_issuer):
            return JSONResponse(status_code=401, content={"detail": "Unauthorized — invalid trusted proxy issuer"})
        if not tenant_id:
            return JSONResponse(
                status_code=401,
                content={"detail": "Authentication required — trusted proxy requests must include X-Agent-Bom-Tenant-ID"},
            )
        # Customer-supplied identifiers must not collide with the agent-bom
        # reserved tenant namespace (system fallbacks + role/permission
        # vocabulary). See docs/IDENTITY_AND_NAMING_CONTRACT.md.
        from agent_bom.platform_invariants import ReservedTenantIdError, validate_customer_tenant_id

        try:
            tenant_id = validate_customer_tenant_id(tenant_id)
        except ReservedTenantIdError as exc:
            return JSONResponse(status_code=400, content={"detail": str(exc)})

        from agent_bom.api.auth import Role

        proxy_role: Role | None = None
        if role_header:
            try:
                proxy_role = Role(role_header)
            except ValueError:
                return JSONResponse(status_code=403, content={"detail": f"Invalid proxy role '{role_header}'"})

        effective_role, scim_error = await self._resolve_runtime_role(
            request,
            tenant_id=tenant_id,
            upstream_role=proxy_role,
            subjects=(subject,),
        )
        if scim_error is not None:
            return scim_error
        if effective_role is None:
            return JSONResponse(status_code=403, content={"detail": "Forbidden — trusted proxy role required"})

        required = Role(self._required_role(request.method, request.url.path))
        if not self._role_allows(effective_role, required):
            return JSONResponse(
                status_code=403,
                content={"detail": f"Forbidden — requires {required.value} role, proxy session has {effective_role.value}"},
            )

        request.state.api_key_name = subject or "proxy-header"
        request.state.api_key_role = effective_role.value
        request.state.tenant_id = tenant_id
        request.state.auth_method = "proxy_header"
        request.state.proxy_auth_attested = True
        request.state.auth_issuer = presented_issuer or None
        try:
            from agent_bom.api.audit_async import log_action_async

            await log_action_async(
                "auth.proxy_header_authenticated",
                actor=str(request.state.api_key_name),
                resource=str(request.url.path),
                tenant_id=tenant_id,
                role=effective_role.value,
                issuer=presented_issuer or None,
            )
        except Exception:  # pragma: no cover - audit side effects must not block auth
            _logger.error("Failed to record trusted proxy authentication audit event")
        return await self._call_with_tenant_context(request, call_next)

    async def _call_with_tenant_context(self, request: StarletteRequest, call_next: RequestResponseEndpoint) -> Response:
        from agent_bom.api.tenancy import call_with_request_tenant

        return await call_with_request_tenant(request, call_next, authenticate=self.dispatch)


# ─── structured error envelope ───────────────────────────

# Map HTTP status codes to stable string codes that downstream consumers can
# pin on without parsing free-form messages. The mapping is intentionally
# narrow — every API error funnels through one of these buckets, with anything
# else falling back to ``INTERNAL_ERROR``.


_PROXY_CONTROL_PLANE_MTLS_MODES = {"app_native", "delegated", "disabled"}


def _app_native_mtls_config() -> dict[str, object]:
    cert_file = env_raw("AGENT_BOM_TLS_CERT_FILE", "").strip()
    key_file = env_raw("AGENT_BOM_TLS_KEY_FILE", "").strip()
    client_ca_file = env_raw("AGENT_BOM_TLS_CLIENT_CA_FILE", "").strip()
    require_client_cert = _env_flag("AGENT_BOM_TLS_REQUIRE_CLIENT_CERT")
    complete = bool(cert_file and key_file and client_ca_file and require_client_cert)
    missing = []
    if not cert_file:
        missing.append("AGENT_BOM_TLS_CERT_FILE")
    if not key_file:
        missing.append("AGENT_BOM_TLS_KEY_FILE")
    if not client_ca_file:
        missing.append("AGENT_BOM_TLS_CLIENT_CA_FILE")
    if not require_client_cert:
        missing.append("AGENT_BOM_TLS_REQUIRE_CLIENT_CERT")
    return {
        "cert_file_configured": bool(cert_file),
        "key_file_configured": bool(key_file),
        "client_ca_file_configured": bool(client_ca_file),
        "require_client_cert": require_client_cert,
        "complete": complete,
        "missing_evidence": missing,
    }


def describe_control_plane_direct_listener_posture(
    *,
    listener_host: str | None = None,
    mtls_ok: bool | None = None,
    trusted_proxy_ok: bool | None = None,
) -> dict[str, object]:
    """Return non-secret direct-listener posture for operator policy surfaces."""

    host = _configured_listener_host(listener_host)
    loopback = _is_loopback_listener(host)
    production_or_clustered = _production_or_clustered_control_plane()
    if mtls_ok is None or trusted_proxy_ok is None:
        mtls = describe_proxy_control_plane_mtls_posture(listener_host=host)
        if mtls_ok is None:
            mtls_ok = mtls.get("status") == "ok" and mtls.get("mtls_mode") in {"app_native", "delegated"}
        if trusted_proxy_ok is None:
            trusted_proxy_ok = get_trusted_proxy_auth_status().get("status") == "ok"
    unsafe = bool(production_or_clustered and not loopback and not mtls_ok and not trusted_proxy_ok)
    return {
        "host": host,
        "loopback": loopback,
        "production_or_clustered": production_or_clustered,
        "trusted_proxy_attestation": "enabled" if trusted_proxy_ok else "disabled",
        "mtls_enforced": bool(mtls_ok),
        "status": "unknown" if host == "unknown" else ("unsafe" if unsafe else "ok"),
        "message": (
            "Listener address is not declared; set AGENT_BOM_API_HOST to the ASGI server's actual bind address."
            if host == "unknown"
            else "Production or clustered control planes must not expose a non-loopback listener without "
            "trusted-proxy attestation or app-native mTLS."
            if unsafe
            else "Direct listener posture is acceptable for the declared deployment mode."
        ),
    }


def require_safe_control_plane_listener(listener_host: str | None = None) -> None:
    """Fail closed for unsafe production/clustered direct listener exposure."""

    posture = describe_control_plane_direct_listener_posture(listener_host=listener_host)
    if posture["status"] == "unsafe":
        raise RuntimeError(str(posture["message"]))


def describe_proxy_control_plane_mtls_posture(*, listener_host: str | None = None) -> dict[str, object]:
    """Return non-secret proxy-to-control-plane mTLS posture.

    Delegated ingress or service-mesh mTLS remains the production default.
    App-native mTLS is available as a fallback for non-mesh deployments and is
    reported here only from non-secret environment posture.
    """

    raw_mode = env_raw("AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_MODE", "disabled").strip().lower() or "disabled"
    provider = env_raw("AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_PROVIDER", "").strip()
    client_ca_ref = env_raw("AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_CLIENT_CA_REF", "").strip()
    evidence_ref = env_raw("AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_EVIDENCE_REF", "").strip()
    cert_header = env_raw("AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_CERT_HEADER", "").strip()
    trusted_proxy = get_trusted_proxy_auth_status()
    app_native = _app_native_mtls_config()
    effective_mode = "app_native" if raw_mode == "app_native" or app_native["complete"] else raw_mode
    mtls_mode = "none" if effective_mode == "disabled" else effective_mode

    base: dict[str, object] = {
        "mode": effective_mode,
        "declared_mode": raw_mode,
        "mtls_mode": mtls_mode,
        "supported_modes": sorted(_PROXY_CONTROL_PLANE_MTLS_MODES),
        "mode_env": "AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_MODE",
        "provider": provider or None,
        "client_ca_ref_configured": bool(client_ca_ref),
        "client_cert_header_configured": bool(cert_header),
        "evidence_ref": evidence_ref or None,
        "trusted_proxy_auth_status": trusted_proxy.get("status"),
        "trusted_proxy_issuer_pinned": bool(trusted_proxy.get("issuer_pinned")),
        "trusted_proxy_attestation": "enabled" if trusted_proxy.get("status") == "ok" else "disabled",
        "app_native_mtls": app_native,
    }
    if raw_mode not in _PROXY_CONTROL_PLANE_MTLS_MODES:
        return {
            **base,
            "status": "misconfigured",
            "enforced": False,
            "message": (
                "Unsupported AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_MODE. Use disabled or delegated; "
                "terminate and verify mTLS in ingress, Envoy, or a service mesh, or use app_native with TLS env vars."
            ),
        }
    if effective_mode == "app_native":
        status = "ok" if app_native["complete"] else "needs_evidence"
        missing = list(cast(list[str], app_native["missing_evidence"]))
        direct = describe_control_plane_direct_listener_posture(
            listener_host=listener_host,
            mtls_ok=status == "ok",
            trusted_proxy_ok=trusted_proxy.get("status") == "ok",
        )
        return {
            **base,
            "status": status,
            "enforced": status == "ok",
            "missing_evidence": missing,
            "direct_listener": direct,
            "message": (
                "App-native mTLS is configured for the FastAPI control plane."
                if status == "ok"
                else "App-native mTLS was requested, but TLS certificate, key, client CA, or client-cert enforcement is incomplete."
            ),
        }
    if effective_mode == "disabled":
        direct = describe_control_plane_direct_listener_posture(
            listener_host=listener_host,
            mtls_ok=False,
            trusted_proxy_ok=trusted_proxy.get("status") == "ok",
        )
        return {
            **base,
            "status": "disabled",
            "enforced": False,
            "direct_listener": direct,
            "message": "Proxy-to-control-plane mTLS posture is disabled or not declared.",
        }

    return _delegated_mtls_posture(base, trusted_proxy, client_ca_ref, evidence_ref, listener_host)


def _delegated_mtls_posture(
    base: dict[str, object], trusted_proxy: dict, client_ca_ref: str, evidence_ref: str, listener_host: str | None
) -> dict[str, object]:
    trusted_ok = trusted_proxy.get("status") == "ok"
    status = "ok" if client_ca_ref and evidence_ref and trusted_ok else "needs_evidence"
    missing = []
    if not client_ca_ref:
        missing.append("AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_CLIENT_CA_REF")
    if not evidence_ref:
        missing.append("AGENT_BOM_PROXY_CONTROL_PLANE_MTLS_EVIDENCE_REF")
    if not trusted_ok:
        missing.append("trusted proxy auth with issuer pinning")
    direct = describe_control_plane_direct_listener_posture(
        listener_host=listener_host,
        mtls_ok=status == "ok",
        trusted_proxy_ok=trusted_ok,
    )
    return {
        **base,
        "status": status,
        "enforced": True,
        "missing_evidence": missing,
        "direct_listener": direct,
        "message": (
            "Delegated mTLS is declared and backed by client-CA evidence plus trusted-proxy issuer pinning."
            if status == "ok"
            else "Delegated mTLS is declared, but operator evidence is incomplete."
        ),
    }


class RateLimitMiddleware(_RateLimitMiddleware):
    """Compose tenant rate limiting with the current API key store."""

    def __init__(
        self,
        app: ASGIApp,
        scan_rpm: int = DEFAULT_SCAN_RATE_LIMIT_RPM,
        read_rpm: int = DEFAULT_READ_RATE_LIMIT_RPM,
        authenticated_read_rpm: int = DEFAULT_AUTHENTICATED_READ_RATE_LIMIT_RPM,
    ) -> None:
        super().__init__(
            app,
            scan_rpm=scan_rpm,
            read_rpm=read_rpm,
            authenticated_read_rpm=authenticated_read_rpm,
            get_key_store=lambda: get_key_store(),
        )
