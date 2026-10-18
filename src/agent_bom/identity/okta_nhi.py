"""Okta non-human-identity (NHI) discovery.

Enumerates the *machine* identities in an Okta org — OAuth2 service apps
(client-credentials service accounts) and API tokens — and returns them as
normalized :class:`DiscoveredNonHumanIdentity` records. The
``agent_bom.graph.nhi_overlay`` projects those records into the unified graph as
``managed_identity`` nodes so the governance / effective-permissions overlays
can reason about them alongside agent-bom-issued identities.

Trust posture (mirrors the cloud read-only providers):

* **Read-only / reference-only.** Only ``GET`` list endpoints are called; no
  Okta write API is ever invoked and no secret material (token values, client
  secrets) is read — only references and metadata.
* **Token-authenticated.** An SSWS token is read from the
  ``AGENT_BOM_OKTA_TOKEN`` environment variable, or a scoped DPoP-bound OAuth
  token is obtained using a local private-key file. The org base URL comes
  from ``AGENT_BOM_OKTA_ORG_URL``.
* **Gated, default OFF.** Discovery only runs when
  ``AGENT_BOM_OKTA_DISCOVERY`` is set to a truthy value. Otherwise it returns a
  ``DISABLED`` status without touching the network.
* **Never raises.** A missing client, missing credentials, or an API error
  degrades to a populated :class:`NHIDiscoveryResult` carrying a clear status
  and a user-safe warning — discovery callers never have to wrap this in a
  ``try``/``except``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any

from agent_bom.core.settings import env_str
from agent_bom.identity.okta_http import MetadataReader, PartialCollectionError, org_origin
from agent_bom.security import sanitize_text

logger = logging.getLogger(__name__)

_DISCOVERY_FLAG_ENV = "AGENT_BOM_OKTA_DISCOVERY"
_TOKEN_ENV = "AGENT_BOM_OKTA_TOKEN"
_ORG_URL_ENV = "AGENT_BOM_OKTA_ORG_URL"

# Read-only Okta API scopes / endpoints this connector exercises. Kept here so
# the per-run trust contract stays honest — the producer owns the catalog.
OKTA_READ_PERMISSIONS: tuple[str, ...] = (
    "okta.apps.read",
    "okta.apiTokens.read",
)

# Okta OAuth2 app "signOnMode" / type values that denote a non-human
# (machine-to-machine, client-credentials) principal rather than a human SSO app.
_SERVICE_SIGN_ON_MODES = frozenset({"OPENID_CONNECT"})
_SERVICE_GRANT_TYPES = frozenset({"client_credentials"})

_MAX_RESULTS = 2000

_TRUTHY = frozenset({"1", "true", "yes", "on"})


class NHIDiscoveryStatus(str, Enum):
    """Outcome of an NHI discovery run (locked vocabulary)."""

    OK = "ok"
    """Discovery ran and returned a (possibly empty) identity list."""

    DISABLED = "disabled"
    """The discovery feature flag was not enabled — nothing was attempted."""

    MISSING_CREDENTIALS = "missing_credentials"
    """The flag was on but no token / org URL was configured."""

    MISSING_CLIENT = "missing_client"
    """The Okta SDK / HTTP client could not be constructed."""

    PARTIAL = "partial"
    """At least one collection failed or reached its collection bound."""

    ERROR = "error"
    """The flag and credentials were present but the API calls failed."""


@dataclass(frozen=True)
class DiscoveredNonHumanIdentity:
    """A normalized non-human identity discovered from an IdP.

    All fields are simple types so the record round-trips through the graph
    overlay, JSON, and the API surface. Credential *values* are never captured —
    only references and age/usage metadata.
    """

    identity_id: str
    """Stable provider identifier (Okta app id or api-token id)."""

    name: str
    """Human-readable label (app label / token name)."""

    identity_type: str
    """``service_account`` (OAuth2 service app) or ``api_token``."""

    provider: str = "okta"
    status: str = "active"
    owner: str | None = None
    """Owning user / principal where the API reports one."""

    created_at: str | None = None
    last_used_at: str | None = None
    credential_expires_at: str | None = None
    scopes: tuple[str, ...] = ()
    """Granted OAuth2 scopes / token privileges (references, not secrets)."""

    source_scope: str | None = None
    """Provider tenant origin used to disambiguate native IDs."""

    raw_identity: dict[str, Any] = field(default_factory=dict)
    """Low-risk provider fields kept for audit (ids, timestamps — no secrets)."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "source_scope": self.source_scope,
            "name": self.name,
            "identity_type": self.identity_type,
            "provider": self.provider,
            "status": self.status,
            "owner": self.owner,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "credential_expires_at": self.credential_expires_at,
            "scopes": list(self.scopes),
            "raw_identity": dict(self.raw_identity),
        }


@dataclass(frozen=True)
class NHIDiscoveryResult:
    """Result envelope for one NHI discovery run. Never raises into callers."""

    status: NHIDiscoveryStatus
    identities: tuple[DiscoveredNonHumanIdentity, ...] = ()
    warnings: tuple[str, ...] = ()
    org_url: str | None = None
    provider: str | None = None
    coverage: tuple[dict[str, Any], ...] = ()

    @property
    def ok(self) -> bool:
        return self.status is NHIDiscoveryStatus.OK


class OktaClient:
    """Minimal read-only Okta REST client (no third-party SDK required).

    Issues only ``GET`` metadata calls with SSWS or DPoP-bound OAuth.
    OAuth authentication separately posts to the token endpoint. Tests inject a fake
    client exposing the same ``list_oauth2_service_apps`` / ``list_api_tokens``
    methods, so no live call is ever made under test.
    """

    def __init__(self, org_url: str, token: str = "", *, auth: Any = None, transport: Any = None) -> None:
        self._reader = MetadataReader(org_url, token, auth=auth, transport=transport)

    def _get(self, path: str) -> list[dict[str, Any]]:
        return self._reader.collect(path)

    def list_oauth2_service_apps(self) -> list[dict[str, Any]]:
        """List OAuth2 / OIDC service applications (client-credentials NHIs)."""
        return self._get("/api/v1/apps?limit=200")

    def list_api_tokens(self) -> list[dict[str, Any]]:
        """List org API tokens (machine credentials)."""
        return self._get("/api/v1/api-tokens?limit=200")


def _validated_listing(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(
        not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"].strip() for row in value
    ):
        raise ValueError("Invalid Okta metadata collection")
    for row in value:
        for key in ("settings", "credentials"):
            if key not in row:
                continue
            block = row[key]
            if not isinstance(block, dict) or ("oauthClient" in block and not isinstance(block["oauthClient"], dict)):
                raise ValueError("Invalid Okta client configuration")
            oauth = block.get("oauthClient", {})
            if "grant_types" in oauth and (
                not isinstance(oauth["grant_types"], list) or any(not isinstance(g, str) for g in oauth["grant_types"])
            ):
                raise ValueError("Invalid Okta grant-type metadata")
    return value


def _is_truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in _TRUTHY


def _is_service_app(app: dict[str, Any]) -> bool:
    """A non-human OAuth2 app: OIDC service sign-on with client-credentials grant."""
    sign_on = str(app.get("signOnMode") or "").upper()
    if sign_on not in _SERVICE_SIGN_ON_MODES:
        return False
    settings = app.get("settings")
    oauth = settings.get("oauthClient", {}) if isinstance(settings, dict) else {}
    app_type = str(oauth.get("application_type") or "").lower()
    grants = {str(g).lower() for g in (oauth.get("grant_types") or [])}
    return app_type == "service" or bool(grants & _SERVICE_GRANT_TYPES)


def _oauth_grant_types(app: dict[str, Any]) -> tuple[str, ...]:
    settings = app.get("settings")
    oauth = settings.get("oauthClient", {}) if isinstance(settings, dict) else {}
    grants = oauth.get("grant_types") or []
    return tuple(str(g) for g in grants if str(g).strip())


def _normalize_service_app(app: dict[str, Any]) -> DiscoveredNonHumanIdentity | None:
    app_id = str(app.get("id") or "").strip()
    if not app_id:
        return None
    settings = app.get("settings")
    oauth = settings.get("oauthClient", {}) if isinstance(settings, dict) else {}
    credentials = app.get("credentials", {}).get("oauthClient", {})
    client_id = _opt_str(credentials.get("client_id")) or _opt_str(oauth.get("client_id")) or ""
    auth_method = _opt_str(credentials.get("token_endpoint_auth_method"))
    dpop = oauth.get("dpop_bound_access_tokens")
    return DiscoveredNonHumanIdentity(
        identity_id=app_id,
        name=str(app.get("label") or app.get("name") or app_id),
        identity_type="service_account",
        status=str(app.get("status") or "active").lower(),
        created_at=_opt_str(app.get("created")),
        last_used_at=None,
        scopes=(),
        raw_identity={
            "id": app_id,
            "name": str(app.get("name") or ""),
            "sign_on_mode": str(app.get("signOnMode") or ""),
            "client_id": client_id,
            "client_authentication": auth_method,
            "dpop_bound_access_tokens": dpop if isinstance(dpop, bool) else None,
            "grant_types": list(_oauth_grant_types(app)),
            "last_updated_at": _opt_str(app.get("lastUpdated")),
            "scope_coverage": "not_collected",
        },
    )


def _normalize_api_token(token: dict[str, Any]) -> DiscoveredNonHumanIdentity | None:
    token_id = str(token.get("id") or "").strip()
    if not token_id:
        return None
    return DiscoveredNonHumanIdentity(
        identity_id=token_id,
        name=str(token.get("name") or token_id),
        identity_type="api_token",
        status=str(token.get("status") or "active").lower(),
        owner=_opt_str(token.get("userId")),
        created_at=_opt_str(token.get("created")),
        last_used_at=None,
        credential_expires_at=_opt_str(token.get("expiresAt")),
        raw_identity={
            "id": token_id,
            "user_id": str(token.get("userId") or ""),
            "last_updated_at": _opt_str(token.get("lastUpdated")),
        },
    )


def _opt_str(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    return sanitize_text(value.strip(), max_len=512) or None


def _iter_normalized(
    raw_apps: Iterable[dict[str, Any]],
    raw_tokens: Iterable[dict[str, Any]],
) -> Iterator[DiscoveredNonHumanIdentity]:
    for app in raw_apps:
        if not isinstance(app, dict) or not _is_service_app(app):
            continue
        identity = _normalize_service_app(app)
        if identity is not None:
            yield identity
    for token in raw_tokens:
        if not isinstance(token, dict):
            continue
        identity = _normalize_api_token(token)
        if identity is not None:
            yield identity


def discover_okta_non_human_identities(
    *,
    client: Any = None,
    org_url: str | None = None,
    token: str | None = None,
    force: bool = False,
) -> NHIDiscoveryResult:
    """Discover non-human identities (service accounts + API tokens) from Okta.

    Read-only and gated: unless ``force`` is set (used by tests / explicit
    callers that already supply a ``client``), discovery only runs when the
    ``AGENT_BOM_OKTA_DISCOVERY`` flag is truthy. Returns a result envelope and
    never raises.

    Args:
        client: An injected Okta client exposing ``list_oauth2_service_apps()``
            and ``list_api_tokens()``. When ``None`` a read-only
            :class:`OktaClient` is built from the token + org URL.
        org_url: Okta org base URL; falls back to ``AGENT_BOM_OKTA_ORG_URL``.
        token: SSWS token; falls back to ``AGENT_BOM_OKTA_TOKEN``.
        force: Bypass the feature-flag gate (when a client is injected directly).
    """
    flag_on = force or client is not None or _is_truthy(env_str(_DISCOVERY_FLAG_ENV))
    if not flag_on:
        return NHIDiscoveryResult(
            provider="okta",
            status=NHIDiscoveryStatus.DISABLED,
            warnings=(f"Okta NHI discovery is disabled. Set {_DISCOVERY_FLAG_ENV}=1 to enable.",),
        )

    resolved_org = (org_url or env_str(_ORG_URL_ENV) or "").strip()
    if resolved_org:
        try:
            resolved_org = org_origin(resolved_org)
        except ValueError:
            return NHIDiscoveryResult(
                provider="okta", status=NHIDiscoveryStatus.MISSING_CREDENTIALS, warnings=("A valid HTTPS Okta tenant origin is required.",)
            )
    oauth_configured = bool(env_str("AGENT_BOM_OKTA_CLIENT_ID"))

    if client is None:
        resolved_token = (token or env_str(_TOKEN_ENV) or "").strip()
        if (not resolved_token and not oauth_configured) or not resolved_org:
            missing = []
            if not resolved_token:
                missing.append(_TOKEN_ENV)
            if not resolved_org:
                missing.append(_ORG_URL_ENV)
            return NHIDiscoveryResult(
                provider="okta",
                status=NHIDiscoveryStatus.MISSING_CREDENTIALS,
                org_url=resolved_org or None,
                warnings=(f"Okta NHI discovery enabled but missing: {', '.join(missing)}.",),
            )
        try:
            if oauth_configured:
                from agent_bom.identity.okta_oauth import from_environment

                client = OktaClient(resolved_org, auth=from_environment(resolved_org))
            else:
                client = OktaClient(resolved_org, resolved_token)
        except Exception:  # noqa: BLE001
            logger.debug("Could not construct Okta discovery client")
            return NHIDiscoveryResult(
                provider="okta",
                status=NHIDiscoveryStatus.MISSING_CLIENT,
                org_url=resolved_org or None,
                warnings=("Could not initialise the Okta client for NHI discovery.",),
            )

    return _discover_client(client, resolved_org)


def _collect_listing(fetch: Any, capability: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    try:
        try:
            rows = fetch()
        except PartialCollectionError as exc:
            rows = _validated_listing(exc.records)
            return rows, {"capability": capability, "state": "partial", "count": len(rows), "reason_code": exc.reason_code}
        rows = _validated_listing(rows)
        return rows, {"capability": capability, "state": "complete", "count": len(rows)}
    except Exception:  # broad-except: provider clients can fail with SDK-specific errors; expose only static coverage.
        return [], {"capability": capability, "state": "unknown", "count": None, "reason_code": "listing_failed"}


def _discover_client(client: Any, resolved_org: str) -> NHIDiscoveryResult:
    warnings: list[str] = []
    raw_apps: list[dict[str, Any]] = []
    raw_tokens: list[dict[str, Any]] = []
    failures = 0
    coverage: list[dict[str, Any]] = []

    raw_apps, app_coverage = _collect_listing(client.list_oauth2_service_apps, "applications")
    raw_tokens, token_coverage = _collect_listing(client.list_api_tokens, "api_token_metadata")
    coverage.extend((app_coverage, token_coverage))
    failures = sum(item["state"] == "unknown" for item in coverage)
    partial = any(item["state"] != "complete" for item in coverage)
    for item, label in zip(coverage, ("service-app", "API-token")):
        if item["state"] == "unknown":
            warnings.append(f"Okta {label} listing failed; coverage is incomplete.")
        elif item["state"] == "partial":
            warnings.append(f"Okta {label} listing reached a collection bound; coverage is incomplete.")

    all_identities = tuple(
        replace(identity, source_scope=resolved_org.rstrip("/") or None) for identity in _iter_normalized(raw_apps, raw_tokens)
    )
    identities = all_identities[:_MAX_RESULTS]
    truncated = len(all_identities) > _MAX_RESULTS
    if truncated:
        warnings.append("Okta identity collection limit reached; coverage is incomplete.")

    if failures == 2:
        return NHIDiscoveryResult(
            provider="okta",
            status=NHIDiscoveryStatus.ERROR,
            coverage=tuple(coverage),
            org_url=resolved_org or None,
            warnings=tuple(warnings),
        )

    return NHIDiscoveryResult(
        provider="okta",
        status=NHIDiscoveryStatus.PARTIAL if partial or truncated else NHIDiscoveryStatus.OK,
        identities=identities,
        coverage=tuple(coverage),
        warnings=tuple(warnings),
        org_url=resolved_org or None,
    )


__all__ = [
    "OKTA_READ_PERMISSIONS",
    "DiscoveredNonHumanIdentity",
    "NHIDiscoveryResult",
    "NHIDiscoveryStatus",
    "OktaClient",
    "discover_okta_non_human_identities",
]
