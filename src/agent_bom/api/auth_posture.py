"""Auth posture."""

from __future__ import annotations

import ipaddress
from typing import cast

from agent_bom.api.auth_runtime_state import _AUTH_POSTURE as _AUTH_POSTURE
from agent_bom.api.auth_runtime_state import _AUTH_RUNTIME_STATUS as _AUTH_RUNTIME_STATUS
from agent_bom.api.auth_runtime_state import _EMPTY_AUTH_POSTURE as _EMPTY_AUTH_POSTURE
from agent_bom.api.auth_runtime_state import AuthPosture as AuthPosture
from agent_bom.api.auth_runtime_state import AuthPostureError as AuthPostureError
from agent_bom.api.auth_runtime_state import apply_auth_posture as apply_auth_posture
from agent_bom.api.auth_runtime_state import get_auth_posture as get_auth_posture
from agent_bom.api.auth_runtime_state import get_auth_runtime_status as get_auth_runtime_status
from agent_bom.api.storage.deployment import _production_or_clustered_control_plane
from agent_bom.core.settings import env_bool, env_raw, env_str

_TRUSTED_PROXY_SECRET_MIN_BYTES = 32


def _env_flag(name: str) -> bool:
    return env_bool(name, False, on_invalid="default")


def _secret_min_bytes(secret: str) -> int:
    return len(secret.encode("utf-8"))


def _trusted_proxy_secret_is_strong(secret: str) -> bool:
    return _secret_min_bytes(secret) >= _TRUSTED_PROXY_SECRET_MIN_BYTES


def get_trusted_proxy_auth_status() -> dict[str, object]:
    """Return trusted-proxy auth posture without exposing secret material."""
    from agent_bom.api.secret_source import resolve_secret

    enabled = _env_flag("AGENT_BOM_TRUST_PROXY_AUTH")
    secret = resolve_secret("AGENT_BOM_TRUST_PROXY_AUTH_SECRET")
    issuer = env_str("AGENT_BOM_TRUST_PROXY_AUTH_ISSUER")
    if not enabled:
        return {
            "enabled": False,
            "status": "disabled",
            "secret_min_bytes": _TRUSTED_PROXY_SECRET_MIN_BYTES,
            "issuer_pinned": False,
            "message": "Trusted reverse-proxy header authentication is disabled.",
        }
    if not secret:
        return {
            "enabled": True,
            "status": "misconfigured",
            "secret_configured": False,
            "secret_min_bytes": _TRUSTED_PROXY_SECRET_MIN_BYTES,
            "issuer_pinned": bool(issuer),
            "message": "AGENT_BOM_TRUST_PROXY_AUTH is enabled but AGENT_BOM_TRUST_PROXY_AUTH_SECRET is not set.",
        }
    if not _trusted_proxy_secret_is_strong(secret):
        return {
            "enabled": True,
            "status": "weak_secret",
            "secret_configured": True,
            "secret_min_bytes": _TRUSTED_PROXY_SECRET_MIN_BYTES,
            "issuer_pinned": bool(issuer),
            "message": (
                f"AGENT_BOM_TRUST_PROXY_AUTH_SECRET must contain at least {_TRUSTED_PROXY_SECRET_MIN_BYTES} bytes of secret material."
            ),
        }
    return {
        "enabled": True,
        "status": "ok" if issuer else "issuer_unpinned",
        "secret_configured": True,
        "secret_min_bytes": _TRUSTED_PROXY_SECRET_MIN_BYTES,
        "issuer_pinned": bool(issuer),
        "issuer": issuer or None,
        "message": (
            "Trusted proxy auth uses strong shared-secret attestation."
            if issuer
            else (
                "Trusted proxy auth uses strong shared-secret attestation; set "
                "AGENT_BOM_TRUST_PROXY_AUTH_ISSUER to pin the upstream issuer."
            )
        ),
    }


def trusted_proxy_auth_usable() -> bool:
    """Return whether trusted-proxy auth is enabled with a strong resolved secret.

    The feature flag alone is not an authentication mechanism.  Treat unreadable
    mounted secrets, missing values, and weak values as unusable so startup gates
    and health posture describe the same boundary enforced by the middleware.
    """
    try:
        status = get_trusted_proxy_auth_status()
    except (OSError, ValueError):
        return False
    return status.get("status") in {"ok", "issuer_unpinned"}


def _is_loopback_listener(host: str | None) -> bool:
    cleaned = (host or "").strip().lower()
    if not cleaned:
        return False
    if cleaned in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(cleaned).is_loopback
    except ValueError:
        return False


def _configured_listener_host(host: str | None = None) -> str:
    # Direct ASGI imports do not reveal the ASGI server's actual bind address.
    return (host or "").strip() or env_str("AGENT_BOM_API_HOST") or "unknown"


def derive_auth_posture(
    *,
    api_key_configured: bool,
    allow_unauthenticated: bool,
    listener_host: str | None = None,
) -> AuthPosture:
    """Derive the auth posture from the environment plus caller-known facts.

    This is the single derivation of the env-based credential-source facts
    (OIDC bearer/browser, Snowflake OAuth, SCIM, SAML, trusted proxy). The
    caller supplies the two facts it uniquely knows — whether an API key source
    is configured (static key flag / env keys / runtime key store) and whether
    the unauthenticated opt-in is on — and the listener host being bound.
    """
    from agent_bom.api.oidc import OIDCConfig, OIDCError, oidc_enabled_from_env
    from agent_bom.api.oidc_browser import oidc_browser_enabled_from_env
    from agent_bom.api.saml import saml_enabled_from_env
    from agent_bom.api.scim import scim_enabled_from_env
    from agent_bom.api.snowflake_oauth import snowflake_oauth_enabled_from_env

    oidc_bearer = oidc_enabled_from_env()
    oidc_config_invalid = False
    oidc_config_error: str | None = None
    if oidc_bearer:
        try:
            OIDCConfig.from_env()
        except OIDCError as exc:
            from agent_bom.security import sanitize_error

            oidc_config_invalid = True
            oidc_config_error = sanitize_error(exc)

    host = _configured_listener_host(listener_host)
    return AuthPosture(
        listener_host=host,
        listener_loopback=_is_loopback_listener(host),
        api_key=bool(api_key_configured),
        oidc_bearer=oidc_bearer,
        oidc_browser=oidc_browser_enabled_from_env(),
        snowflake_oauth=snowflake_oauth_enabled_from_env(),
        scim_bearer=scim_enabled_from_env(),
        saml=saml_enabled_from_env(),
        trusted_proxy=trusted_proxy_auth_usable(),
        anonymous_allowed=bool(allow_unauthenticated),
        oidc_config_invalid=oidc_config_invalid,
        oidc_config_error=oidc_config_error,
    )


def validate_auth_posture(posture: AuthPosture) -> None:
    """Raise ``AuthPostureError`` for an internally contradictory posture.

    Consolidation, not policy change: this only rejects combinations that are
    already broken today (a malformed/contradictory OIDC configuration currently
    500s on the first OIDC request). Every combination that boots and serves
    today keeps working — including trusted-proxy alongside direct OIDC on one
    listener, which stays allowed.
    """
    if posture.oidc_config_invalid:
        detail = posture.oidc_config_error or "OIDC configuration is invalid"
        raise AuthPostureError(f"Invalid OIDC configuration: {detail}")


def configure_auth_runtime(
    *,
    api_key_configured: bool,
    oidc_enabled: bool,
    trusted_proxy_enabled: bool,
    scim_enabled: bool = False,
    saml_enabled: bool = False,
    oidc_browser_enabled: bool = False,
    snowflake_oauth_enabled: bool = False,
    unauthenticated_allowed: bool = False,
) -> None:
    """Build and apply an :class:`AuthPosture` from already-derived source facts.

    Backward-compatible entry point: callers that have already resolved the
    per-source booleans (notably ``configure_api``) hand them here, and the
    posture object becomes the single stored source the runtime status,
    ``/health``, and the startup log all read.
    """
    host = _configured_listener_host(None)
    posture = AuthPosture(
        listener_host=host,
        listener_loopback=_is_loopback_listener(host),
        api_key=bool(api_key_configured),
        oidc_bearer=bool(oidc_enabled),
        oidc_browser=bool(oidc_browser_enabled),
        snowflake_oauth=bool(snowflake_oauth_enabled),
        scim_bearer=bool(scim_enabled),
        saml=bool(saml_enabled),
        trusted_proxy=bool(trusted_proxy_enabled),
        anonymous_allowed=bool(unauthenticated_allowed),
    )
    apply_auth_posture(posture)


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
