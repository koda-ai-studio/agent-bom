"""Fail-closed listener and storage posture checks for server startup."""

from __future__ import annotations

import importlib.util
import ipaddress
import os
import secrets
import ssl
import sys
import tempfile
from pathlib import Path
from typing import Any

import click

from agent_bom.api.secret_source import secret_is_configured
from agent_bom.core.settings import env_flag, env_raw, env_str


def _require_optional_dependencies(command: str, extra: str, modules: dict[str, str]) -> None:
    """Fail fast with an actionable install hint for optional runtime surfaces."""
    missing = [label for label, module_name in modules.items() if importlib.util.find_spec(module_name) is None]
    if not missing:
        return
    _fail_missing_optional_dependencies(command, extra, missing)


def _fail_missing_optional_dependencies(command: str, extra: str, missing: list[str]) -> None:
    """Print the shared optional-extra install hint and exit."""
    missing_text = ", ".join(missing)
    click.echo(
        f"ERROR: {missing_text} required for `{command}`.\n"
        f"Install with:  uv pip install 'agent-bom[{extra}]'  (or: pip install 'agent-bom[{extra}]')",
        err=True,
    )
    sys.exit(1)


def _is_loopback_host(host: str) -> bool:
    """Return True when ``host`` resolves to loopback-only access."""
    cleaned = host.strip().lower()
    if cleaned in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(cleaned).is_loopback
    except ValueError:
        return False


def _enforce_cors_posture(host: str, cors_allow_all: bool) -> None:
    """Keep wildcard browser access confined to a loopback development listener."""
    if cors_allow_all and not _is_loopback_host(host):
        raise click.ClickException(
            "Refusing wildcard CORS on a non-loopback listener. Configure explicit CORS origins for every trusted UI."
        )


def _oidc_enabled() -> bool:
    """Return True when OIDC auth is configured via environment."""
    from agent_bom.api.oidc import oidc_enabled_from_env

    return oidc_enabled_from_env()


def _scim_bearer_enabled() -> bool:
    """True when a SCIM bearer token is configured.

    Imported lazily so command-line tooling that doesn't touch SCIM doesn't
    pay the import cost.
    """
    from agent_bom.api.scim import scim_enabled_from_env

    return scim_enabled_from_env()


def _saml_enabled() -> bool:
    """True when SAML SSO is configured via environment.

    Imported lazily so command-line tooling that doesn't touch SAML doesn't
    pay the import cost.
    """
    from agent_bom.api.saml import saml_enabled_from_env

    return saml_enabled_from_env()


def _enforce_auth_defaults(command: str, host: str, api_key: str | None, allow_insecure_no_auth: bool) -> None:
    """Refuse unauthenticated non-loopback binds unless explicitly overridden.

    Recognises six auth paths:
    - explicit API key (--api-key / AGENT_BOM_API_KEY)
    - OIDC (AGENT_BOM_OIDC_ISSUER + tenant providers)
    - SCIM bearer (AGENT_BOM_SCIM_BEARER_TOKEN) -- the SCIM middleware
      authenticates every endpoint when this is configured
    - SAML SSO (AGENT_BOM_SAML_IDP_* + AGENT_BOM_SAML_SP_*) -- browser users
      authenticate against the IdP and receive a short-lived session API key;
      anonymous requests still fail closed via the API-key middleware, which
      stays installed whenever any auth path is configured
    - trusted reverse-proxy auth (feature flag + strong env/file secret)
    - --allow-insecure-no-auth (explicit override; emits a loud warning when
      another auth method is also configured so operators understand that
      their `--allow-insecure-no-auth` does NOT actually disable the SCIM /
      SAML / OIDC / API-key middleware path that's still in effect)
    """
    from agent_bom.api.auth_posture import AuthPostureError, derive_auth_posture, validate_auth_posture

    has_api_key = bool(api_key or secret_is_configured("AGENT_BOM_API_KEYS") or secret_is_configured("AGENT_BOM_API_KEY"))
    # One derivation, shared with configure_api: the CLI serve gate reads the
    # same posture rather than re-deriving each credential-source fact from env.
    posture = derive_auth_posture(
        api_key_configured=has_api_key,
        allow_unauthenticated=_resolve_allow_unauthenticated(allow_insecure_no_auth),
        listener_host=host,
    )
    # A contradictory/broken auth configuration (e.g. malformed OIDC) is a
    # fail-fast startup error on any host — consolidation surfaces it here
    # instead of a per-request 500 later.
    try:
        validate_auth_posture(posture)
    except AuthPostureError as exc:
        raise click.ClickException(str(exc)) from exc

    if posture.listener_loopback:
        return

    if posture.programmatic_auth_configured:
        if allow_insecure_no_auth:
            active: list[str] = []
            if posture.api_key:
                active.append("API-key")
            if posture.oidc_bearer:
                active.append("OIDC")
            if posture.scim_bearer:
                active.append("SCIM-bearer")
            if posture.saml:
                active.append("SAML")
            if posture.trusted_proxy:
                active.append("trusted-proxy")
            click.secho(
                f"warning: --allow-insecure-no-auth was passed but {', '.join(active)} authentication is "
                "still configured -- requests will continue to be authenticated. "
                "Unset the relevant env vars to actually run unauthenticated.",
                fg="yellow",
                err=True,
            )
        return
    if allow_insecure_no_auth:
        return
    raise click.ClickException(
        f"Refusing to expose `{command}` on non-loopback host {host!r} without authentication. "
        "Set --api-key / AGENT_BOM_API_KEY, configure AGENT_BOM_API_KEYS, configure AGENT_BOM_OIDC_ISSUER / "
        "AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON, set AGENT_BOM_SCIM_BEARER_TOKEN, configure SAML SSO "
        "(AGENT_BOM_SAML_IDP_ENTITY_ID / AGENT_BOM_SAML_SP_ENTITY_ID + related), "
        "configure AGENT_BOM_TRUST_PROXY_AUTH with a strong AGENT_BOM_TRUST_PROXY_AUTH_SECRET, "
        "or pass --allow-insecure-no-auth to override."
    )


def _uvicorn_tls_kwargs() -> dict[str, Any]:
    """Return uvicorn TLS kwargs from app-native control-plane TLS env vars."""
    cert_file = env_str("AGENT_BOM_TLS_CERT_FILE")
    key_file = env_str("AGENT_BOM_TLS_KEY_FILE")
    client_ca_file = env_str("AGENT_BOM_TLS_CLIENT_CA_FILE")
    require_client_cert = env_flag("AGENT_BOM_TLS_REQUIRE_CLIENT_CERT")

    if require_client_cert and not client_ca_file:
        raise click.ClickException("AGENT_BOM_TLS_REQUIRE_CLIENT_CERT requires AGENT_BOM_TLS_CLIENT_CA_FILE.")
    if client_ca_file and not require_client_cert:
        raise click.ClickException("AGENT_BOM_TLS_CLIENT_CA_FILE requires AGENT_BOM_TLS_REQUIRE_CLIENT_CERT=1.")
    if bool(cert_file) != bool(key_file):
        raise click.ClickException("AGENT_BOM_TLS_CERT_FILE and AGENT_BOM_TLS_KEY_FILE must be configured together.")
    if not cert_file:
        return {}

    kwargs: dict[str, Any] = {
        "ssl_certfile": cert_file,
        "ssl_keyfile": key_file,
    }
    if require_client_cert:
        kwargs["ssl_ca_certs"] = client_ca_file
        kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED
    return kwargs


def _enforce_control_plane_listener_posture(host: str) -> None:
    """Fail closed when production/clustered direct listener posture is unsafe."""
    from agent_bom.api.middleware import require_safe_control_plane_listener

    try:
        require_safe_control_plane_listener(listener_host=host)
    except RuntimeError as exc:
        raise click.ClickException(str(exc)) from exc


def _enforce_database_role_posture(command: str) -> None:
    """Fail fast when Postgres application or maintenance roles are unsafe.

    Tenant isolation on Postgres is enforced solely by ``FORCE ROW LEVEL
    SECURITY``; a ``SUPERUSER`` / ``BYPASSRLS`` role ignores it and voids the
    isolation. ``_guard_rls_capable_role`` already refuses such a role, but only
    lazily on the first pool use (i.e. per request). Running it here — beside the
    non-loopback auth gate, before uvicorn binds — turns that into a single,
    actionable boot error instead of a 500 on every request. The same preflight
    requires an independently named, marker-authorized maintenance login so
    cross-tenant work cannot reuse the application principal. No-op unless
    Postgres is active. Every failed probe is fatal because a configured
    maintenance boundary that cannot be authenticated and validated is not a
    safe state in which to accept requests.
    """
    if env_raw("SNOWFLAKE_ACCOUNT"):
        return
    if not env_raw("AGENT_BOM_POSTGRES_URL"):
        return
    from agent_bom.api import postgres_common

    try:
        postgres_common.preflight_rls_capable_role()
    except (
        postgres_common.MaintenanceRoleConfigurationError,
        postgres_common.RlsRolePrivilegeError,
        ValueError,
    ) as exc:
        raise click.ClickException(str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 - convert driver/config failures into a safe CLI error
        # Do not expose the raw driver exception: authentication failures can
        # include connection strings, hosts, usernames, or secret-file paths.
        raise click.ClickException(
            f"Postgres role preflight failed before {command} could bind. Verify the distinct "
            "application and maintenance credentials, database reachability, migrations, and "
            "agent_bom_rls_maintenance membership."
        ) from exc


def _enforce_writable_control_plane_state(command: str) -> None:
    """Fail once, before app import, when durable SQLite state is unwritable."""
    from agent_bom.api.durable_store import select_backend, sqlite_path

    backend = select_backend()
    # Jobs may still use SQLite when lifecycle stores are ephemeral.
    if backend != "sqlite" and not (backend == "memory" and env_raw("AGENT_BOM_DB")):
        return
    raw_path = sqlite_path(create_parent=False)
    if raw_path == ":memory:":
        return

    database_path = Path(raw_path).expanduser()
    directory = database_path.parent
    try:
        directory.mkdir(parents=True, exist_ok=True)
        # SQLite may create journal, WAL, and shared-memory sidecars even when
        # the database file already exists, so the parent must always be
        # writable as well as the file itself.
        with tempfile.NamedTemporaryFile(prefix=".agent-bom-write-probe-", dir=directory):
            pass
        if database_path.exists():
            descriptor = os.open(database_path, os.O_WRONLY | os.O_APPEND)
            os.close(descriptor)
    except OSError as exc:
        raise click.ClickException(
            "Control-plane state is not writable. Set a writable state directory and retry:\n"
            f"  AGENT_BOM_STATE_DIR=/writable/path agent-bom {command}\n"
            "Or choose an explicit database with --persist /writable/path/control-plane.db."
        ) from exc


def _enforce_remote_mcp_auth_defaults(host: str, bearer_token: str | None, allow_insecure_no_auth: bool) -> None:
    """Refuse unauthenticated remote MCP transports on non-loopback binds."""
    from agent_bom.mcp_tools.oauth import OAuthConfig, oauth_configured

    if oauth_configured():
        try:
            OAuthConfig.from_env()  # Incomplete configuration never opens a listener.
        except ValueError as exc:
            raise click.ClickException("Incomplete or invalid MCP OAuth configuration") from exc
        return
    if bearer_token or _is_loopback_host(host):
        return
    if allow_insecure_no_auth:
        return
    raise click.ClickException(
        f"Refusing to expose `mcp server` on non-loopback host {host!r} without transport authentication. "
        "Set --bearer-token / AGENT_BOM_MCP_BEARER_TOKEN or pass --allow-insecure-no-auth to override."
    )


def _env_truthy(name: str) -> bool:
    """Return True when environment variable ``name`` holds a truthy flag."""
    return env_flag(name)


def _resolve_allow_unauthenticated(allow_insecure_no_auth: bool) -> bool:
    """Resolve the effective unauthenticated-API posture the server will apply.

    Mirrors ``configure_api``: the ``--allow-insecure-no-auth`` flag OR the
    ``AGENT_BOM_ALLOW_UNAUTHENTICATED_API`` env var enables it. Non-loopback
    binds are already gated fail-closed by ``_enforce_auth_defaults`` before
    this runs, so the env var can only take effect on loopback.
    """
    return bool(allow_insecure_no_auth) or _env_truthy("AGENT_BOM_ALLOW_UNAUTHENTICATED_API")


_DEV_API_KEY_PREFIX = "abk"


def _generate_dev_api_key() -> str:
    """Return a fresh ephemeral loopback dev API key (per-process, not persisted)."""
    return f"{_DEV_API_KEY_PREFIX}_{secrets.token_urlsafe(24)}"


def _should_auto_generate_dev_key(*, host: str, api_key: str | None, allow_insecure_no_auth: bool) -> bool:
    """Decide whether a zero-config loopback dev API key should be auto-generated.

    Fail-closed by construction: only ever true on a loopback bind with no other
    auth path configured. Any explicit key, override, configured auth backend, or
    the ``AGENT_BOM_NO_AUTO_DEV_KEY`` opt-out keeps the current behaviour (fail
    closed on loopback, or the existing non-loopback refusal in
    ``_enforce_auth_defaults``). A non-loopback host NEVER auto-generates a key.
    """
    if not _is_loopback_host(host):
        return False
    if _env_truthy("AGENT_BOM_NO_AUTO_DEV_KEY"):
        return False
    if api_key or allow_insecure_no_auth:
        return False

    if secret_is_configured("AGENT_BOM_API_KEYS") or secret_is_configured("AGENT_BOM_API_KEY"):
        return False
    if _oidc_enabled() or _scim_bearer_enabled() or _saml_enabled():
        return False
    if _env_truthy("AGENT_BOM_ALLOW_UNAUTHENTICATED_API"):
        return False
    if _env_truthy("AGENT_BOM_TRUST_PROXY_AUTH"):
        return False
    return True


def _auth_summary(
    *,
    host: str,
    api_key: str | None = None,
    bearer_token: str | None = None,
    allow_insecure_no_auth: bool = False,
    oidc_enabled: bool = False,
    mcp_remote: bool = False,
) -> str:
    """Return a user-facing summary for the active auth mode."""

    if api_key or secret_is_configured("AGENT_BOM_API_KEYS") or secret_is_configured("AGENT_BOM_API_KEY"):
        return "API key required (Bearer / X-API-Key)"
    if bearer_token:
        return "Bearer token required"
    if oidc_enabled:
        return "OIDC bearer token required"
    if allow_insecure_no_auth and not _is_loopback_host(host):
        return "Disabled by explicit override (--allow-insecure-no-auth)"
    if mcp_remote:
        return "Loopback-only without transport auth; add --bearer-token before exposing remotely"
    return "local unauthenticated mode (loopback only); add --api-key or OIDC before exposing remotely"


def _api_auth_summary(
    *,
    host: str,
    api_key: str | None,
    oidc_enabled: bool,
    allow_unauthenticated: bool,
    dev_api_key: str | None = None,
) -> str:
    """Return a startup banner that matches the server's real auth posture.

    Derived from the same inputs ``configure_api`` uses so the banner can never
    claim unauthenticated access while the API actually fails closed (or vice
    versa). ``allow_unauthenticated`` is the resolved flag-OR-env value.
    ``dev_api_key`` is the auto-generated loopback key, if one was minted.
    """

    if api_key or secret_is_configured("AGENT_BOM_API_KEYS") or secret_is_configured("AGENT_BOM_API_KEY"):
        return "API key required (Bearer / X-API-Key)"
    if dev_api_key:
        return "auto dev API key (loopback only); the local UI uses it automatically"
    if oidc_enabled:
        return "OIDC bearer token required"
    if _scim_bearer_enabled():
        return "SCIM bearer token required"
    if _saml_enabled():
        return "SAML SSO (IdP session mints a short-lived session API key)"
    if _env_truthy("AGENT_BOM_TRUST_PROXY_AUTH"):
        return "Reverse-proxy auth (trusted proxy headers)"
    if allow_unauthenticated:
        if _is_loopback_host(host):
            return "local unauthenticated mode (loopback only); add --api-key or OIDC before exposing remotely"
        return "Disabled by explicit override (--allow-insecure-no-auth)"
    return (
        "auth required but no key configured; requests fail closed (401). "
        "Pass --allow-insecure-no-auth for a local demo, or set --api-key / AGENT_BOM_API_KEY."
    )
