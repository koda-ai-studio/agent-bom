"""Snowflake cloud discovery — Cortex agents, MCP servers, Snowpark packages, governance.

Requires ``snowflake-connector-python``.  Install with::

    pip install 'agent-bom[snowflake]'

Authentication — zero-credential model (no passwords stored or logged):

agent-bom never stores credentials. Auth resolution order:

1. ``SNOWFLAKE_AUTHENTICATOR`` env var (or ``--snowflake-authenticator`` CLI flag)
   Recommended values:
   - ``externalbrowser``   — SSO via Okta/Azure AD/Google (opens browser) ← **default**
   - ``snowflake_jwt``     — RSA key-pair (set SNOWFLAKE_PRIVATE_KEY_PATH)
   - ``oauth``             — OAuth access token (set SNOWFLAKE_TOKEN)

2. ``SNOWFLAKE_PRIVATE_KEY_PATH`` env var — RSA key-pair auth (recommended for CI/CD)

3. ``SNOWFLAKE_PASSWORD`` env var — **deprecated**, emits a runtime warning.
   Migrate to SSO (``externalbrowser``) or key-pair (``SNOWFLAKE_PRIVATE_KEY_PATH``).

All credentials are read from environment at runtime and passed directly to the
Snowflake connector. They are never logged, stored, or transmitted by agent-bom.
Errors are sanitized before display (sanitize_error strips secrets from messages).

Required Snowflake privileges (read-only):
    IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE (for ACCOUNT_USAGE)
    USAGE ON WAREHOUSE <warehouse>
    SELECT on SNOWFLAKE.ACCOUNT_USAGE views (for CIS benchmark)
"""

from __future__ import annotations

import logging
import os
import warnings
from typing import Any

from agent_bom.cloud.snowflake_spcs_auth import apply_spcs_workload_identity
from agent_bom.discovery_envelope import DiscoveryEnvelope, RedactionStatus, ScanMode, attach_envelope_to_agents
from agent_bom.governance import GovernanceReport
from agent_bom.models import Agent
from agent_bom.security import sanitize_error

from .base import CloudDiscoveryError
from .snowflake_ai_surfaces import (
    _describe_mcp_server_tools,
    _discover_cortex_agents,
    _discover_cortex_services,
    _discover_custom_tools,
    _discover_from_query_history,
    _discover_mcp_servers,
    _discover_snowpark_packages,
    _discover_streamlit_apps,
    _parse_create_statement_name,
)
from .snowflake_common import (
    _CONTROL_CHAR_RE as _CONTROL_CHAR_RE,
)
from .snowflake_common import (
    _SAFE_IDENT_RE as _SAFE_IDENT_RE,
)
from .snowflake_common import (
    _coerce_int_or_none,
    _parse_json_field,
    _parse_json_object,
    _quote_sf_identifier,
    _record_snowflake_inventory_failure,
    _sf_truthy,
    _validate_sf_identifier,
)
from .snowflake_common import (
    _coerce_snowflake_days as _coerce_snowflake_days,
)
from .snowflake_common import (
    _env_or_value as _env_or_value,
)
from .snowflake_discovery._base import (  # noqa: F401 - facade re-export
    _active_borrowed_connection,
    _base_connect_kwargs,
    _borrowed_connection,
    _BorrowedConnection,
    _for_each_row,
    _warn_with,
)
from .snowflake_discovery.ai_surfaces import (  # noqa: F401 - facade re-export
    _discover_ai_surfaces,
    _mine_governance_report,
    _snowflake_cloud_origin,
    _snowpark_agent,
)
from .snowflake_discovery.estate import (  # noqa: F401 - facade re-export
    _estate_exfil,
    _estate_external_data,
    _estate_governance,
    _estate_integrations,
    _estate_login_anomalies,
    _estate_object_graph,
    _estate_pipeline,
    _estate_services,
    _has_any,
    enrich_report_with_snowflake_estate,
)
from .snowflake_discovery.identity import (  # noqa: F401 - facade re-export
    _live_role_grants,
    _LiveRoleGraph,
    _merge_live_rows,
    _role_grants_failure,
    merge_live_identity_into_object_graph,
)
from .snowflake_discovery.security import (  # noqa: F401 - facade re-export
    _add_external_stage,
    _add_login_summary,
    _add_network_policy,
    _add_outbound_share,
    _add_sensitive_object,
    _auth_posture_findings,
    _collect_auth_posture,
    _collect_exfil_surfaces,
    _collect_login_signals,
    _exfil_findings,
    _login_findings,
    _set_account_network_policy,
    discover_auth_posture,
    discover_data_exfil,
    discover_login_anomalies,
)
from .snowflake_estate_inventory import (
    _parse_external_location,
    discover_snowflake_external_data,
    discover_snowflake_integrations,
    discover_snowflake_pipeline,
    discover_snowflake_services,
)
from .snowflake_governance_findings import (
    _derive_findings,
    _find_agent_usage_anomalies,
    _find_elevated_privilege_risks,
    _find_sensitive_data_access,
    _find_write_access_risks,
)
from .snowflake_governance_mining import (
    _classify_agent_query,
    _mine_access_history,
    _mine_cortex_agent_usage,
    _mine_grants_to_roles,
    _mine_observability_events,
    _mine_query_history_365,
    _mine_tag_references,
    discover_activity,
)
from .snowflake_notebooks import (
    _discover_snowflake_notebooks,
)
from .snowflake_object_graph import (
    _LIVE_MAX_ROLES as _LIVE_MAX_ROLES,
)
from .snowflake_object_graph import (
    _discover_sf_grants,
    _grant_object_fqn,
    discover_identity_live,
    discover_object_dependencies,
)
from .snowflake_organization import (
    discover_organization,
)

logger = logging.getLogger(__name__)
__all__ = ["_MAX_ORG_ACCOUNTS", "_classify_agent_query", "_coerce_int_or_none", "_derive_findings",
    "_describe_mcp_server_tools", "_discover_cortex_agents", "_discover_cortex_services", "_discover_custom_tools",
    "_discover_from_query_history", "_discover_mcp_servers", "_discover_sf_grants", "_discover_snowflake_notebooks",
    "_discover_snowpark_packages", "_discover_streamlit_apps", "_find_agent_usage_anomalies",
    "_find_elevated_privilege_risks", "_find_sensitive_data_access", "_find_write_access_risks", "_grant_object_fqn",
    "_mine_access_history", "_mine_cortex_agent_usage", "_mine_grants_to_roles", "_mine_observability_events",
    "_mine_query_history_365", "_mine_tag_references", "_parse_create_statement_name", "_parse_external_location",
    "_parse_json_field", "_parse_json_object", "_quote_sf_identifier", "_record_snowflake_inventory_failure", "_sf_truthy",
    "_validate_sf_identifier", "discover_activity", "discover_identity_live", "discover_object_dependencies",
    "discover_organization", "discover_snowflake_external_data", "discover_snowflake_integrations",
    "discover_snowflake_pipeline", "discover_snowflake_services", "logger", "_borrowed_connection",
    "_snowflake_cloud_origin"]  # fmt: skip

# Opt-in env flag. Default OFF — estate-wide enumeration must be explicitly
# requested by an operator. Symmetric with the other providers'
# AGENT_BOM_<PROVIDER>_INVENTORY gates (AWS / AZURE / GCP), so an ordinary scan
# can fold the Snowflake estate into the graph without the ``--snowflake`` CLI
# flag.
INVENTORY_ENV_FLAG = "AGENT_BOM_SNOWFLAKE_INVENTORY"

# Opt-in env flag for the Organization → Accounts roll-up. Default OFF and
# separate from the per-account inventory gate because enumerating the
# organization requires the ORGADMIN role (``SHOW ORGANIZATION ACCOUNTS``),
# which the read-only ``ABOM_READONLY`` role typically lacks. Symmetric with the
# GCP/AWS organization gates: a single account graphs unchanged when this is off.
ORG_ENV_FLAG = "AGENT_BOM_SNOWFLAKE_ORG"

_TRUTHY = {"1", "true", "yes", "on"}

# Read-only privileges this discoverer exercises, surfaced on the discovery
# envelope so ``permissions_used`` stays honest (the producer owns the catalog).
_SF_ORG_PERMISSIONS: tuple[str, ...] = (
    "ORGADMIN.ORGANIZATION_ACCOUNTS:SELECT",
    "SNOWFLAKE.ORGANIZATION_USAGE.ACCOUNTS:SELECT",
)

# Cap accounts walked so a very large organization can't run unbounded.
_MAX_ORG_ACCOUNTS = int(os.environ.get("AGENT_BOM_SNOWFLAKE_MAX_ACCOUNTS", "500") or "500")


def _org_discovery_envelope(org_name: str) -> dict[str, Any]:
    """Discovery envelope for an enumerated organization; the façade owns the permission catalog."""
    return DiscoveryEnvelope(
        scan_mode=ScanMode.SAAS_READ_ONLY,
        discovery_scope=(f"snowflake:organization/{org_name}",),
        permissions_used=_SF_ORG_PERMISSIONS,
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    ).to_dict()


def inventory_enabled() -> bool:
    """Return whether estate-wide Snowflake inventory enumeration is opted in.

    Default OFF. Operators enable it by setting ``AGENT_BOM_SNOWFLAKE_INVENTORY``
    to a truthy value (``1`` / ``true`` / ``yes`` / ``on``). Read-only with no
    side effects — mirrors the AWS / Azure / GCP inventory gates.
    """
    return os.environ.get(INVENTORY_ENV_FLAG, "").strip().lower() in _TRUTHY


def org_enabled() -> bool:
    """Return whether the Snowflake Organization roll-up is opted in.

    Default OFF. Operators enable it by setting ``AGENT_BOM_SNOWFLAKE_ORG`` to a
    truthy value. Read-only with no side effects — mirrors the GCP/AWS org gates.
    """
    return os.environ.get(ORG_ENV_FLAG, "").strip().lower() in _TRUTHY


def _apply_key_pair(conn_kwargs: dict[str, Any]) -> bool:
    """Load the RSA key-pair (``SNOWFLAKE_PRIVATE_KEY_PATH``) into *conn_kwargs*.

    Returns ``True`` when a key path was configured. Shared by the explicit
    ``snowflake_jwt`` authenticator path and the implicit key-pair fallback so a
    private key is loaded in both — never just the authenticator name alone.
    """
    key_path = os.environ.get("SNOWFLAKE_PRIVATE_KEY_PATH", "")
    if not key_path:
        return False
    conn_kwargs["private_key_file"] = key_path
    passphrase = os.environ.get("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "")
    if passphrase:
        conn_kwargs["private_key_file_pwd"] = passphrase
    return True


def _resolve_snowflake_auth(
    conn_kwargs: dict[str, Any],
    authenticator: str | None,
) -> None:
    """Resolve Snowflake auth into *conn_kwargs* in-place.

    Priority: explicit authenticator → SNOWFLAKE_AUTHENTICATOR env →
    key-pair (SNOWFLAKE_PRIVATE_KEY_PATH) → SNOWFLAKE_PASSWORD (deprecated) →
    externalbrowser SSO (safe default).
    """
    if apply_spcs_workload_identity(conn_kwargs):
        return

    if not authenticator:
        authenticator = os.environ.get("SNOWFLAKE_AUTHENTICATOR", "")
    if authenticator:
        conn_kwargs["authenticator"] = authenticator
        # `snowflake_jwt` is key-pair auth — it still needs the private key
        # loaded. Without this, setting SNOWFLAKE_AUTHENTICATOR=snowflake_jwt
        # (the documented key-pair option) sent the authenticator with no key
        # and the connector failed with "Expected bytes ... got NoneType".
        if authenticator.lower() == "snowflake_jwt":
            _apply_key_pair(conn_kwargs)
        return

    # Key-pair auth (recommended for CI/CD)
    if _apply_key_pair(conn_kwargs):
        return

    # Password auth — deprecated, emit warning
    password = os.environ.get("SNOWFLAKE_PASSWORD", "")
    if password:
        warnings.warn(
            "SNOWFLAKE_PASSWORD is deprecated and will be removed in a future release. "
            "Migrate to SSO (SNOWFLAKE_AUTHENTICATOR=externalbrowser) or key-pair "
            "(SNOWFLAKE_PRIVATE_KEY_PATH). See https://github.com/koda-ai-studio/agent-bom#auth",
            DeprecationWarning,
            stacklevel=3,
        )
        conn_kwargs["password"] = password
        return

    # Safe default — SSO via browser
    conn_kwargs["authenticator"] = "externalbrowser"


def _get_connection(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> Any:
    """Open a Snowflake connection using the standard auth resolution contract."""
    borrowed = _active_borrowed_connection()
    if borrowed is not None:
        return borrowed
    try:
        import snowflake.connector
    except ImportError as exc:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake access. Install with: pip install 'agent-bom[snowflake]'"
        ) from exc

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    resolved_user = _env_or_value(user, "SNOWFLAKE_USER")
    if not resolved_account:
        raise CloudDiscoveryError("SNOWFLAKE_ACCOUNT not set.")

    conn_kwargs = _base_connect_kwargs(resolved_account, resolved_user, authenticator, database, schema)
    _resolve_snowflake_auth(conn_kwargs, authenticator)
    return snowflake.connector.connect(**conn_kwargs)


def discover(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
    conn: Any = None,
) -> tuple[list[Agent], list[str]]:
    """Discover Cortex agents, MCP servers, and Snowpark packages from Snowflake.

    Args:
        conn: Optional already-open Snowflake connection (e.g. brokered from a
            stored read-only connection). When supplied it is used directly
            instead of building one from env/args, and it is **not** closed here
            — the caller owns its lifecycle. When ``None`` (the default) a
            connection is built from env/args and closed before returning.

    Returns:
        (agents, warnings) — discovered agents and non-fatal warnings.

    Raises:
        CloudDiscoveryError: if ``snowflake-connector-python`` is not installed.
    """
    try:
        import snowflake.connector  # noqa: F811
        from snowflake.connector.errors import DatabaseError  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake discovery. Install with: pip install 'agent-bom[snowflake]'"
        )

    agents: list[Agent] = []
    warnings: list[str] = []

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    resolved_user = _env_or_value(user, "SNOWFLAKE_USER")

    # An injected connection (the broker path) does not require SNOWFLAKE_ACCOUNT
    # in env; fall back to a placeholder scope label only for graph/envelope use.
    owns_conn = conn is None
    if owns_conn and not resolved_account:
        warnings.append("SNOWFLAKE_ACCOUNT not set. Provide --snowflake-account or set the SNOWFLAKE_ACCOUNT env var.")
        return agents, warnings
    if not resolved_account:
        resolved_account = "connection"

    if conn is None:
        conn_kwargs = _base_connect_kwargs(resolved_account, resolved_user, authenticator, database, schema)

        _resolve_snowflake_auth(conn_kwargs, authenticator)

        try:
            conn = snowflake.connector.connect(**conn_kwargs)
        except (DatabaseError, Exception) as exc:
            warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
            return agents, warnings

    try:
        _discover_ai_surfaces(conn, resolved_account, database, schema, agents, warnings)
    finally:
        # Only close a connection we opened; an injected (brokered) connection is
        # the caller's to close.
        if owns_conn:
            conn.close()

    _attach_discover_envelope(agents, resolved_account, database, schema)
    return agents, warnings


def _attach_discover_envelope(agents: list[Agent], account: str, database: str | None, schema: str | None) -> None:
    """Per-run discovery envelope (#2083 PR B).

    Snowflake reads through the SQL surface using the user's role. We expose the
    role as a scope qualifier so operators can see which Snowflake role this run used.
    """
    scope: list[str] = []
    if account:
        scope.append(f"snowflake:account/{account}")
    if database:
        scope.append(f"snowflake:database/{database}")
    if schema:
        scope.append(f"snowflake:schema/{schema}")
    attach_envelope_to_agents(
        agents,
        scan_mode=ScanMode.SAAS_READ_ONLY,
        discovery_scope=tuple(scope),
        permissions_used=(
            "INFORMATION_SCHEMA.AGENTS:SELECT",
            "INFORMATION_SCHEMA.CORTEX_SEARCH_SERVICES:SELECT",
            "INFORMATION_SCHEMA.PACKAGES:SELECT",
            "INFORMATION_SCHEMA.STAGES:SELECT",
            "INFORMATION_SCHEMA.STREAMLITS:SELECT",
            "INFORMATION_SCHEMA.NOTEBOOKS:SELECT",
        ),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )


# ---------------------------------------------------------------------------
# Governance Discovery — ACCESS_HISTORY, GRANTS, TAG_REFERENCES, Agent Usage
# ---------------------------------------------------------------------------


def discover_governance(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
    days: int = 30,
) -> GovernanceReport:
    """Discover governance posture from Snowflake ACCOUNT_USAGE views.

    Mines ACCESS_HISTORY, GRANTS_TO_ROLES, TAG_REFERENCES, and
    CORTEX_AGENT_USAGE_HISTORY to produce a governance report with
    risk findings.

    Requires Enterprise edition or higher for ACCESS_HISTORY.
    CORTEX_AGENT_USAGE_HISTORY requires Cortex Agents (GA Feb 2026).

    Args:
        account: Snowflake account identifier.
        user: Snowflake username.
        authenticator: Auth method (externalbrowser, snowflake_jwt, etc.).
        database: Default database context.
        schema: Default schema context.
        days: Look-back window for ACCESS_HISTORY and agent usage.

    Returns:
        GovernanceReport with findings, access records, grants, and usage data.

    Raises:
        CloudDiscoveryError: if snowflake-connector-python is not installed.
    """
    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    resolved_user = _env_or_value(user, "SNOWFLAKE_USER")
    report = GovernanceReport(account=resolved_account)
    days = _coerce_snowflake_days(days)

    if not resolved_account:
        report.warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return report

    try:
        import snowflake.connector
        from snowflake.connector.errors import DatabaseError  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake governance. Install with: pip install 'agent-bom[snowflake]'"
        )

    conn_kwargs = _base_connect_kwargs(resolved_account, resolved_user, authenticator, database, schema)

    _resolve_snowflake_auth(conn_kwargs, authenticator)

    borrowed = _active_borrowed_connection()
    if borrowed is not None:
        conn = borrowed
    else:
        try:
            conn = snowflake.connector.connect(**conn_kwargs)
        except (DatabaseError, Exception) as exc:
            report.warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
            return report

    try:
        _mine_governance_report(conn, days, report)
    finally:
        conn.close()

    return report


def _live_show_roles(conn: Any, warnings_list: list[str]) -> list[dict[str, Any]]:
    """``SHOW ROLES`` → current role list (name / owner / comment).

    Bounded by ``AGENT_BOM_SNOWFLAKE_MAX_ROLES`` (default ``_LIVE_MAX_ROLES``) so
    large accounts can raise it; hitting the bound emits a warning rather than a
    silent truncation.
    """
    try:
        cap = max(1, int(os.environ.get("AGENT_BOM_SNOWFLAKE_MAX_ROLES", "") or _LIVE_MAX_ROLES))
    except ValueError:
        cap = _LIVE_MAX_ROLES
    roles: list[dict[str, Any]] = []
    cursor = conn.cursor()
    try:
        cursor.execute("SHOW ROLES")
        keys = [d[0].lower() for d in cursor.description] if cursor.description else []
        for row in cursor.fetchall():
            r = dict(zip(keys, row))
            name = str(r.get("name", "") or "")
            if not name:
                continue
            roles.append({"name": name, "owner": str(r.get("owner", "") or ""), "comment": str(r.get("comment", "") or "")})
            if len(roles) >= cap:
                warnings_list.append(f"SHOW ROLES truncated at {cap} roles; raise AGENT_BOM_SNOWFLAKE_MAX_ROLES to see more.")
                break
    except Exception as exc:  # noqa: BLE001
        warnings_list.append(f"Could not list roles (SHOW ROLES): {sanitize_error(exc)}")
    finally:
        cursor.close()
    return roles
