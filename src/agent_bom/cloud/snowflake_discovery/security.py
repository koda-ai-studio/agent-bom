"""Snowflake data-exfiltration, login-anomaly and authentication-posture discovery."""

from __future__ import annotations

import functools
import importlib
import re
from typing import Any

from agent_bom.security import sanitize_error

from ..base import CloudDiscoveryError
from ..snowflake_common import _coerce_snowflake_days as _coerce_snowflake_days
from ..snowflake_common import _env_or_value as _env_or_value
from ..snowflake_common import _sf_truthy as _sf_truthy
from ._base import _for_each_row, _warn_with

_FACADE = "agent_bom.cloud.snowflake"


def _seams() -> Any:
    """Resolve patchable collaborators through the public facade at call time."""
    return importlib.import_module(_FACADE)


_EXTERNAL_STAGE_SCHEMES = {"s3": "aws", "s3gov": "aws", "azure": "azure", "gcs": "gcp"}


def discover_data_exfil(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> dict[str, Any]:
    """Discover Snowflake data-exfiltration surfaces (read-only).

    Three egress surfaces, summarized (no row data leaves Snowflake):

    * **Outbound shares** — data shared to consumer accounts (`SHOW SHARES`,
      identified by ``target_accounts``).
    * **External stages** — off-account storage reachable by ``COPY INTO``
      (`SHOW STAGES IN ACCOUNT`, external ``s3://`` / ``azure://`` / ``gcs://``
      URLs). The destination bucket id matches what an AWS/Azure/GCP scan emits,
      so the graph **stitches Snowflake to the actual cloud storage node**.
    * **Sensitive objects** — tables/columns tagged PII/PHI/etc.
      (`ACCOUNT_USAGE.TAG_REFERENCES`) and whether a masking/row-access policy
      protects them (`POLICY_REFERENCES`).

    Returns a payload with ``status``, ``outbound_shares``, ``external_stages``,
    ``sensitive_objects``, derived ``findings``, and ``warnings``.

    Raises:
        CloudDiscoveryError: if snowflake-connector-python is not installed.
    """
    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake exfil discovery. Install with: pip install 'agent-bom[snowflake]'"
        )

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    result: dict[str, Any] = {
        "status": "disabled",
        "account": resolved_account,
        "outbound_shares": [],
        "external_stages": [],
        "sensitive_objects": [],
        "findings": [],
        "warnings": [],
    }
    warnings: list[str] = result["warnings"]
    if not resolved_account:
        result["status"] = "no_account"
        warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return result

    try:
        conn = _seams()._get_connection(account, user, authenticator, database, schema)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
        return result

    try:
        _collect_exfil_surfaces(conn, result)
        result["findings"].extend(_exfil_findings(result))
        result["status"] = "ok"
    finally:
        conn.close()
    return result


def _add_outbound_share(result: dict[str, Any], r: dict[str, Any]) -> None:
    if str(r.get("kind", "")).upper() != "OUTBOUND":
        return
    consumers = [c.strip() for c in re.split(r"[,\s]+", str(r.get("to", "") or "")) if c.strip()]
    result["outbound_shares"].append(
        {
            "share_name": str(r.get("name", "")),
            "database_name": str(r.get("database_name", "")),
            "consumers": consumers,
            "is_marketplace": bool(str(r.get("listing_global_name", "") or "")),
        }
    )


def _add_external_stage(result: dict[str, Any], r: dict[str, Any]) -> None:
    url = str(r.get("url", "") or "")
    if "://" not in url:
        return
    scheme = url.split("://", 1)[0].lower()
    cloud = _EXTERNAL_STAGE_SCHEMES.get(scheme, "")
    if not cloud:
        return
    bucket = url.split("://", 1)[1].split("/", 1)[0]
    result["external_stages"].append(
        {
            "stage_name": str(r.get("name", "")),
            "database_name": str(r.get("database_name", "")),
            "schema_name": str(r.get("schema_name", "")),
            "url": url,
            "cloud_provider": cloud,
            "bucket": bucket,
        }
    )


def _add_sensitive_object(result: dict[str, Any], protected: set[str], r: dict[str, Any]) -> None:
    fqn = ".".join(str(r.get(k, "")) for k in ("object_database", "object_schema", "object_name"))
    result["sensitive_objects"].append(
        {
            "fqn": fqn,
            "tagged_columns": int(r.get("cols", 0) or 0),
            "tag_count": int(r.get("tags", 0) or 0),
            "is_protected": fqn.upper() in protected,
            "sensitivity": "sensitive",
        }
    )


def _collect_exfil_surfaces(conn: Any, result: dict[str, Any]) -> None:
    """Outbound shares, external stages, then sensitive objects + their masking/row-access coverage."""
    warnings: list[str] = result["warnings"]
    _for_each_row(
        conn, "SHOW SHARES", functools.partial(_add_outbound_share, result), _warn_with(warnings, "Could not list outbound shares")
    )
    _for_each_row(
        conn,
        "SHOW STAGES IN ACCOUNT",
        functools.partial(_add_external_stage, result),
        _warn_with(warnings, "Could not list external stages"),
    )

    # Sensitive objects (tagged) + masking/row-access coverage.
    protected: set[str] = set()
    _for_each_row(
        conn,
        "SELECT ref_database_name, ref_schema_name, ref_entity_name "
        "FROM SNOWFLAKE.ACCOUNT_USAGE.POLICY_REFERENCES "
        "WHERE policy_kind IN ('MASKING_POLICY', 'ROW_ACCESS_POLICY') LIMIT 5000",
        lambda r: protected.add(".".join(str(r.get(k, "")) for k in ("ref_database_name", "ref_schema_name", "ref_entity_name")).upper()),
        _warn_with(warnings, "Could not query POLICY_REFERENCES"),
    )
    _for_each_row(
        conn,
        "SELECT object_database, object_schema, object_name, "
        "       COUNT(DISTINCT tag_name) AS tags, COUNT(DISTINCT column_name) AS cols "
        "FROM SNOWFLAKE.ACCOUNT_USAGE.TAG_REFERENCES "
        "WHERE tag_name ILIKE ANY ('%PII%', '%PHI%', '%SENSITIVE%', '%CONFIDENTIAL%', "
        "      '%FINANCIAL%', '%CLASSIFICATION%', '%PRIVACY%', '%SEMANTIC_CATEGORY%') "
        "GROUP BY 1, 2, 3 LIMIT 5000",
        functools.partial(_add_sensitive_object, result, protected),
        _warn_with(warnings, "Could not query TAG_REFERENCES"),
    )


def _exfil_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for s in result["outbound_shares"]:
        findings.append(
            {
                "severity": "high" if s["is_marketplace"] else "medium",
                "title": "Outbound data share",
                "detail": f"Share {s['share_name']} exposes data to {len(s['consumers'])} consumer account(s)"
                + (" via a public Marketplace listing" if s["is_marketplace"] else "")
                + ".",
            }
        )
    for st in result["external_stages"]:
        findings.append(
            {
                "severity": "medium",
                "title": "External stage (exfil destination)",
                "detail": f"Stage {st['stage_name']} writes to {st['cloud_provider']} bucket '{st['bucket']}'.",
            }
        )
    unprotected = [s["fqn"] for s in result["sensitive_objects"] if not s["is_protected"]]
    if unprotected:
        findings.append(
            {
                "severity": "high",
                "title": "Unprotected sensitive data",
                "detail": f"{len(unprotected)} sensitivity-tagged object(s) have no masking/row-access policy.",
            }
        )
    return findings


def discover_login_anomalies(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
    days: int = 7,
    rapid_switch_minutes: int = 10,
    max_distinct_ips: int = 20,
    failed_burst_threshold: int = 5,
) -> dict[str, Any]:
    """Detect Snowflake login anomalies from LOGIN_HISTORY (read-only).

    Three identity-threat signals, all summarized server-side (no raw IPs/PII
    leave Snowflake):

    * **Impossible travel** — the same user logging in from a *different* client
      IP within ``rapid_switch_minutes`` of a prior successful login. Switching
      source IPs faster than one can physically travel is the classic signal
      (geo distance would refine it, but the rapid-IP-switch heuristic needs no
      external GeoIP data).
    * **High distinct-IP count** — a user authenticating from more than
      ``max_distinct_ips`` distinct addresses in the window.
    * **Failed-login bursts** — a user with at least ``failed_burst_threshold``
      failed logins (brute-force / credential-stuffing pressure).

    Returns a payload with ``status``, ``per_user`` summaries, ``impossible_travel``,
    ``failed_bursts``, derived ``findings``, and ``warnings``.

    Raises:
        CloudDiscoveryError: if snowflake-connector-python is not installed.
    """
    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake login anomaly detection. Install with: pip install 'agent-bom[snowflake]'"
        )

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    days = _coerce_snowflake_days(days, max_days=365)
    result: dict[str, Any] = {
        "status": "disabled",
        "account": resolved_account,
        "window_days": days,
        "per_user": [],
        "impossible_travel": [],
        "failed_bursts": [],
        "findings": [],
        "warnings": [],
    }
    warnings: list[str] = result["warnings"]
    if not resolved_account:
        result["status"] = "no_account"
        warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return result

    try:
        conn = _seams()._get_connection(account, user, authenticator, database, schema)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
        return result

    try:
        _collect_login_signals(conn, result, days, rapid_switch_minutes, failed_burst_threshold)
        result["findings"].extend(_login_findings(result, days, rapid_switch_minutes, max_distinct_ips))
        result["status"] = "ok"
    finally:
        conn.close()
    return result


def _add_login_summary(result: dict[str, Any], failed_burst_threshold: int, r: dict[str, Any]) -> None:
    distinct_ips = int(r.get("distinct_ips", 0) or 0)
    failed = int(r.get("failed", 0) or 0)
    entry = {
        "user": str(r.get("user_name", "")),
        "distinct_ips": distinct_ips,
        "logins": int(r.get("logins", 0) or 0),
        "failed": failed,
    }
    result["per_user"].append(entry)
    if failed >= failed_burst_threshold:
        result["failed_bursts"].append({"user": entry["user"], "failed": failed})


def _collect_login_signals(conn: Any, result: dict[str, Any], days: int, rapid_switch_minutes: int, failed_burst_threshold: int) -> None:
    """Per-user LOGIN_HISTORY summary, then the impossible-travel signal."""
    warnings: list[str] = result["warnings"]
    _for_each_row(
        conn,
        "SELECT user_name, COUNT(DISTINCT client_ip) AS distinct_ips, COUNT(*) AS logins, "
        "       SUM(IFF(is_success = 'NO', 1, 0)) AS failed "
        "FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY "
        f"WHERE event_timestamp >= DATEADD(day, -{days}, CURRENT_TIMESTAMP()) "  # nosec B608 — int day window
        "GROUP BY user_name ORDER BY distinct_ips DESC LIMIT 1000",
        functools.partial(_add_login_summary, result, failed_burst_threshold),
        _warn_with(warnings, "Could not summarize LOGIN_HISTORY"),
    )

    # Impossible travel: consecutive successful logins from a different IP
    # within rapid_switch_minutes (computed server-side via LAG).
    _for_each_row(
        conn,
        "WITH ordered AS ( "
        "  SELECT user_name, client_ip, event_timestamp, "
        "         LAG(client_ip) OVER (PARTITION BY user_name ORDER BY event_timestamp) AS prev_ip, "
        "         LAG(event_timestamp) OVER (PARTITION BY user_name ORDER BY event_timestamp) AS prev_ts "
        "  FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY "
        f"  WHERE is_success = 'YES' AND event_timestamp >= DATEADD(day, -{days}, CURRENT_TIMESTAMP()) "  # nosec B608
        ") "
        "SELECT user_name, COUNT(*) AS rapid_switches "
        "FROM ordered "
        "WHERE prev_ip IS NOT NULL AND client_ip != prev_ip "
        f"  AND TIMESTAMPDIFF(minute, prev_ts, event_timestamp) <= {rapid_switch_minutes} "  # nosec B608
        "GROUP BY user_name HAVING COUNT(*) > 0 ORDER BY rapid_switches DESC LIMIT 1000",
        lambda r: result["impossible_travel"].append(
            {"user": str(r.get("user_name", "")), "rapid_switches": int(r.get("rapid_switches", 0) or 0)}
        ),
        _warn_with(warnings, "Could not compute impossible-travel signal"),
    )


def _login_findings(result: dict[str, Any], days: int, rapid_switch_minutes: int, max_distinct_ips: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for it in result["impossible_travel"]:
        findings.append(
            {
                "severity": "high",
                "title": "Possible impossible travel",
                "detail": f"User {it['user']} switched source IP within {rapid_switch_minutes} min "
                f"{it['rapid_switches']} time(s) — faster than physical travel.",
            }
        )
    for u in result["per_user"]:
        if u["distinct_ips"] > max_distinct_ips:
            findings.append(
                {
                    "severity": "medium",
                    "title": "High distinct source-IP count",
                    "detail": f"User {u['user']} logged in from {u['distinct_ips']} distinct IPs in {days} days.",
                }
            )
    for b in result["failed_bursts"]:
        findings.append(
            {
                "severity": "medium",
                "title": "Failed-login burst",
                "detail": f"User {b['user']} had {b['failed']} failed logins (brute-force / stuffing pressure).",
            }
        )
    return findings


def discover_auth_posture(
    account: str | None = None,
    user: str | None = None,
    authenticator: str | None = None,
    database: str | None = None,
    schema: str | None = None,
) -> dict[str, Any]:
    """Inventory Snowflake authentication posture (read-only).

    The preventive complement to :func:`discover_login_anomalies` (which is
    detective). Two surfaces:

    * **Per-user auth matrix** — for each enabled user, which credential types
      exist (password / key-pair / federated SSO), whether MFA is enrolled
      (``ext_authn_duo``), and whether a network policy is bound
      (`ACCOUNT_USAGE.USERS`).
    * **Network policies** — IP allow/block lists and whether one is applied at
      the account level (`SHOW NETWORK POLICIES` + the ``NETWORK_POLICY``
      account parameter).

    Surfaces concrete exposures: password users without MFA, human users not
    behind any network policy, and an account with no default network policy.

    Returns ``status``, ``account``, ``users``, ``network_policies``,
    ``account_network_policy``, ``findings``, ``warnings``. Never leaks
    credential material — only boolean capability flags.

    Raises:
        CloudDiscoveryError: if snowflake-connector-python is not installed.
    """
    try:
        import snowflake.connector  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake auth-posture discovery. Install with: pip install 'agent-bom[snowflake]'"
        )

    resolved_account = _env_or_value(account, "SNOWFLAKE_ACCOUNT")
    result: dict[str, Any] = {
        "status": "disabled",
        "account": resolved_account,
        "users": [],
        "network_policies": [],
        "account_network_policy": None,
        "findings": [],
        "warnings": [],
    }
    warnings: list[str] = result["warnings"]
    if not resolved_account:
        result["status"] = "no_account"
        warnings.append("SNOWFLAKE_ACCOUNT not set.")
        return result

    try:
        conn = _seams()._get_connection(account, user, authenticator, database, schema)
    except CloudDiscoveryError:
        raise
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not connect to Snowflake: {sanitize_error(exc)}")
        return result

    try:
        _collect_auth_posture(conn, result)
        result["findings"].extend(_auth_posture_findings(result))
        result["status"] = "ok"
    finally:
        conn.close()
    return result


def _set_account_network_policy(result: dict[str, Any], r: dict[str, Any]) -> None:
    val = str(r.get("value", "") or "")
    if val:
        result["account_network_policy"] = val


def _add_network_policy(result: dict[str, Any], r: dict[str, Any]) -> None:
    result["network_policies"].append(
        {
            "name": str(r.get("name", "")),
            "allowed_ip_count": int(r.get("entries_in_allowed_ip_list", 0) or 0),
            "blocked_ip_count": int(r.get("entries_in_blocked_ip_list", 0) or 0),
        }
    )


def _add_auth_user(result: dict[str, Any], r: dict[str, Any]) -> None:
    name = str(r.get("name", ""))
    if not name:
        return
    disabled = _sf_truthy(r.get("disabled"))
    has_password = _sf_truthy(r.get("has_password"))
    has_key_pair = _sf_truthy(r.get("has_rsa_public_key"))
    # MFA: ext_authn_duo (Duo) or the newer has_mfa column when present.
    has_mfa = _sf_truthy(r.get("ext_authn_duo")) or _sf_truthy(r.get("has_mfa"))
    user_type = str(r.get("type", "") or "").upper()  # PERSON / SERVICE / LEGACY_SERVICE / NULL
    auth_methods = []
    if has_password:
        auth_methods.append("password")
    if has_key_pair:
        auth_methods.append("key_pair")
    if not auth_methods:
        auth_methods.append("federated_or_none")
    result["users"].append(
        {
            "name": name,
            "disabled": disabled,
            "auth_methods": auth_methods,
            "has_mfa": has_mfa,
            "user_type": user_type or "UNKNOWN",
            "default_role": str(r.get("default_role", "") or ""),
        }
    )


def _collect_auth_posture(conn: Any, result: dict[str, Any]) -> None:
    """Account default network policy, network policies, then the per-user auth matrix."""
    warnings: list[str] = result["warnings"]
    # Account-level default network policy.
    _for_each_row(
        conn,
        "SHOW PARAMETERS LIKE 'NETWORK_POLICY' IN ACCOUNT",
        functools.partial(_set_account_network_policy, result),
        _warn_with(warnings, "Could not read account network policy"),
    )
    # Network policies (allow/block IP ranges).
    _for_each_row(
        conn,
        "SHOW NETWORK POLICIES",
        functools.partial(_add_network_policy, result),
        _warn_with(warnings, "Could not list network policies"),
    )
    # Per-user auth matrix.
    _for_each_row(
        conn,
        "SELECT name, disabled, has_password, has_rsa_public_key, ext_authn_duo, "
        "       default_role, type, has_mfa "
        "FROM SNOWFLAKE.ACCOUNT_USAGE.USERS "
        "WHERE deleted_on IS NULL LIMIT 10000",
        functools.partial(_add_auth_user, result),
        _warn_with(warnings, "Could not query USERS auth matrix"),
    )


def _auth_posture_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if result["users"] and not result["account_network_policy"]:
        findings.append(
            {
                "severity": "medium",
                "title": "No account-level network policy",
                "detail": "No default NETWORK_POLICY is set at the account level; logins are not IP-restricted by default.",
            }
        )
    # Password users without MFA (skip disabled + non-person service identities,
    # which legitimately use key-pair/OAuth and cannot enroll interactive MFA).
    weak = [
        u["name"]
        for u in result["users"]
        if not u["disabled"] and "password" in u["auth_methods"] and not u["has_mfa"] and u["user_type"] in ("PERSON", "UNKNOWN", "")
    ]
    if weak:
        findings.append(
            {
                "severity": "high",
                "title": "Password users without MFA",
                "detail": f"{len(weak)} enabled human user(s) authenticate with a password and have no MFA enrolled.",
            }
        )
    return findings
