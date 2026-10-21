"""CIS GCP 6.x: Cloud SQL instance configuration."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.normalization import sanitize_discovery_warning

from ._base import _SQL_SECTION, _gcp_cloud_sql_instances


def _evaluate_instances(
    project_id: str,
    result: CISCheckResult,
    *,
    fails: Callable[[dict[str, Any]], bool],
    success: Callable[[int], str],
    failure: Callable[[list[str], int], str],
    error_context: str,
    missing_sdk: str = "google-api-python-client not installed.",
) -> CISCheckResult:
    """Keep collection errors distinct from failed configuration predicates."""
    try:
        instances = _gcp_cloud_sql_instances(project_id)
        failing = [instance.get("name", "unknown") for instance in instances if fails(instance)]
        result.status = CheckStatus.FAIL if failing else CheckStatus.PASS
        if failing:
            result.evidence = failure(failing, len(instances))
            result.resource_ids = failing
        else:
            result.evidence = success(len(instances))
    except ImportError:
        result.status = CheckStatus.ERROR
        result.evidence = missing_sdk
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check {error_context}: {sanitize_discovery_warning(exc)}"
    return result


def _postgres_flag_fails(instance: dict[str, Any], name: str, allowed: set[str], *, case_sensitive: bool = False) -> bool:
    if not instance.get("databaseVersion", "").upper().startswith("POSTGRES"):
        return False
    flags = instance.get("settings", {}).get("databaseFlags", [])
    value = next(
        (flag.get("value", "") if case_sensitive else flag.get("value", "").lower() for flag in flags if flag.get("name") == name),
        None,
    )
    return all(value != expected for expected in allowed)


def _check_6_1(project_id: str) -> CISCheckResult:
    """CIS 6.1 — Ensure Cloud SQL database instances require all incoming connections to use SSL."""
    result = CISCheckResult(
        check_id="6.1",
        title="Cloud SQL requires SSL for all connections",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable 'Require SSL' (requireSsl) on all Cloud SQL instances to encrypt connections in transit.",
        cis_section=_SQL_SECTION,
    )
    return _evaluate_instances(
        project_id,
        result,
        fails=lambda inst: not inst.get("settings", {}).get("ipConfiguration", {}).get("requireSsl", False),
        success=lambda total: f"All {total} Cloud SQL instance(s) require SSL connections.",
        failure=lambda failing, total: f"Cloud SQL instances not requiring SSL ({len(failing)}/{total}): {', '.join(failing[:10])}",
        error_context="Cloud SQL SSL configuration",
        missing_sdk="google-api-python-client not installed. Install with: pip install google-api-python-client",
    )


def _check_6_2(project_id: str) -> CISCheckResult:
    """CIS 6.2 — Ensure Cloud SQL database instances do not have public IPs."""
    result = CISCheckResult(
        check_id="6.2",
        title="Cloud SQL instances lack public IPs",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove public IP addresses from Cloud SQL instances and use private IP or Cloud SQL Proxy instead.",
        cis_section=_SQL_SECTION,
    )
    return _evaluate_instances(
        project_id,
        result,
        fails=lambda inst: any(ip.get("type") == "PRIMARY" for ip in inst.get("ipAddresses", [])),
        success=lambda total: f"No Cloud SQL instances have public IP addresses across {total} instance(s).",
        failure=lambda failing, total: f"Cloud SQL instances with public IPs ({len(failing)}/{total}): {', '.join(failing[:10])}",
        error_context="Cloud SQL public IPs",
        missing_sdk="google-api-python-client not installed. Install with: pip install google-api-python-client",
    )


def _check_6_3(project_id: str) -> CISCheckResult:
    """CIS 6.3 — Ensure Cloud SQL database instances have automated backups enabled."""
    result = CISCheckResult(
        check_id="6.3",
        title="Cloud SQL automated backups enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable automated backups on all Cloud SQL instances.",
        cis_section=_SQL_SECTION,
    )
    return _evaluate_instances(
        project_id,
        result,
        fails=lambda inst: not inst.get("settings", {}).get("backupConfiguration", {}).get("enabled", False),
        success=lambda total: f"All {total} Cloud SQL instance(s) have automated backups enabled.",
        failure=lambda failing, total: f"Cloud SQL instances without automated backups ({len(failing)}/{total}): {', '.join(failing[:10])}",
        error_context="Cloud SQL backup configuration",
        missing_sdk="google-api-python-client not installed. Install with: pip install google-api-python-client",
    )


def _check_6_4(project_id: str) -> CISCheckResult:
    """CIS 6.4 — Ensure Cloud SQL PostgreSQL instances have log_error_verbosity set to DEFAULT or stricter."""
    result = CISCheckResult(
        check_id="6.4",
        title="Cloud SQL PostgreSQL log_error_verbosity DEFAULT or stricter",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the log_error_verbosity database flag to DEFAULT or TERSE on PostgreSQL instances.",
        cis_section=_SQL_SECTION,
    )
    return _evaluate_instances(
        project_id,
        result,
        fails=lambda inst: _postgres_flag_fails(inst, "log_error_verbosity", {"default", "terse"}),
        success=lambda total: "All PostgreSQL instances have log_error_verbosity set to DEFAULT or stricter.",
        failure=lambda failing, total: f"PostgreSQL instances without proper log_error_verbosity: {', '.join(failing[:10])}",
        error_context="PostgreSQL log_error_verbosity",
    )


def _check_6_5(project_id: str) -> CISCheckResult:
    """CIS 6.5 — Ensure Cloud SQL PostgreSQL instances have log_connections enabled."""
    result = CISCheckResult(
        check_id="6.5",
        title="Cloud SQL PostgreSQL log_connections flag on",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the log_connections database flag to 'on' on all PostgreSQL instances.",
        cis_section=_SQL_SECTION,
    )
    return _evaluate_instances(
        project_id,
        result,
        fails=lambda inst: _postgres_flag_fails(inst, "log_connections", {"on"}),
        success=lambda total: "All PostgreSQL instances have log_connections enabled.",
        failure=lambda failing, total: f"PostgreSQL instances without log_connections enabled: {', '.join(failing[:10])}",
        error_context="PostgreSQL log_connections",
    )


def _check_6_6(project_id: str) -> CISCheckResult:
    """CIS 6.6 — Ensure Cloud SQL PostgreSQL instances have log_disconnections enabled."""
    result = CISCheckResult(
        check_id="6.6",
        title="Cloud SQL PostgreSQL log_disconnections flag on",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the log_disconnections database flag to 'on' on all PostgreSQL instances.",
        cis_section=_SQL_SECTION,
    )
    return _evaluate_instances(
        project_id,
        result,
        fails=lambda inst: _postgres_flag_fails(inst, "log_disconnections", {"on"}),
        success=lambda total: "All PostgreSQL instances have log_disconnections enabled.",
        failure=lambda failing, total: f"PostgreSQL instances without log_disconnections enabled: {', '.join(failing[:10])}",
        error_context="PostgreSQL log_disconnections",
    )


def _check_6_7(project_id: str) -> CISCheckResult:
    """CIS 6.7 — Ensure Cloud SQL PostgreSQL instances have log_min_duration_statement set to -1."""
    result = CISCheckResult(
        check_id="6.7",
        title="Cloud SQL PostgreSQL log_min_duration_statement set to -1",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the log_min_duration_statement database flag to '-1' to disable logging of statement durations (prevents sensitive data leakage).",  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_SQL_SECTION,
    )
    return _evaluate_instances(
        project_id,
        result,
        fails=lambda inst: _postgres_flag_fails(inst, "log_min_duration_statement", {"-1"}, case_sensitive=True),
        success=lambda total: "All PostgreSQL instances have log_min_duration_statement set to -1.",
        failure=lambda failing, total: f"PostgreSQL instances without log_min_duration_statement=-1: {', '.join(failing[:10])}",
        error_context="PostgreSQL log_min_duration_statement",
    )
