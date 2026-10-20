"""Advisory lookup and version-existence helpers for the MCP/REST ``check`` tool."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from agent_bom.http_client import request_with_retry
from agent_bom.scanners.local_data_freshness import CheckDataEvidence, check_data_evidence
from agent_bom.scanners.package_check_result import has_lookup_coverage_gap


def incomplete_lookup_reason(package: str, coverage_warnings: list[dict], evidence: CheckDataEvidence) -> str | None:
    """Why a zero-finding lookup is not a clean verdict, or None when it is.

    An advisory coverage gap, or untrusted local data that OSV did not back
    (unless ``--allow-stale-db`` / ``AGENT_BOM_ALLOW_STALE_DB`` accepts it).
    """
    if has_lookup_coverage_gap(coverage_warnings):
        return f"Advisory coverage was incomplete for {package}; a clean verdict cannot be trusted"
    if evidence.blocks_clean():
        return evidence.stale_message()
    return None


async def scan_checked_package(pkg: Any, *, offline: bool, warnings: list[str]) -> tuple[list[dict], CheckDataEvidence]:
    """Scan one package and return its coverage warnings plus data-freshness evidence.

    Raises ``IncompleteScanError`` unchanged so the caller owns the verdict.
    """
    from agent_bom.scanners import ScanOptions, consume_coverage_warnings, consume_scan_warnings, reset_scan_warnings, scan_packages

    reset_scan_warnings()
    await scan_packages([pkg], options=ScanOptions(offline=offline))
    warnings.extend(consume_scan_warnings())
    coverage_warnings = consume_coverage_warnings()
    warnings.extend(str(warning.get("detail") or "Package advisory coverage is incomplete") for warning in coverage_warnings)
    return coverage_warnings, check_data_evidence(offline=offline, coverage_warnings=coverage_warnings)


async def version_published(name: str, version: str, ecosystem: str, client) -> bool:
    """Return True if an exact package version is published (404 → not published).

    Fails open (returns True) on network/other errors and for ecosystems without
    a cheap per-version endpoint, so a transient failure never turns a genuine
    clean result into a false "unknown".
    """

    # Package coordinates are path data, never URL structure. Encoding every
    # reserved character also makes scoped npm names (``@scope/name``) a
    # single registry path segment instead of allowing caller-controlled path
    # separators. The shared request wrapper validates the fixed registry
    # origin before opening a socket.
    encoded_name = quote(name, safe="")
    encoded_version = quote(version, safe="")

    try:
        if ecosystem == "pypi":
            url = f"https://pypi.org/pypi/{encoded_name}/{encoded_version}/json"
        elif ecosystem == "npm":
            url = f"https://registry.npmjs.org/{encoded_name}/{encoded_version}"
        else:
            return True
        resp = await request_with_retry(client, "GET", url, max_retries=0)
        if resp is None:
            return True
        return resp.status_code == 200
    except Exception:  # noqa: BLE001 — best-effort existence check; fail open
        return True
