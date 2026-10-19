"""Posture dimensions over the tenant's current open findings.

The overview headline and tiles read the open findings of every current scan
(newest successful scan per target scope, inside the default read window).
The per-dimension breakdown reads the same set: finding-based dimensions use
those open vulnerability rows, and inventory-based dimensions (credentials,
supply chain, configuration) use the agents and servers of the same scans.
Scoring is the scan-time function, so each dimension keeps its meaning.
"""

from __future__ import annotations

from typing import Any, cast

from agent_bom.evidence.posture_inputs import FRAMEWORK_TAG_FIELDS, PostureInputs, VulnerabilitySignal, score_posture_dimensions
from agent_bom.evidence.scan_run import VULNERABILITY_SCAN_SKIPPED_CODE, VULNERABILITY_SCAN_SKIPPED_MESSAGE
from agent_bom.models import Package
from agent_bom.posture import load_posture_policy

TENANT_DIMENSIONS_BASIS = "tenant_current_findings"


def _is_vulnerability_row(row: dict[str, Any]) -> bool:
    return str(row.get("finding_type") or "").upper() == "CVE" or row.get("source") == "blast_radius"


def _vulnerability_signal(row: dict[str, Any]) -> VulnerabilitySignal:
    return VulnerabilitySignal(
        vuln_id=str(row.get("vulnerability_id") or row.get("cve_id") or row.get("id") or ""),
        severity=str(row.get("severity") or "unknown").upper(),
        fixable=bool(row.get("fixed_version")),
        is_kev=bool(row.get("is_kev") or row.get("cisa_kev")),
        epss_score=float(row.get("epss_score") or 0),
        framework_mapped=any(row.get(key) for key in FRAMEWORK_TAG_FIELDS),
    )


def _package(raw: dict[str, Any]) -> Package:
    return Package(
        name=str(raw.get("name") or ""),
        version=str(raw.get("version") or ""),
        ecosystem=str(raw.get("ecosystem") or ""),
        purl=raw.get("purl"),
        homepage=raw.get("homepage"),
        repository_url=raw.get("repository_url"),
        source_repo=raw.get("source_repo"),
        scorecard_score=raw.get("scorecard_score"),
        scorecard_repo=raw.get("scorecard_repo"),
        scorecard_lookup_state=raw.get("scorecard_lookup_state"),
        scorecard_lookup_reason=raw.get("scorecard_lookup_reason"),
    )


def _vulnerability_lane_skipped(result: dict[str, Any]) -> bool:
    run = result.get("scan_run")
    issues = run.get("issues") if isinstance(run, dict) else None
    return any(
        isinstance(issue, dict)
        and (issue.get("code") == VULNERABILITY_SCAN_SKIPPED_CODE or issue.get("message") == VULNERABILITY_SCAN_SKIPPED_MESSAGE)
        for issue in issues or []
    )


def _has_vulnerability_rows(result: dict[str, Any]) -> bool:
    if result.get("blast_radius"):
        return True
    return any(isinstance(row, dict) and _is_vulnerability_row(row) for row in result.get("findings") or [])


def _fold_inventory(inputs: PostureInputs, results: list[dict[str, Any]]) -> set[str]:
    """Agents/servers of the current scans, each (agent, server) counted once."""
    seen: set[tuple[str, str]] = set()
    credential_servers: set[str] = set()
    for result in results:
        for agent in result.get("agents") or []:
            if not isinstance(agent, dict):
                continue
            for server in agent.get("mcp_servers") or []:
                if not isinstance(server, dict):
                    continue
                key = (str(agent.get("name") or ""), str(server.get("name") or ""))
                if key in seen:
                    continue
                seen.add(key)
                inputs.total_servers += 1
                inputs.verified_servers += int(bool(server.get("registry_verified")))
                inputs.servers_with_tools += int(bool(server.get("tools")))
                if server.get("has_credentials"):
                    inputs.credential_servers += 1
                    credential_servers.add(key[1])
                    inputs.credentials.update(str(name) for name in server.get("credential_env_vars") or [])
                inputs.packages.extend(_package(pkg) for pkg in server.get("packages") or [] if isinstance(pkg, dict))
    return credential_servers


def _fold_exposed_credentials(inputs: PostureInputs, rows: list[dict[str, Any]], credential_servers: set[str]) -> int:
    """Credentials an open finding exposes are exposure even if no inventory server lists them.

    A finding's ``affected_servers`` names every server running the package,
    not only the ones holding the credential, so servers are counted only for
    credentials the inventory does not already explain.
    """
    exposing = 0
    for row in rows:
        exposed = {str(name) for name in row.get("exposed_credentials") or [] if name}
        if not exposed:
            continue
        exposing += 1
        unexplained = exposed - inputs.credentials
        if not unexplained:
            continue
        inputs.credentials.update(unexplained)
        servers = [str(name) for name in row.get("affected_servers") or [] if name]
        for name in servers or ["unattributed"]:
            if name not in credential_servers:
                credential_servers.add(name)
                inputs.credential_servers += 1
    return exposing


def current_findings_dimensions(evidence_jobs: list[Any], rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Dimensions plus their basis over the current scans and their open finding rows."""
    results = [cast(dict[str, Any], job.result) for job in evidence_jobs]
    vulnerability_rows = [row for row in rows if _is_vulnerability_row(row)]
    inputs = PostureInputs(
        vulnerabilities=[_vulnerability_signal(row) for row in vulnerability_rows],
        has_mcp_context=any(bool(result.get("has_mcp_context")) for result in results),
        vulnerability_lane_skipped=bool(results) and all(_vulnerability_lane_skipped(result) for result in results),
    )
    if not inputs.vulnerabilities:
        # Vulnerability records with no analysed finding (imported SBOM
        # projections) stay "verdict unavailable", never a clean 100.
        unanalysed = [result for result in results if not _has_vulnerability_rows(result)]
        inputs.retained_vulnerability_occurrences = sum(
            int((result.get("summary") or {}).get("total_vulnerabilities") or 0) for result in unanalysed
        )
    credential_servers = _fold_inventory(inputs, results)
    exposing = _fold_exposed_credentials(inputs, rows, credential_servers)

    dimensions = score_posture_dimensions(inputs, load_posture_policy().weights)
    return {
        "dimensions": {key: value.to_dict() for key, value in dimensions.items()},
        "basis": {
            "basis": TENANT_DIMENSIONS_BASIS,
            "scan_ids": sorted(str(result.get("scan_id") or job.job_id) for result, job in zip(results, evidence_jobs)),
            "scan_count": len(evidence_jobs),
            "open_findings": len(rows),
            "vulnerability_findings": len(vulnerability_rows),
            "credential_exposed_findings": exposing,
        },
    }


__all__ = ["TENANT_DIMENSIONS_BASIS", "current_findings_dimensions"]
