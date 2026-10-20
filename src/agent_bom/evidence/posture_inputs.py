"""The evidence a posture scorecard grades, and the six dimension scores over it.

One scoring function serves both bases: a single scan report
(``posture_inputs_from_report``) and the tenant's current open findings across
every current scan (built in ``agent_bom.api.tenant_posture_dimensions``). Only
the input set differs, so a dimension means the same thing on either basis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Mapping

from agent_bom import config
from agent_bom.compliance_utils import effective_blast_radius_tags
from agent_bom.evidence.posture_dimensions import DimensionScore, mark_vulnerability_lane_not_assessed
from agent_bom.evidence.scan_run import effective_scan_run, vulnerability_scan_skipped
from agent_bom.scorecard import summarize_scorecard_coverage
from agent_bom.vex import active_blast_radii

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport


@dataclass(frozen=True)
class VulnerabilitySignal:
    """One active (not suppressed) vulnerability occurrence."""

    vuln_id: str
    severity: str
    fixable: bool
    is_kev: bool
    epss_score: float
    framework_mapped: bool


@dataclass
class PostureInputs:
    vulnerabilities: list[VulnerabilitySignal] = field(default_factory=list)
    retained_vulnerability_occurrences: int = 0
    credential_servers: int = 0
    credentials: set[str] = field(default_factory=set)
    packages: list[Any] = field(default_factory=list)
    total_servers: int = 0
    verified_servers: int = 0
    servers_with_tools: int = 0
    has_mcp_context: bool = False
    vulnerability_lane_skipped: bool = False


def posture_inputs_from_report(report: "AIBOMReport") -> PostureInputs:
    vulnerabilities = []
    for br in active_blast_radii(report.blast_radii):
        tags = effective_blast_radius_tags(br)
        vulnerabilities.append(
            VulnerabilitySignal(
                vuln_id=br.vulnerability.id,
                severity=br.vulnerability.severity.value.upper(),
                fixable=bool(br.vulnerability.fixed_version),
                is_kev=bool(br.vulnerability.is_kev),
                epss_score=float(br.vulnerability.epss_score or 0),
                framework_mapped=any(tags[key] for key in FRAMEWORK_TAG_FIELDS),
            )
        )
    inputs = PostureInputs(
        vulnerabilities=vulnerabilities,
        retained_vulnerability_occurrences=report.total_vulnerabilities,
        has_mcp_context=bool(report.has_mcp_context),
        vulnerability_lane_skipped=vulnerability_scan_skipped(effective_scan_run(report)),
    )
    for agent in report.agents:
        for server in agent.mcp_servers:
            inputs.total_servers += 1
            inputs.verified_servers += int(bool(server.registry_verified))
            inputs.servers_with_tools += int(bool(server.tools))
            if server.has_credentials:
                inputs.credential_servers += 1
                inputs.credentials.update(server.credential_names)
            inputs.packages.extend(server.packages)
    return inputs


# The framework fields whose presence counts a finding as mapped.
FRAMEWORK_TAG_FIELDS = (
    "owasp_tags",
    "atlas_tags",
    "nist_ai_rmf_tags",
    "owasp_mcp_tags",
    "owasp_agentic_tags",
    "eu_ai_act_tags",
    "nist_csf_tags",
    "iso_27001_tags",
    "soc2_tags",
    "cis_tags",
)


def _vulnerability_dimension(inputs: PostureInputs, weight: float) -> DimensionScore:
    sev_counts: dict[str, int] = {}
    for vuln in inputs.vulnerabilities:
        sev_counts[vuln.severity] = sev_counts.get(vuln.severity, 0) + 1
    total_vulns = len(inputs.vulnerabilities)
    fixable = sum(vuln.fixable for vuln in inputs.vulnerabilities)
    if total_vulns == 0:
        if inputs.retained_vulnerability_occurrences:
            vuln_score = 0.0
            retained = inputs.retained_vulnerability_occurrences
            vuln_detail = f"{retained} vulnerability occurrence(s) retained from inventory; analysis verdict unavailable"
        else:
            vuln_score = 100.0
            vuln_detail = "No vulnerabilities found"
    else:
        # Weighted penalty: critical=15, high=8, medium=3, low=1
        penalty = (
            sev_counts.get("CRITICAL", 0) * 15
            + sev_counts.get("HIGH", 0) * 8
            + sev_counts.get("MEDIUM", 0) * 3
            + sev_counts.get("LOW", 0) * 1
        )
        vuln_score = max(0.0, 100.0 - penalty)
        vuln_score = min(100.0, vuln_score + fixable / total_vulns * 10)
        parts = [f"{sev_counts[s]} {s.lower()}" for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if sev_counts.get(s, 0) > 0]
        unit = "vulnerability occurrence" if total_vulns == 1 else "vulnerability occurrences"
        vuln_detail = f"{total_vulns} {unit} ({', '.join(parts)}), {fixable} fixable"
    return DimensionScore(name="Vulnerability Posture", score=round(vuln_score, 1), weight=weight, details=vuln_detail)


def _credential_dimension(inputs: PostureInputs, weight: float) -> DimensionScore:
    if inputs.credential_servers == 0:
        cred_score = 100.0
        cred_detail = "No credential exposure detected"
    else:
        cred_penalty = min(len(inputs.credentials) * 8 + inputs.credential_servers * 3, 100)
        cred_score = max(0.0, 100.0 - cred_penalty)
        cred_detail = f"{len(inputs.credentials)} unique credentials across {inputs.credential_servers} servers"
    return DimensionScore(name="Credential Hygiene", score=round(cred_score, 1), weight=weight, details=cred_detail)


def _supply_chain_dimension(inputs: PostureInputs, weight: float) -> DimensionScore:
    packages = inputs.packages
    scorecard_scores = [pkg.scorecard_score for pkg in packages if pkg.scorecard_score is not None]
    stats = summarize_scorecard_coverage(packages)
    transient_failures = {
        pkg.scorecard_lookup_reason
        for pkg in packages
        if pkg.scorecard_lookup_state == "failed"
        and pkg.scorecard_lookup_reason in {"scorecard_rate_limited", "scorecard_service_unavailable"}
    }
    if scorecard_scores:
        avg_scorecard = sum(scorecard_scores) / len(scorecard_scores)
        sc_score = min(100.0, avg_scorecard * 10)
        coverage = f"{stats.enriched_packages}/{stats.eligible_packages} eligible packages enriched"
        sc_detail = f"Avg OpenSSF Scorecard: {avg_scorecard:.1f}/10 ({coverage})"
    elif stats.eligible_packages == 0:
        sc_score = 50.0
        sc_detail = "No GitHub-backed packages eligible for OpenSSF Scorecard"
    elif stats.failed_packages > 0 and transient_failures:
        sc_score = 100.0
        sc_detail = (
            "OpenSSF Scorecard temporarily unavailable upstream; "
            f"not penalizing posture ({stats.enriched_packages}/{stats.eligible_packages} eligible packages enriched, "
            f"{stats.failed_packages} transient lookup failures)"
        )
    elif stats.failed_packages > 0:
        sc_score = 50.0
        sc_detail = (
            "OpenSSF Scorecard coverage pending: "
            f"{stats.enriched_packages}/{stats.eligible_packages} eligible packages enriched, "
            f"{stats.failed_packages} lookup failures"
        )
    else:
        sc_score = 50.0
        sc_detail = (
            f"OpenSSF Scorecard coverage unresolved: {stats.unresolved_packages} package(s) lacked resolvable GitHub source metadata"
        )
    return DimensionScore(name="Supply Chain Quality", score=round(sc_score, 1), weight=weight, details=sc_detail)


def _compliance_dimension(inputs: PostureInputs, weight: float) -> DimensionScore:
    total = len(inputs.vulnerabilities)
    mapped = sum(vuln.framework_mapped for vuln in inputs.vulnerabilities)
    if total == 0:
        return DimensionScore(name="Compliance Coverage", score=100.0, weight=weight, details="No findings to map")
    return DimensionScore(
        name="Compliance Coverage",
        score=round(min(100.0, mapped / total * 100), 1),
        weight=weight,
        details=f"{mapped}/{total} findings mapped to threat frameworks",
    )


def _exploitation_dimension(inputs: PostureInputs, weight: float) -> DimensionScore:
    kev_ids = {vuln.vuln_id for vuln in inputs.vulnerabilities if vuln.is_kev}
    high_epss_ids = {vuln.vuln_id for vuln in inputs.vulnerabilities if vuln.epss_score >= config.EPSS_CRITICAL_THRESHOLD}
    if not kev_ids and not high_epss_ids:
        return DimensionScore(name="Active Exploitation", score=100.0, weight=weight, details="No actively exploited vulnerabilities")
    # KEV penalty=25, EPSS-only penalty=10, both=25 (no double-count)
    penalty = len(kev_ids) * 25 + len(high_epss_ids - kev_ids) * 10
    parts = []
    if kev_ids:
        parts.append(f"{len(kev_ids)} CISA KEV")
    if high_epss_ids:
        parts.append(f"{len(high_epss_ids)} high-EPSS")
    return DimensionScore(name="Active Exploitation", score=round(max(0.0, 100.0 - penalty), 1), weight=weight, details=", ".join(parts))


def _configuration_dimension(inputs: PostureInputs, weight: float) -> DimensionScore:
    total = inputs.total_servers
    if total == 0:
        config_score, config_detail = 50.0, "No servers to evaluate"
    elif not inputs.has_mcp_context:
        config_score, config_detail = 100.0, "N/A for scans without MCP server configuration context"
    else:
        config_score = inputs.verified_servers / total * 60 + inputs.servers_with_tools / total * 40
        config_detail = f"{inputs.verified_servers}/{total} verified, {inputs.servers_with_tools}/{total} with tool declarations"
    return DimensionScore(name="Configuration Quality", score=round(config_score, 1), weight=weight, details=config_detail)


def score_posture_dimensions(inputs: PostureInputs, weights: Mapping[str, float]) -> dict[str, DimensionScore]:
    """The six posture dimensions over ``inputs``; a skipped vulnerability lane is not assessed."""
    dimensions = {
        "vulnerability_posture": _vulnerability_dimension(inputs, float(weights["vulnerability_posture"])),
        "credential_hygiene": _credential_dimension(inputs, float(weights["credential_hygiene"])),
        "supply_chain_quality": _supply_chain_dimension(inputs, float(weights["supply_chain_quality"])),
        "compliance_coverage": _compliance_dimension(inputs, float(weights["compliance_coverage"])),
        "active_exploitation": _exploitation_dimension(inputs, float(weights["active_exploitation"])),
        "configuration_quality": _configuration_dimension(inputs, float(weights["configuration_quality"])),
    }
    if inputs.vulnerability_lane_skipped:
        mark_vulnerability_lane_not_assessed(dimensions)
    return dimensions


__all__ = [
    "FRAMEWORK_TAG_FIELDS",
    "PostureInputs",
    "VulnerabilitySignal",
    "posture_inputs_from_report",
    "score_posture_dimensions",
]
