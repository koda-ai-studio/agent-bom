"""Posture scorecard engine — letter grade + score from a scan report snapshot.

Default logic is informed by findings, enrichment, credentials, KEV/EPSS,
framework coverage, and config quality on **that report** (latest completed
scan, or the scan the operator is viewing). Metrics are not a static demo
grade — they move with scan evidence.

Adopters are not forced onto the defaults. Override dimension weights and/or
grade thresholds via ``AGENT_BOM_POSTURE_POLICY`` (inline JSON) or
``AGENT_BOM_POSTURE_POLICY_FILE`` (path to JSON). Example::

    {
      "weights": {
        "vulnerability_posture": 0.40,
        "credential_hygiene": 0.25,
        "supply_chain_quality": 0.10,
        "compliance_coverage": 0.10,
        "active_exploitation": 0.10,
        "configuration_quality": 0.05
      },
      "grade_thresholds": {"A": 92, "B": 82, "C": 72, "D": 60}
    }

Missing keys keep the built-in defaults. Weights are renormalized to sum to 1.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Mapping

from agent_bom.core.risk_display import assessed_risk_score
from agent_bom.core.severity import severity_policy_rank
from agent_bom.evidence.posture_dimensions import DimensionScore, assessed_weighted_total, lane_summary
from agent_bom.evidence.posture_inputs import posture_inputs_from_report, score_posture_dimensions
from agent_bom.evidence.scan_run import vulnerability_coverage_caveat, vulnerability_coverage_incomplete
from agent_bom.vex import active_blast_radii

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport

# Default dimension weights — informed defaults, not a locked customer policy.
DEFAULT_DIMENSION_WEIGHTS: dict[str, float] = {
    "vulnerability_posture": 0.30,
    "credential_hygiene": 0.20,
    "supply_chain_quality": 0.15,
    "compliance_coverage": 0.15,
    "active_exploitation": 0.10,
    "configuration_quality": 0.10,
}

# Minimum score (inclusive) for each letter grade.
DEFAULT_GRADE_THRESHOLDS: dict[str, float] = {
    "A": 90.0,
    "B": 80.0,
    "C": 70.0,
    "D": 60.0,
}


@dataclass(frozen=True)
class PosturePolicy:
    """Resolved posture scoring policy (defaults + optional adopter overrides)."""

    weights: Mapping[str, float]
    grade_thresholds: Mapping[str, float]
    source: str = "default"


def _normalize_weights(weights: Mapping[str, float]) -> dict[str, float]:
    merged = {key: float(DEFAULT_DIMENSION_WEIGHTS[key]) for key in DEFAULT_DIMENSION_WEIGHTS}
    for key, value in weights.items():
        if key in merged:
            try:
                merged[key] = max(0.0, float(value))
            except (TypeError, ValueError):
                continue
    total = sum(merged.values())
    if total <= 0:
        return dict(DEFAULT_DIMENSION_WEIGHTS)
    return {key: round(value / total, 6) for key, value in merged.items()}


def _normalize_thresholds(thresholds: Mapping[str, float]) -> dict[str, float]:
    merged = {key: float(DEFAULT_GRADE_THRESHOLDS[key]) for key in DEFAULT_GRADE_THRESHOLDS}
    for key, value in thresholds.items():
        letter = str(key).upper()
        if letter in merged:
            try:
                merged[letter] = float(value)
            except (TypeError, ValueError):
                continue
    # Keep A >= B >= C >= D so grade bands stay ordered.
    ordered = sorted(
        (("A", merged["A"]), ("B", merged["B"]), ("C", merged["C"]), ("D", merged["D"])),
        key=lambda item: item[1],
        reverse=True,
    )
    return {letter: score for letter, score in ordered}


def load_posture_policy(
    *,
    weights: Mapping[str, float] | None = None,
    grade_thresholds: Mapping[str, float] | None = None,
) -> PosturePolicy:
    """Resolve posture policy from explicit args, then env, then defaults."""

    source = "default"
    env_weights: dict[str, float] = {}
    env_thresholds: dict[str, float] = {}

    raw = os.environ.get("AGENT_BOM_POSTURE_POLICY", "").strip()
    file_path = os.environ.get("AGENT_BOM_POSTURE_POLICY_FILE", "").strip()
    payload: dict | None = None
    if raw:
        try:
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                payload = loaded
                source = "env:AGENT_BOM_POSTURE_POLICY"
        except json.JSONDecodeError:
            payload = None
    elif file_path:
        try:
            loaded = json.loads(Path(file_path).read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                payload = loaded
                source = f"file:{file_path}"
        except (OSError, json.JSONDecodeError):
            payload = None

    if payload:
        maybe_weights = payload.get("weights")
        if isinstance(maybe_weights, dict):
            env_weights = {str(k): float(v) for k, v in maybe_weights.items() if _is_number(v)}
        maybe_thresholds = payload.get("grade_thresholds") or payload.get("thresholds")
        if isinstance(maybe_thresholds, dict):
            env_thresholds = {str(k).upper(): float(v) for k, v in maybe_thresholds.items() if _is_number(v)}

    if weights is not None:
        env_weights = {**env_weights, **{str(k): float(v) for k, v in weights.items()}}
        source = "explicit" if source == "default" else f"{source}+explicit"
    if grade_thresholds is not None:
        env_thresholds = {
            **env_thresholds,
            **{str(k).upper(): float(v) for k, v in grade_thresholds.items()},
        }
        source = "explicit" if source == "default" else f"{source}+explicit"

    return PosturePolicy(
        weights=_normalize_weights(env_weights),
        grade_thresholds=_normalize_thresholds(env_thresholds),
        source=source,
    )


def _is_number(value: object) -> bool:
    try:
        float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    return True


@dataclass
class PostureScorecard:
    """Enterprise posture scorecard result."""

    grade: str  # A, B, C, D, F, or N/A
    score: float  # 0-100
    dimensions: dict[str, DimensionScore] = field(default_factory=dict)
    summary: str = ""
    policy_source: str = "default"
    no_data: bool = False  # True when the scan examined no gradable artifacts

    def to_dict(self) -> dict:
        return {
            "grade": self.grade,
            "score": self.score,
            "summary": self.summary,
            "policy_source": self.policy_source,
            "no_data": self.no_data,
            "dimensions": {k: v.to_dict() for k, v in self.dimensions.items()},
        }


def _score_to_grade(
    score: float,
    thresholds: Mapping[str, float] | None = None,
) -> str:
    """Convert numeric score to letter grade (adopter thresholds optional)."""
    bands = thresholds or DEFAULT_GRADE_THRESHOLDS
    if score >= float(bands.get("A", 90)):
        return "A"
    if score >= float(bands.get("B", 80)):
        return "B"
    if score >= float(bands.get("C", 70)):
        return "C"
    if score >= float(bands.get("D", 60)):
        return "D"
    return "F"


def compute_posture_scorecard(
    report: "AIBOMReport",
    *,
    policy: PosturePolicy | None = None,
    weights: Mapping[str, float] | None = None,
    grade_thresholds: Mapping[str, float] | None = None,
) -> PostureScorecard:
    """Compute posture scorecard from a scan report snapshot.

    Dimensions (default weights — override via ``policy`` / env):
        vulnerability_posture  30%  — severity distribution + fix availability
        credential_hygiene     20%  — credential exposure footprint
        supply_chain_quality   15%  — OpenSSF Scorecard coverage
        compliance_coverage    15%  — threat framework tag coverage
        active_exploitation    10%  — KEV / high EPSS presence
        configuration_quality  10%  — registry verification + tool declaration

    Returns:
        PostureScorecard with grade, score, and per-dimension breakdown for
        **this report** (current scan / selected snapshot), not a frozen demo.
    """
    resolved = policy or load_posture_policy(weights=weights, grade_thresholds=grade_thresholds)
    inputs = posture_inputs_from_report(report)
    dimensions = score_posture_dimensions(inputs, resolved.weights)
    total_vulns = len(inputs.vulnerabilities)
    total_cred_servers = inputs.credential_servers
    total_servers = inputs.total_servers
    verified_servers = inputs.verified_servers
    all_packages = inputs.packages
    retained_vulnerability_occurrences = inputs.retained_vulnerability_occurrences

    vuln_lane_skipped = inputs.vulnerability_lane_skipped
    # ── Did-we-scan guard ──
    # A grade requires real evaluated inputs. When a scan examined ZERO gradable
    # artifacts (no packages, no MCP servers, no active findings), every
    # dimension above falls back to its empty default (100/50) and would produce
    # a passing "B" — an honest-looking pass for a scan that evaluated nothing.
    # Return an explicit no-data / N/A posture instead, mirroring the honest N/A
    # treatment used elsewhere (overview tile, exec score). Dimensions and policy
    # source are preserved for downstream plumbing; only the headline is honest.
    examined_artifacts = total_vulns + total_servers + len(all_packages)
    if examined_artifacts == 0:
        return PostureScorecard(
            grade="N/A",
            score=0.0,
            dimensions=dimensions,
            summary="No artifacts scanned — posture grade unavailable. Connect a surface or run a scan to grade posture.",
            policy_source=resolved.source,
            no_data=True,
        )

    # Imported SBOMs and scan-report snapshots can carry vulnerability records
    # even when a downstream scanner returns no BlastRadius rows.  Those records
    # are still evidence, but they do not contain enough analyzed reachability
    # context to compute this scorecard.  Never turn that projection gap into a
    # clean posture claim.
    if total_vulns == 0 and retained_vulnerability_occurrences:
        return PostureScorecard(
            grade="N/A",
            score=0.0,
            dimensions=dimensions,
            summary=(
                "Retained vulnerability evidence requires analysis — posture grade unavailable. Re-run with vulnerability analysis enabled."
            ),
            policy_source=resolved.source,
            no_data=True,
        )

    # ── Could-we-evaluate guard ──
    # The guard above measures DISCOVERY. A scan can discover packages and still
    # have had no vulnerability data to grade them against — the vuln DB was
    # unavailable, a required scanner failed. Every dimension then falls back to
    # its empty default and the headline reads "No vulnerabilities found …(A)",
    # which is a false all-clear, not a missing one. Grade only what we could
    # actually evaluate.
    if vulnerability_coverage_incomplete(report):
        return PostureScorecard(
            grade="N/A",
            score=0.0,
            dimensions=dimensions,
            summary="Vulnerability coverage incomplete — posture grade unavailable. Re-run once vulnerability data is available.",
            policy_source=resolved.source,
            no_data=True,
        )

    # ── Final score ──
    total_score = assessed_weighted_total(dimensions)
    grade = _score_to_grade(total_score, resolved.grade_thresholds)

    # Build summary: keep vulnerability cleanliness apart from config quality so
    # clean scans never read as contradictory when optional metadata is missing.
    if total_vulns == 0:
        if grade in ("A", "B"):
            summary = f"No vulnerabilities found; strong best-practice/config posture ({grade}, {total_score}%)"
        elif grade == "C":
            summary = f"No vulnerabilities found; config/best-practice improvements recommended ({grade}, {total_score}%)"
        else:
            summary = f"No vulnerabilities found; config/best-practice gaps need attention ({grade}, {total_score}%)"
    elif grade in ("A", "B"):
        summary = f"Strong best-practice/config posture ({grade}, {total_score}%)"
    elif grade == "C":
        summary = f"Moderate best-practice/config posture ({grade}, {total_score}%) — improvements recommended"
    else:
        drivers: list[str] = []
        if total_cred_servers > 0:
            drivers.append(f"real credential exposure across {total_cred_servers} server{'s' if total_cred_servers != 1 else ''}")
        if report.has_mcp_context and total_servers > 0 and verified_servers < total_servers:
            drivers.append(
                "unverified or underspecified MCP configuration on "
                f"{total_servers - verified_servers}/{total_servers} "
                f"server{'s' if total_servers != 1 else ''}"
            )
        if drivers:
            summary = f"Weak best-practice/config posture ({grade}, {total_score}%) — this grade is driven by " + " and ".join(drivers)
        else:
            summary = f"Weak best-practice/config posture ({grade}, {total_score}%) — immediate attention required"

    summary = lane_summary(summary, skipped=vuln_lane_skipped, grade=grade, score=total_score)
    coverage_caveat = vulnerability_coverage_caveat(report)
    if coverage_caveat:
        summary = f"{summary}. {coverage_caveat}."

    return PostureScorecard(
        grade=grade,
        score=total_score,
        dimensions=dimensions,
        summary=summary,
        policy_source=resolved.source,
    )


def compute_credential_risk_ranking(report: "AIBOMReport") -> list[dict]:
    """Rank credentials by blast radius exposure.

    Returns a sorted list of credentials with:
    - credential name
    - exposure count (how many servers)
    - affected agents
    - associated vulnerabilities (critical/high counts)
    - risk tier (critical, high, medium, low)
    """
    cred_data: dict[str, dict] = {}

    def _entry(cred: str) -> dict:
        if cred not in cred_data:
            cred_data[cred] = {
                "credential": cred,
                "server_count": 0,
                "agents": set(),
                "servers": set(),
                "reachable_tools": set(),
                "vuln_critical": 0,
                "vuln_high": 0,
                "vuln_total": 0,
                "max_risk_score": 0.0,
            }
        return cred_data[cred]

    # ── Phase 1: CVE-backed exposure ──
    # Credentials reachable from an active (non-VEX-suppressed) blast radius.
    for br in active_blast_radii(report.blast_radii):
        for cred in br.exposed_credentials:
            entry = _entry(cred)
            for a in br.affected_agents:
                entry["agents"].add(a.name)
            for s in br.affected_servers:
                entry["servers"].add(s.name)
                entry["reachable_tools"].update(t.name for t in s.tools)
            sev = br.vulnerability.severity.value.upper()
            if sev == "CRITICAL":
                entry["vuln_critical"] += 1
            elif sev == "HIGH":
                entry["vuln_high"] += 1
            entry["vuln_total"] += 1
            entry["max_risk_score"] = max(entry["max_risk_score"], assessed_risk_score(br))

    # ── Phase 2: discovery-only exposure ──
    # A credential on an MCP server with no CVE-backed blast radius is still a
    # standing exposure — a long-lived secret reachable by the agent's tools.
    # Rank it by breadth instead of dropping it from the report (previously it
    # was invisible whenever no vulnerability matched). Credentials already
    # ranked in Phase 1 are enriched in place (servers/agents/tools merge via
    # sets); their CVE-derived tier is preserved.
    for agent in report.agents:
        for server in agent.mcp_servers:
            for cred in server.credential_names:
                entry = _entry(cred)
                entry["agents"].add(agent.name)
                entry["servers"].add(server.name)
                entry["reachable_tools"].update(t.name for t in server.tools)

    results = []
    for cred, data in cred_data.items():
        server_count = len(data["servers"])
        reachable_tools = sorted(data["reachable_tools"])
        risk_score = data["max_risk_score"]

        if data["vuln_total"] > 0:
            basis = "vulnerability"
            if data["vuln_critical"] > 0 or risk_score >= 8.0:
                risk_tier = "critical"
            elif data["vuln_high"] > 0 or risk_score >= 6.0:
                risk_tier = "high"
            elif data["vuln_total"] > 3:
                risk_tier = "medium"
            else:
                risk_tier = "low"
        else:
            # Discovery-only: no proven exploit path, so cap at medium. A secret
            # reachable by tools or shared across servers has a broader standing
            # blast radius than one isolated to a single tool-less server.
            basis = "discovery"
            risk_tier = "medium" if (server_count > 1 or reachable_tools) else "low"

        results.append(
            {
                "credential": cred,
                "risk_tier": risk_tier,
                "basis": basis,
                "server_count": server_count,
                "agents": sorted(data["agents"]),
                "reachable_tools": reachable_tools,
                "vuln_critical": data["vuln_critical"],
                "vuln_high": data["vuln_high"],
                "vuln_total": data["vuln_total"],
                "max_risk_score": round(risk_score, 1),
            }
        )

    # Sort: tier first, then proven (vulnerability) before discovery at the same
    # tier, then by max_risk_score descending.
    basis_order = {"vulnerability": 0, "discovery": 1}
    results.sort(
        key=lambda x: (
            -severity_policy_rank(str(x["risk_tier"])),
            basis_order.get(x["basis"], 9),
            -x["max_risk_score"],
        )
    )
    return results


def compute_incident_correlation(report: "AIBOMReport") -> list[dict]:
    """Group vulnerabilities by agent for SOC incident correlation.

    Returns a list of agent-centric incident summaries with:
    - agent name, type, config path
    - vulnerability counts by severity
    - unique CVE IDs
    - credential exposure
    - overall incident priority (P1-P4)
    - recommended actions
    """
    agent_incidents: dict[str, dict] = {}
    active_findings = active_blast_radii(report.blast_radii)

    for br in active_findings:
        for agent in br.affected_agents:
            if agent.name not in agent_incidents:
                agent_incidents[agent.name] = {
                    "agent_name": agent.name,
                    "agent_type": agent.agent_type.value,
                    "config_path": agent.config_path,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "cve_ids": set(),
                    "kev_ids": set(),
                    "credentials_exposed": set(),
                    "packages_affected": set(),
                    "max_risk_score": 0.0,
                    "has_ai_risk": False,
                }

            entry = agent_incidents[agent.name]
            sev = br.vulnerability.severity.value.upper()
            if sev == "CRITICAL":
                entry["critical"] += 1
            elif sev == "HIGH":
                entry["high"] += 1
            elif sev == "MEDIUM":
                entry["medium"] += 1
            else:
                entry["low"] += 1

            entry["cve_ids"].add(br.vulnerability.id)
            if br.vulnerability.is_kev:
                entry["kev_ids"].add(br.vulnerability.id)
            for cred in br.exposed_credentials:
                entry["credentials_exposed"].add(cred)
            entry["packages_affected"].add(f"{br.package.name}@{br.package.version}")
            entry["max_risk_score"] = max(entry["max_risk_score"], assessed_risk_score(br))
            if br.ai_risk_context:
                entry["has_ai_risk"] = True

    results = []
    for data in agent_incidents.values():
        # Determine incident priority
        if data["kev_ids"] or data["critical"] >= 3:
            priority = "P1"
            recommended = "Immediate remediation required — actively exploited or multiple critical CVEs"
        elif data["critical"] > 0 or (data["high"] > 0 and data["credentials_exposed"]):
            priority = "P2"
            recommended = "Urgent remediation — critical CVEs or credential-exposed high-severity vulns"
        elif data["high"] > 0:
            priority = "P3"
            recommended = "Scheduled remediation — high-severity vulnerabilities present"
        else:
            priority = "P4"
            recommended = "Monitor and patch during next maintenance window"

        results.append(
            {
                "agent_name": data["agent_name"],
                "agent_type": data["agent_type"],
                "config_path": data["config_path"],
                "priority": priority,
                "severity_counts": {
                    "critical": data["critical"],
                    "high": data["high"],
                    "medium": data["medium"],
                    "low": data["low"],
                },
                "total_vulns": data["critical"] + data["high"] + data["medium"] + data["low"],
                "unique_cves": sorted(data["cve_ids"]),
                "kev_ids": sorted(data["kev_ids"]),
                "credentials_exposed": sorted(data["credentials_exposed"]),
                "packages_affected": sorted(data["packages_affected"]),
                "max_risk_score": round(data["max_risk_score"], 1),
                "has_ai_risk": data["has_ai_risk"],
                "recommended_action": recommended,
            }
        )

    # Sort by priority (P1 first), then by max_risk_score descending
    priority_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    results.sort(key=lambda x: (priority_order.get(x["priority"], 4), -x["max_risk_score"]))
    return results
