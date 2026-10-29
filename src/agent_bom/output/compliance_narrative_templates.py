"""Text formatting for evaluated compliance evidence and remediation summaries."""

from __future__ import annotations

from agent_bom import config
from agent_bom.output.compliance_narrative_models import FrameworkNarrative


def _severity_order(sev: str) -> int:
    from agent_bom.core.severity import severity_worst_first_rank

    return severity_worst_first_rank(sev)


def _control_narrative(
    control_id: str,
    control_name: str,
    findings: int,
    affected_pkgs: list[str],
    affected_agents: list[str],
    sev_breakdown: dict[str, int],
) -> str:
    """Generate a plain-English explanation for a control's status."""
    if findings == 0:
        return (
            f"Control {control_id} ({control_name}) shows no findings in this scan. "
            "This is an absence of mapped findings, not a determination that the control is satisfied."
        )

    pkg_str = ", ".join(affected_pkgs[:3])
    if len(affected_pkgs) > 3:
        pkg_str += f" and {len(affected_pkgs) - 3} more"

    agent_str = ""
    if affected_agents:
        a_list = ", ".join(affected_agents[:3])
        agent_str = f" reaching agent{'s' if len(affected_agents) > 1 else ''} {a_list}"

    crit = sev_breakdown.get("critical", 0)
    high = sev_breakdown.get("high", 0)
    med = sev_breakdown.get("medium", 0)

    severity_desc = ""
    if crit:
        severity_desc = f"{crit} critical"
        if high:
            severity_desc += f" and {high} high"
    elif high:
        severity_desc = f"{high} high"
    elif med:
        severity_desc = f"{med} medium"
    else:
        severity_desc = "low"

    return (
        f"Control {control_id} ({control_name}) has {findings} finding"
        f"{'s' if findings > 1 else ''} ({severity_desc} severity) "
        f"in packages: {pkg_str}{agent_str}. "
        "The mapped finding requires review and remediation; this mapping does not determine control compliance."
    )


def _detective_control_narrative(control_id: str, control_name: str, status: str) -> str:
    """Explain a detective control's status in scan-evidence terms.

    A detective control is *implemented by* the scan (see
    :mod:`agent_bom.evidence.control_modes`), so its story is about evidence
    freshness, never about which findings mapped to it.
    """
    if status == "pass":
        return (
            f"Control {control_id} ({control_name}) is evidenced by this scan itself: "
            "the run completed inside the evidence-freshness window, which is what "
            "this control requires. Findings surfaced by the scan are proof the "
            "control operates, not proof it failed."
        )
    return (
        f"Control {control_id} ({control_name}) has no scan evidence inside the "
        f"freshness window ({config.COMPLIANCE_DETECTIVE_EVIDENCE_MAX_AGE_DAYS} days) — "
        "the evidence backing it is stale, so continuous monitoring has lapsed. "
        "Its evidence status requires action independently of any vulnerability finding."
    )


def _detective_remediation_steps(control_id: str, control_name: str) -> list[str]:
    """Remediation for a detective control is to resume scanning, not to patch."""
    return [
        f"Re-run agent-bom so {control_id} is backed by evidence inside the "
        f"{config.COMPLIANCE_DETECTIVE_EVIDENCE_MAX_AGE_DAYS}-day freshness window.",
        "Schedule the scan continuously (CI or a recurring job) — this evidence documents "
        "ongoing monitoring, so a one-off run is current only until the window lapses.",
        f"Record the scan cadence for {control_name} in your compliance evidence package.",
    ]


def _control_remediation_steps(
    control_id: str,
    control_name: str,
    affected_pkgs: list[str],
    sev_breakdown: dict[str, int],
) -> list[str]:
    """Generate actionable remediation steps for mapped control evidence."""
    steps: list[str] = []
    if affected_pkgs:
        steps.append(f"Upgrade vulnerable packages: {', '.join(affected_pkgs[:5])}" + (" (and others)" if len(affected_pkgs) > 5 else ""))
    if sev_breakdown.get("critical", 0) or sev_breakdown.get("high", 0):
        steps.append("Prioritise critical and high severity findings for immediate patching, then validate the control independently.")
    steps.append(f"Re-run agent-bom after upgrades to verify findings mapped to {control_id} are no longer detected.")
    steps.append(f"Document the remediation timeline for {control_name} in your compliance evidence package.")
    return steps


def _framework_overall_narrative(
    display_name: str,
    total_controls: int,
    evaluated_count: int,
    pass_count: int,
    fail_count: int,
    warn_count: int,
    critical_failing: list[str],
    score: int,
) -> str:
    """2-3 sentence framework-level posture narrative."""
    if evaluated_count == 0:
        return (
            f"No {display_name} controls could be evaluated in this scan: "
            f"0 of {total_controls} controls have vulnerability-derived evidence. "
            "This is a coverage gap, not a pass — controls without mapped findings are "
            f"reported as not-evaluated. Run scans that map findings to {display_name} "
            "before relying on this posture."
        )

    plural = "s" if evaluated_count != 1 else ""
    if fail_count == 0 and warn_count == 0:
        return (
            f"Evidence is current for all {evaluated_count} evaluated {display_name} control{plural} "
            f"({evaluated_count} of {total_controls} controls evaluated; score {score}/100 "
            "over evaluated controls). Controls with no mapped findings are reported as "
            "not-evaluated rather than compliant. This evidence status is not an audit conclusion."
        )

    if fail_count == 0:
        return (
            f"{display_name} evidence requires review: {warn_count} control"
            f"{'s have' if warn_count > 1 else ' has'} mapped medium or low severity findings "
            f"(score {score}/100 over {evaluated_count} evaluated control{plural}). "
            "Schedule remediation within the next maintenance cycle. The mapping is not a compliance determination."
        )

    ctrl_str = ", ".join(critical_failing[:3])
    if len(critical_failing) > 3:
        ctrl_str += f" and {len(critical_failing) - 3} others"

    return (
        f"{display_name} evidence requires action: {fail_count} control"
        f"{'s have' if fail_count > 1 else ' has'} mapped critical or high severity findings "
        f"(score {score}/100 over {evaluated_count} evaluated control{plural}). "
        f"Controls requiring review include {ctrl_str}. "
        "Remediate the underlying findings and obtain independent control evidence before drawing a compliance conclusion."
    )


def _build_risk_narrative(
    blast_radii_dicts: list[dict],
    total_agents: int,
    total_vulns: int,
    critical_count: int,
    finding_label: str = "vulnerability",
) -> str:
    """Plain-English top-risk explanation from scan data."""
    plural_label = "vulnerabilities" if finding_label == "vulnerability" else f"{finding_label}s"
    if not blast_radii_dicts:
        if finding_label != "vulnerability":
            return (
                "No security findings were detected in the current evidence scope. "
                "This is not a claim that unscanned or unavailable sources are clean."
            )
        return (
            "No vulnerabilities were detected in this scan. "
            "The AI agent environment appears clean based on the packages assessed. "
            "Continue regular scanning to detect newly published vulnerabilities."
        )

    kev_entries = [br for br in blast_radii_dicts if br.get("is_kev")]
    # Find the highest-risk entry
    sorted_by_risk = sorted(
        blast_radii_dicts,
        key=lambda b: (
            -(b.get("risk_score") or 0),
            _severity_order(b.get("severity") or "low"),
        ),
    )
    top = sorted_by_risk[0] if sorted_by_risk else None

    parts: list[str] = []

    # Lead sentence
    agent_str = f"{total_agents} agent{'s' if total_agents != 1 else ''}"
    item_word = finding_label if total_vulns == 1 else plural_label
    evidence_subject = "This scan" if finding_label == "vulnerability" else "Current evidence"
    parts.append(f"{evidence_subject} identified {total_vulns} {item_word} across {agent_str}.")

    # KEV callout
    if kev_entries:
        kev_pkgs = list({(br.get("package") or "") for br in kev_entries})[:3]
        parts.append(
            f"{len(kev_entries)} finding{'s are' if len(kev_entries) > 1 else ' is'} "
            f"listed in the CISA Known Exploited Vulnerabilities (KEV) catalog "
            f"(packages: {', '.join(kev_pkgs)}), indicating active exploitation in the wild."
        )

    # Critical callout
    if critical_count and not kev_entries:
        parts.append(
            f"{critical_count} critical severity finding{'s require' if critical_count > 1 else ' requires'} "
            "immediate attention as they represent the highest exploitability risk."
        )

    # Top finding
    if top:
        top_pkg = top.get("package", "an affected package")
        top_vuln = top.get("vulnerability_id", "an unknown CVE")
        top_agents = top.get("affected_agents", [])
        top_creds = top.get("exposed_credentials", [])
        top_score = top.get("risk_score") or 0

        agent_exposure = ""
        if top_agents:
            agent_exposure = f", affecting agent{'s' if len(top_agents) > 1 else ''} {', '.join(top_agents[:2])}"

        cred_exposure = ""
        if top_creds:
            cred_exposure = f" with {len(top_creds)} exposed credential{'s' if len(top_creds) > 1 else ''}"

        subject = top["title"] if (top.get("finding_type") or "CVE") != "CVE" and top.get("title") else f"{top_vuln} in {top_pkg}"
        parts.append(f"The highest-risk finding is {subject} (risk score {top_score:.1f}/10{agent_exposure}{cred_exposure}).")

    return " ".join(parts)


def _named_list(names: list[str], shown: int = 3) -> str:
    """Name the first few items and count the rest, so a list is never silently cut."""
    head = ", ".join(names[:shown])
    return f"{head} and {len(names) - shown} more" if len(names) > shown else head


def _build_executive_summary(
    framework_narratives: list[FrameworkNarrative],
    total_agents: int,
    total_packages: int,
    total_vulns: int,
    critical_count: int,
    generated_at: str,
    finding_label: str = "vulnerability",
) -> str:
    """3-5 sentence executive summary for compliance stakeholders."""
    action_fws = [fn for fn in framework_narratives if fn.status == "action_required"]
    review_fws = [fn for fn in framework_narratives if fn.status == "review"]
    evaluated_fws = [fn for fn in framework_narratives if fn.status in ("evidence_current", "review", "action_required")]
    # Lead: what was scanned
    evidence_verb = "scanned on" if finding_label == "vulnerability" else "represented in current evidence through"
    sentences: list[str] = [
        f"This AI-BOM compliance report covers {total_agents} AI agent"
        f"{'s' if total_agents != 1 else ''} "
        f"and {total_packages} package{'s' if total_packages != 1 else ''} "
        f"{evidence_verb} {generated_at[:10]}."
    ]

    plural_label = "vulnerabilities" if finding_label == "vulnerability" else f"{finding_label}s"
    item_word = finding_label if total_vulns == 1 else plural_label
    # Finding posture
    if total_vulns == 0:
        if finding_label == "vulnerability":
            sentences.append("No vulnerabilities were detected; all assessed dependencies are clean.")
        else:
            sentences.append(
                "No security findings were detected in the current evidence scope; unavailable or unscanned sources are not claimed clean."
            )
    elif critical_count > 0:
        sentences.append(
            f"{total_vulns} {item_word} {'were' if total_vulns > 1 else 'was'} identified "
            f"including {critical_count} critical finding"
            f"{'s' if critical_count > 1 else ''} that require immediate remediation."
        )
    else:
        sentences.append(f"{total_vulns} {item_word} {'were' if total_vulns > 1 else 'was'} identified across the assessed evidence.")

    # Framework posture
    total_fws = len(framework_narratives)
    if action_fws:
        fw_names = _named_list([fn.framework for fn in action_fws])
        sentences.append(f"{len(action_fws)} of {total_fws} framework mappings have evidence requiring action: {fw_names}.")
    elif review_fws:
        fw_names = _named_list([fn.framework for fn in review_fws])
        sentences.append(
            f"No framework mapping has critical/high findings; {len(review_fws)} "
            f"{'require' if len(review_fws) > 1 else 'requires'} review: {fw_names}."
        )
    elif evaluated_fws:
        sentences.append(f"All {len(evaluated_fws)} evaluated framework evidence sets are current with no mapped critical findings.")
    else:
        sentences.append(
            f"None of the {total_fws} frameworks could be evaluated — no findings mapped to their "
            "controls, so compliance posture is unknown rather than compliant."
        )

    # Closing action
    if action_fws or review_fws:
        sentences.append(
            f"Remediation of identified {plural_label} is the highest-priority action; control owners must validate compliance separately."
        )
    else:
        sentences.append("Continue regular scanning and independent control validation to maintain current evidence coverage.")

    return " ".join(sentences)
