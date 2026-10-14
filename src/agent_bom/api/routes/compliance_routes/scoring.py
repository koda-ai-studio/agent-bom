"""Per-control evaluation and the shared compliance scoring derivation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from agent_bom.compliance_coverage import rows_by_control_key
from agent_bom.compliance_nist_catalog import evaluated_control_status as _evaluated_control_status
from agent_bom.evidence.control_modes import (
    DETECTIVE_CONTROLS,
    MODE_CORRECTIVE,
    MODE_DETECTIVE,
    detective_control_status,
    requires_vulnerability_coverage,
)
from agent_bom.evidence.scoring import ComplianceVerdict, score_compliance


def _control_evaluation(
    code: str,
    findings: int,
    sev_breakdown: dict[str, int],
    *,
    scored: bool,
    detective_ids: frozenset[str],
    scan_count: int,
    latest_scan: str | None,
    vulnerability_coverage_incomplete: bool = False,
) -> tuple[str, str, str]:
    """Return ``(evaluation_mode, status, evidence_reason)`` for one control."""
    if not scored:
        # Applicability overlay (MITRE ATT&CK): a technique is made
        # applicable by an observed weakness, or it is not. It is never
        # a control the estate passed or failed, so it never enters the
        # score. Presenting it as "fail" asserted dozens of unevidenced
        # control failures per CVE.
        mode = "overlay"
        reason = "technique_observed" if findings else "no_observed_signal"
        status = "applicable" if findings else "not_applicable"
    elif code in detective_ids:
        # The scan itself is the evidence this control operates —
        # producing this scan and this SBOM IS the implementation of
        # "monitor and scan for vulnerabilities" / "maintain a component
        # inventory". Findings mapped here would be proof it works, so
        # the status comes from evidence freshness, not from findings.
        mode = MODE_DETECTIVE
        status, reason = detective_control_status(
            scan_count=scan_count,
            latest_scan=latest_scan,
            vulnerability_coverage_incomplete=vulnerability_coverage_incomplete,
        )
    elif scan_count == 0:
        # No completed scans means no evidence was gathered for this
        # control. Rendering "pass" here reads as a clean audit when in
        # fact nothing was measured, so surface an explicit not_assessed
        # status per control (mirrors the aggregate no_data top-line).
        mode = MODE_CORRECTIVE
        status, reason = "not_assessed", "no_completed_scan"
    elif findings == 0:
        # Scan ran but nothing maps to this control — no
        # vulnerability-derived evidence, so it is not_evaluated, never a
        # silent pass. Counting these as pass inflated overall_score
        # toward 100 and contradicted the narrative + CLI export; all
        # three surfaces now agree.
        mode = MODE_CORRECTIVE
        status, reason = "not_evaluated", "no_mapped_finding"
    else:
        mode = MODE_CORRECTIVE
        status = _evaluated_control_status(sev_breakdown)
        reason = "open_finding" if status != "not_evaluated" else "unrated_severity_finding"
    return mode, status, reason


def _build_controls(
    rows_by_code: Mapping[Any, Iterable[dict[str, Any]]],
    catalog: dict[str, str],
    tag_field: str,
    id_key: str,
    *,
    scored: bool = True,
    scan_count: int,
    latest_scan: str | None,
    vulnerability_coverage_incomplete: bool = False,
) -> list[dict]:
    """Build per-control compliance entries from blast_radius data.

    Three evaluation modes decide what a scan result means for a control
    (see :mod:`agent_bom.evidence.control_modes`):

    * ``detective`` — the scan IS the control operating. A fresh completed
      scan is ``pass``; stale evidence is ``fail``; no scan, or a scan whose
      vulnerability lane was incomplete (for controls that rest on it), is
      ``not_assessed``. Findings never fail a detective control.
    * ``corrective`` — attested by the ABSENCE of an open finding. An open
      finding fails/warns by worst severity; no mapped finding stays
      ``not_evaluated`` (absence of a CVE is not proof of implementation).
    * ``overlay`` (``scored=False``) — not a control at all. Entries are
      ``applicable`` / ``not_applicable`` and never touch the score.
    """
    detective_ids = DETECTIVE_CONTROLS.get(tag_field, frozenset())
    controls = []
    for code, name in sorted(catalog.items()):
        sev_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        affected_pkgs: set[str] = set()
        affected_agents: set[str] = set()
        findings = 0

        for br in rows_by_code.get(code, ()):
            findings += 1
            sev = (br.get("severity") or "").lower()
            if sev in sev_breakdown:
                sev_breakdown[sev] += 1
            pkg = br.get("package")
            if pkg:
                affected_pkgs.add(pkg)
            for agent in br.get("affected_agents", []):
                affected_agents.add(agent)

        mode, status, reason = _control_evaluation(
            code,
            findings,
            sev_breakdown,
            scored=scored,
            detective_ids=detective_ids,
            scan_count=scan_count,
            latest_scan=latest_scan,
            vulnerability_coverage_incomplete=vulnerability_coverage_incomplete and requires_vulnerability_coverage(tag_field, code),
        )
        controls.append(
            {
                id_key: code,
                "control_id": code,
                "name": name,
                "tags": [code],
                "findings": findings,
                "status": status,
                "evaluation_mode": mode,
                "evidence_reason": reason,
                "severity_breakdown": sev_breakdown,
                "affected_packages": sorted(affected_pkgs),
                "affected_agents": sorted(affected_agents),
            }
        )
    return controls


def _build_framework_controls(
    all_blast: list[dict],
    frameworks: Iterable[Any],
    *,
    scan_count: int,
    latest_scan: str | None,
    vulnerability_coverage_incomplete: bool,
) -> dict[str, list[dict]]:
    """Build every tag-mapped framework's control entries, keyed by output key."""
    return {
        metadata.output_key: _build_controls(
            rows_by_control_key(all_blast, dict(metadata.catalog), metadata.tag_field),
            dict(metadata.catalog),
            metadata.tag_field,
            "code",
            scored=metadata.scored,
            scan_count=scan_count,
            latest_scan=latest_scan,
            vulnerability_coverage_incomplete=vulnerability_coverage_incomplete,
        )
        for metadata in frameworks
    }


def _count_statuses(controls: list[dict]) -> tuple[int, int, int]:
    p = sum(1 for c in controls if c["status"] == "pass")
    w = sum(1 for c in controls if c["status"] == "warning")
    f = sum(1 for c in controls if c["status"] == "fail")
    return p, w, f


def _total_control_count(frameworks: Iterable[Any], cis_foundations_agg: dict[str, Any], aisvs_summary: dict[str, Any]) -> int:
    # A score over EVALUATED controls is only honest next to its coverage: a
    # scan that touched 8 of 931 controls and passed all 8 is "100%" of a very
    # small denominator, and a bare percentage hides that. Every surface that
    # renders overall_score MUST render these alongside it.
    return (
        sum(m.control_count for m in frameworks if m.scored)
        + int(
            cis_foundations_agg["counts"]["pass"]
            + cis_foundations_agg["counts"]["fail"]
            + cis_foundations_agg["counts"]["error"]
            + cis_foundations_agg["counts"].get("not_applicable", 0)
        )
        + int(aisvs_summary["total"])
    )


def _compliance_verdict(
    framework_controls: dict[str, list[dict]],
    frameworks: Iterable[Any],
    cis_foundations_agg: dict[str, Any],
    aisvs_summary: dict[str, Any],
    scan_count: int,
) -> ComplianceVerdict:
    """Score evaluated CVE controls plus directly evaluated benchmark checks."""
    # Overlay frameworks are excluded from every aggregate: they carry no
    # pass/warning/fail at all, so folding them in would only ever add noise.
    all_frameworks = [framework_controls[m.output_key] for m in frameworks if m.scored]
    status_totals = [_count_statuses(fw) for fw in all_frameworks]
    total_pass = sum(s[0] for s in status_totals)
    total_warn = sum(s[1] for s in status_totals)
    total_fail = sum(s[2] for s in status_totals)

    # AISVS folds in on exactly the same grounds as CIS Foundations: both are
    # DIRECTLY EVALUATED checks, not CVE-tag inferences, so both are real
    # evidence about the estate. Leaving AISVS out was invisible only while
    # ``pass`` was unreachable and every such estate read ``no_data`` anyway;
    # once a scan can legitimately pass its detective controls, an excluded
    # failing AISVS check buys a "100% Compliant" headline over a known
    # failure. AISVS is not in TAG_MAPPED_FRAMEWORKS, so this cannot
    # double-count.
    bench_pass = int(cis_foundations_agg["counts"]["pass"]) + int(aisvs_summary["pass"])
    bench_fail = int(cis_foundations_agg["counts"]["fail"]) + int(aisvs_summary["fail"])
    bench_error = int(cis_foundations_agg["counts"]["error"]) + int(aisvs_summary["error"])

    # A detective pass only establishes that we scan — it is evidence about the
    # monitoring program, not about whether the estate meets a framework. An
    # estate whose ONLY passing evidence is "a scan ran" has not been shown to
    # be compliant, so it reports no_data rather than a green headline. Without
    # this, a fresh scan over an estate with nothing gradeable rendered
    # "100% / Compliant" — the same false green that pinning the score at 0 was
    # originally (wrongly) papering over.
    detective_passes = sum(
        1 for controls_list in all_frameworks for c in controls_list if c.get("evaluation_mode") == MODE_DETECTIVE and c["status"] == "pass"
    )

    # Score over EVALUATED controls/checks only (CVE controls with mapped
    # findings + benchmark pass/fail/error). ONE derivation of status + score,
    # shared with the per-framework route, the MCP tool, the HTML report and
    # the evidence bundle. With zero completed scans nothing is measurable at
    # all, which ``has_evidence`` carries.
    return score_compliance(
        passed=total_pass + bench_pass,
        warned=total_warn,
        failed=total_fail + bench_fail,
        errored=bench_error,
        detective_passes=detective_passes,
        has_evidence=scan_count > 0,
    )


def _framework_status_summary(
    framework_controls: dict[str, list[dict]],
    frameworks: Iterable[Any],
    aisvs_summary: dict[str, Any],
    cis_foundations_line: dict[str, Any],
    nist_800_53_catalog_line: dict[str, Any],
) -> dict[str, int | float]:
    summary: dict[str, int | float] = {}
    for metadata in frameworks:
        controls_list = framework_controls[metadata.output_key]
        if not metadata.scored:
            # An overlay has no pass/warn/fail to report. Emitting zeroed
            # ``*_pass``/``*_fail`` keys would read as "0 passing controls" for
            # something that has no controls at all, so report applicability.
            applicable = sum(1 for c in controls_list if c["status"] == "applicable")
            summary[f"{metadata.summary_prefix}_applicable"] = applicable
            summary[f"{metadata.summary_prefix}_not_applicable"] = len(controls_list) - applicable
            continue
        passed, warned, failed = _count_statuses(controls_list)
        summary[f"{metadata.summary_prefix}_pass"] = passed
        summary[f"{metadata.summary_prefix}_warn"] = warned
        summary[f"{metadata.summary_prefix}_fail"] = failed
        # Controls with no mapped findings are not_evaluated (not_assessed on a
        # zero-scan estate) — surface the count so consumers can tell an
        # unevaluated control apart from a passing one.
        not_evaluated = len(controls_list) - passed - warned - failed
        if not_evaluated:
            summary[f"{metadata.summary_prefix}_not_evaluated"] = not_evaluated
    summary.update(
        {
            "aisvs_pass": aisvs_summary["pass"],
            "aisvs_fail": aisvs_summary["fail"],
            "aisvs_error": aisvs_summary["error"],
            "aisvs_not_applicable": aisvs_summary["not_applicable"],
            "cis_foundations_pass": cis_foundations_line["summary"]["pass"],
            "cis_foundations_fail": cis_foundations_line["summary"]["fail"],
            "cis_foundations_error": cis_foundations_line["summary"]["error"],
            "cis_foundations_not_applicable": cis_foundations_line["summary"]["not_applicable"],
            "cis_foundations_evaluated": cis_foundations_line["summary"]["evaluated"],
            "nist_800_53_catalog_pass": nist_800_53_catalog_line["summary"]["pass"],
            "nist_800_53_catalog_fail": nist_800_53_catalog_line["summary"]["fail"],
            "nist_800_53_catalog_warning": nist_800_53_catalog_line["summary"]["warning"],
            "nist_800_53_catalog_error": nist_800_53_catalog_line["summary"]["error"],
            "nist_800_53_catalog_evaluated": nist_800_53_catalog_line["summary"]["evaluated"],
            "nist_800_53_catalog_not_evaluated": nist_800_53_catalog_line["summary"]["not_evaluated"],
        }
    )
    return summary


def _control_status_counts(value: list[object]) -> tuple[int, int, int, int] | None:
    controls = [item for item in value if isinstance(item, dict) and isinstance(item.get("status"), str)]
    if not controls:
        return None
    pass_count = sum(1 for item in controls if item.get("status") == "pass")
    warn_count = sum(1 for item in controls if item.get("status") == "warning")
    fail_count = sum(1 for item in controls if item.get("status") == "fail")
    return len(controls), pass_count, warn_count, fail_count


def _framework_summary_from(full: dict[str, Any], overlay_keys: set[str], no_data: bool) -> dict[str, dict[str, int | None]]:
    framework_summary: dict[str, dict[str, int | None]] = {}
    for key, value in full.items():
        if isinstance(value, list):
            counts = _control_status_counts(value)
            if counts is None:
                continue
            controls, pass_count, warn_count, fail_count = counts
            if key in overlay_keys:
                # An applicability overlay has no pass/warn/fail. Emitting zeros
                # would read as "0 of N passing"; report applicability instead.
                applicable = sum(1 for item in value if isinstance(item, dict) and item.get("status") == "applicable")
                framework_summary[key] = {
                    "controls": controls,
                    "scored": False,
                    "applicable": 0 if no_data else applicable,
                    "not_applicable": controls if no_data else controls - applicable,
                }
                continue
            if no_data:
                pass_count = warn_count = fail_count = 0
            framework_summary[key] = {
                "controls": controls,
                "scored": True,
                "pass": pass_count,
                "warning": warn_count,
                "fail": fail_count,
                "not_evaluated": controls - pass_count - warn_count - fail_count,
            }
    return framework_summary


def _framework_posture(framework: str, controls: list[dict], *, no_data: bool) -> dict[str, Any]:
    pass_count = sum(1 for c in controls if c["status"] == "pass")
    warn_count = sum(1 for c in controls if c["status"] == "warning")
    fail_count = sum(1 for c in controls if c["status"] == "fail")

    if no_data or not controls:
        pass_count = warn_count = fail_count = 0

    # Same scorer as the aggregate. The hand-rolled chain this replaces —
    # ``"fail" if fail_count else "warning" if warn_count else "pass"`` — fell
    # through to "pass" whenever all three counts were 0, so a framework that
    # was never evaluated (SOC 2 on a zero-finding estate: pass 0, warning 0,
    # fail 0) reported a passing status, and a framework whose only passes were
    # detective (CSF, CIS) reported a pass with a real score.
    detective_passes = sum(1 for c in controls if c.get("evaluation_mode") == MODE_DETECTIVE and c["status"] == "pass")
    verdict = score_compliance(
        passed=pass_count,
        warned=warn_count,
        failed=fail_count,
        detective_passes=0 if no_data or not controls else detective_passes,
        has_evidence=not no_data and bool(controls),
    )

    return {
        "framework": framework,
        "status": verdict.status,
        "controls": controls,
        "summary": {"pass": pass_count, "warning": warn_count, "fail": fail_count},
        "score": verdict.score,
        # The score is a percentage of EVALUATED controls, never of the whole
        # catalogue — it does not travel without its denominator.
        "evaluated_controls": verdict.evaluated,
        "total_controls": len(controls),
    }
