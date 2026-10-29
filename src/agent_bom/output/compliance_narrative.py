"""Compliance narrative generator — review-ready stories from scan data.

Produces human-readable compliance narratives from AIBOMReport data without
requiring an LLM.  Uses template strings and structured data from blast_radius
entries to generate executive summaries, per-framework stories, and
remediation-compliance bridges.

Supported frameworks (slug → display name):
    owasp-llm         OWASP Top 10 for LLM
    owasp-mcp         OWASP MCP Top 10
    owasp-agentic     OWASP Agentic Top 10
    nist-800-53       NIST SP 800-53
    fedramp           FedRAMP Moderate
    atlas             MITRE ATLAS
    attack            MITRE ATT&CK Enterprise
    nist              NIST AI RMF
    eu-ai-act         EU AI Act
    nist-csf          NIST CSF 2.0
    iso-27001         ISO 27001:2022
    soc2              SOC 2 TSC
    cis               CIS Controls v8
    cmmc              CMMC 2.0
    pci-dss           PCI DSS v4.0
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

from agent_bom.core.severity import evaluated_control_status as _control_status

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport

from agent_bom.compliance_coverage import (
    COMPLIANCE_TAG_FIELDS,
    FRAMEWORK_SLUG_ALIASES,
    control_key_for_tag,
    normalize_framework_slug,
)
from agent_bom.evidence.control_modes import DETECTIVE_CONTROLS
from agent_bom.evidence.detective_evidence import DetectiveScanEvidence
from agent_bom.output.compliance_narrative_findings import blast_radii_from_finding_rows as blast_radii_from_finding_rows
from agent_bom.output.compliance_narrative_models import COMPLIANCE_CLAIM_BOUNDARY as COMPLIANCE_CLAIM_BOUNDARY
from agent_bom.output.compliance_narrative_models import ComplianceNarrative as ComplianceNarrative
from agent_bom.output.compliance_narrative_models import ControlNarrative as ControlNarrative
from agent_bom.output.compliance_narrative_models import FrameworkNarrative as FrameworkNarrative
from agent_bom.output.compliance_narrative_models import RemediationImpact as RemediationImpact
from agent_bom.output.compliance_narrative_templates import (
    _build_executive_summary,
    _build_risk_narrative,
    _control_narrative,
    _control_remediation_steps,
    _detective_control_narrative,
    _detective_remediation_steps,
    _framework_overall_narrative,
)

# ─── Catalogue lookups ────────────────────────────────────────────────────────
# Imported lazily where needed to keep top-level import cost low.

_DISPLAY_NAME_OVERRIDES: dict[str, str] = {
    "owasp-llm": "OWASP Top 10 for LLM",
    "owasp-mcp": "OWASP MCP Top 10",
    "owasp-agentic": "OWASP Agentic Top 10",
    "nist": "NIST AI RMF",
    "nist-csf": "NIST CSF 2.0",
    "nist-800-53": "NIST 800-53",
    "fedramp": "FedRAMP",
    "atlas": "MITRE ATLAS",
    "attack": "MITRE ATT&CK",
    "iso-27001": "ISO 27001:2022",
    "soc2": "SOC 2 TSC",
    "cis": "CIS Controls v8",
    "cmmc": "CMMC 2.0",
}


def _get_catalog(slug: str) -> tuple[dict[str, str], str, str]:
    """Return (catalog_dict, tag_field_on_blast_radius, display_name) for a framework slug."""
    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS, scoring_catalog

    for metadata in TAG_MAPPED_FRAMEWORKS:
        if metadata.slug == slug:
            display_name = _DISPLAY_NAME_OVERRIDES.get(metadata.slug, metadata.report_label)
            return scoring_catalog(metadata), metadata.tag_field, display_name
    raise ValueError(f"Unknown framework '{slug}'. Supported: {', '.join(m.slug for m in TAG_MAPPED_FRAMEWORKS)}")


def _all_framework_slugs() -> list[str]:
    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS

    return [metadata.slug for metadata in TAG_MAPPED_FRAMEWORKS]


ALL_FRAMEWORK_SLUGS: list[str] = _all_framework_slugs()
ACCEPTED_FRAMEWORK_SLUGS: list[str] = [*ALL_FRAMEWORK_SLUGS, *FRAMEWORK_SLUG_ALIASES]


def _signing_caveat() -> str:
    """Qualify "export a signed bundle" when this deployment's signer is ephemeral.

    Recommending auditor submission is only honest when the signature can be
    checked. A default deployment signs with a per-process HMAC key, so the
    recommendation has to carry that fact rather than imply verifiable evidence.
    """
    from agent_bom.api.compliance_signing import describe_signer_disclosure

    disclosure = describe_signer_disclosure()
    if disclosure.signature_verifiable:
        return ""
    return (
        " Note: this deployment currently signs with a per-process key, so the bundle's signature cannot be verified "
        "by an auditor — or by this deployment after a restart. Set AGENT_BOM_AUDIT_HMAC_KEY, or "
        "AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM for auditor-distributable signing, and re-export before "
        "submitting."
    )


def _framework_recommendations(
    display_name: str,
    slug: str,
    fail_count: int,
    warn_count: int,
    failing_controls: list[ControlNarrative],
) -> list[str]:
    """Generate 2-4 actionable framework-level recommendations."""
    recs: list[str] = []
    if fail_count:
        recs.append(
            f"Review and remediate all critical/high findings mapped to {display_name} before the next audit window; "
            "validate control operation with independent evidence."
        )
    if warn_count:
        recs.append(f"Schedule remediation for {display_name} warning-state controls within the next sprint or maintenance cycle.")
    if failing_controls:
        top_pkgs: list[str] = []
        for ctrl in failing_controls[:3]:
            top_pkgs.extend(ctrl.affected_packages[:2])
        if top_pkgs:
            recs.append(f"Prioritise upgrades to: {', '.join(dict.fromkeys(top_pkgs))}")
    recs.append(
        f"Export a signed {display_name} evidence bundle from the compliance API "
        f"(`GET /v1/compliance/{slug}/report`, or the all-framework pack at "
        "`GET /v1/compliance/report/pack`) for auditor submission." + _signing_caveat()
    )
    return recs


# ─── Per-framework builder ────────────────────────────────────────────────────


def _collect_control_findings(catalog: dict[str, str], tag_field: str, blast_radii_dicts: list[dict]) -> dict[str, dict]:
    control_data: dict[str, dict] = {}
    for code, name in catalog.items():
        control_data[code] = {
            "name": name,
            "findings": 0,
            "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "affected_pkgs": set(),
            "affected_agents": set(),
            "affected_findings": set(),
        }

    for br in blast_radii_dicts:
        tags = br.get(tag_field, [])
        sev = (br.get("severity") or "").lower()
        pkg = br.get("package", "")
        agents = br.get("affected_agents", [])
        vuln_id = br.get("vulnerability_id") or ""
        for tag in tags:
            control_id = control_key_for_tag(tag, catalog)
            if control_id is None:
                continue
            entry = control_data[control_id]
            entry["findings"] += 1
            if sev in entry["severity_breakdown"]:
                entry["severity_breakdown"][sev] += 1
            if pkg:
                entry["affected_pkgs"].add(pkg)
            if vuln_id:
                entry["affected_findings"].add(vuln_id)
            for agent in agents:
                entry["affected_agents"].add(agent)
    return control_data


def _build_framework_narrative(
    slug: str,
    blast_radii_dicts: list[dict],
    *,
    scan_evidence: DetectiveScanEvidence = DetectiveScanEvidence(),
) -> FrameworkNarrative:
    """Build a FrameworkNarrative for a single framework from pre-serialised blast radius data.

    ``scan_evidence`` carries the scan evidence detective controls are scored
    from — see :func:`_build_framework_narrative`'s detective branch and
    :mod:`agent_bom.evidence.control_modes`.
    """
    catalog, tag_field, display_name = _get_catalog(slug)
    detective_ids = DETECTIVE_CONTROLS.get(tag_field, frozenset())

    control_data = _collect_control_findings(catalog, tag_field, blast_radii_dicts)

    total_controls = len(control_data)
    evaluated_count = 0
    pass_count = 0
    warn_count = 0
    fail_count = 0
    failing_controls: list[ControlNarrative] = []
    critical_failing_ids: list[str] = []

    for code, data in sorted(control_data.items()):
        if code in detective_ids:
            # The scan IS this control operating ("monitor and scan for
            # vulnerabilities", "maintain a component inventory"). Findings are
            # never tagged onto it, so the zero-mapped-findings skip below
            # dropped it from the narrative entirely instead of reporting the
            # pass it earned. Score it from evidence freshness, like the API.
            status, _reason = scan_evidence.control_status(tag_field, code)
            if status == "not_assessed":
                # No completed scan, or a partial vulnerability lane: the
                # control is not asserted in either direction.
                continue
            evaluated_count += 1
            if status == "pass":
                pass_count += 1
                continue
            fail_count += 1
            critical_failing_ids.append(code)
            failing_controls.append(
                ControlNarrative(
                    control_id=code,
                    title=data["name"],
                    status=status,
                    narrative=_detective_control_narrative(code, data["name"], status),
                    remediation_steps=_detective_remediation_steps(code, data["name"]),
                )
            )
            continue

        # A control is only "evaluated" when at least one finding maps to it.
        # Controls with zero mapped findings carry no vulnerability-derived
        # evidence, so they are not-evaluated — never counted as a silent pass.
        if data["findings"] == 0:
            continue
        status = _control_status(data["severity_breakdown"])
        if status == "not_evaluated":
            # Findings map here but all are unrated-severity: evidence exists but
            # severity is ungraded, so it is not an evaluated pass/warn/fail — it
            # must not inflate the denominator or read as a silent pass. Mirrors
            # the API excluding not_evaluated controls from evaluated_controls.
            continue
        evaluated_count += 1
        pkgs = sorted(data["affected_pkgs"])
        agents = sorted(data["affected_agents"])

        if status == "pass":
            pass_count += 1
        elif status == "warning":
            warn_count += 1
        else:
            fail_count += 1
            critical_failing_ids.append(code)

        if status in ("warning", "fail"):
            failing_controls.append(
                ControlNarrative(
                    control_id=code,
                    title=data["name"],
                    status=status,
                    narrative=_control_narrative(code, data["name"], data["findings"], pkgs, agents, data["severity_breakdown"]),
                    affected_packages=pkgs,
                    affected_agents=agents,
                    affected_findings=sorted(data["affected_findings"]),
                    remediation_steps=_control_remediation_steps(code, data["name"], pkgs, data["severity_breakdown"]),
                )
            )

    # Score over EVALUATED controls only. With nothing evaluated there is no
    # evidence, so the score is 0 (not 100) and the status is not_evaluated —
    # an empty scan must never read as "fully compliant".
    score = round((pass_count / evaluated_count) * 100) if evaluated_count > 0 else 0

    if evaluated_count == 0:
        fw_status = "not_evaluated"
    elif fail_count > 0:
        fw_status = "action_required"
    elif warn_count > 0:
        fw_status = "review"
    else:
        fw_status = "evidence_current"

    narrative = _framework_overall_narrative(
        display_name, total_controls, evaluated_count, pass_count, fail_count, warn_count, critical_failing_ids, score
    )
    recommendations = _framework_recommendations(display_name, slug, fail_count, warn_count, failing_controls)

    return FrameworkNarrative(
        framework=display_name,
        slug=slug,
        status=fw_status,
        score=score,
        narrative=narrative,
        failing_controls=failing_controls,
        recommendations=recommendations,
    )


# ─── Remediation-compliance bridge ───────────────────────────────────────────


def _build_remediation_impact(
    blast_radii_dicts: list[dict],
    framework_slug: str | None = None,
) -> list[RemediationImpact]:
    """Cross-reference fix versions with control tags to build RemediationImpact entries.

    Groups blast radius entries by (package, current_version, fix_version),
    collects framework control codes triggered, and generates a narrative.

    When ``framework_slug`` is set, only that framework's controls are listed —
    so a single-framework report (e.g. ``--framework soc2``) doesn't bleed ISO /
    NIST / EU-AI-Act control IDs into its remediation section.
    """
    from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS

    field_to_framework = {
        metadata.tag_field: _DISPLAY_NAME_OVERRIDES.get(metadata.slug, metadata.report_label) for metadata in TAG_MAPPED_FRAMEWORKS
    }
    if framework_slug:
        try:
            _catalog, tag_field, display_name = _get_catalog(framework_slug)
            field_to_framework = {tag_field: display_name}
        except ValueError:
            pass  # unknown slug — fall back to all frameworks

    # Group: key = (pkg_name_version, fix_version)
    # value = {controls: set, frameworks: set}
    groups: dict[tuple[str, str], dict] = {}

    for br in blast_radii_dicts:
        # A hardcoded secret or a code flaw is not fixed by a package upgrade;
        # its remediation lives on the finding, not in this bridge.
        if (br.get("finding_type") or "CVE") != "CVE":
            continue
        raw_pkg = br.get("package", "")  # "name@version" format from json_fmt
        fix_ver = br.get("fixed_version") or ""

        # Extract current version from "name@version" string
        if "@" in raw_pkg:
            pkg_name, current_ver = raw_pkg.rsplit("@", 1)
        else:
            pkg_name = raw_pkg
            current_ver = ""

        key = (f"{pkg_name}@{current_ver}", fix_ver)
        if key not in groups:
            groups[key] = {
                "pkg_name": pkg_name,
                "current_ver": current_ver,
                "fix_ver": fix_ver,
                "controls": set(),
                "frameworks": set(),
            }

        for tag_field, framework_label in field_to_framework.items():
            for tag in br.get(tag_field, []):
                groups[key]["controls"].add(tag)
                groups[key]["frameworks"].add(framework_label)

    impacts: list[RemediationImpact] = []
    for _key, data in groups.items():
        controls = sorted(data["controls"])
        frameworks = sorted(data["frameworks"])
        if not controls:
            continue  # skip entries with no compliance tags

        pkg_name = data["pkg_name"]
        current_ver = data["current_ver"]
        fix_ver = data["fix_ver"]

        if fix_ver:
            ctrl_str = ", ".join(controls[:5])
            if len(controls) > 5:
                ctrl_str += f" and {len(controls) - 5} more"
            narrative = f"Upgrading {pkg_name} from {current_ver} to {fix_ver} resolves compliance findings for controls: {ctrl_str}."
        else:
            ctrl_str = ", ".join(controls[:5])
            narrative = (
                f"{pkg_name} {current_ver} has no fix available. "
                f"Controls affected: {ctrl_str}. "
                "Consider a mitigating control or package replacement."
            )

        impacts.append(
            RemediationImpact(
                package=pkg_name,
                current_version=current_ver,
                fix_version=fix_ver,
                controls_fixed=controls,
                frameworks_impacted=frameworks,
                narrative=narrative,
            )
        )

    # Sort by number of controls fixed (most impactful first)
    impacts.sort(key=lambda x: len(x.controls_fixed), reverse=True)
    return impacts


def _headline_title(row: Mapping[str, object]) -> str:
    vulnerability_id = str(row.get("vulnerability_id") or "Unavailable")
    if row.get("finding_type") == "CVE" and row.get("package"):
        return f"{vulnerability_id} in {row['package']}"
    return vulnerability_id


# ─── Public API ───────────────────────────────────────────────────────────────


def generate_compliance_narrative(
    report: "AIBOMReport",
    framework: str | None = None,
    *,
    finding_label: str = "vulnerability",
) -> ComplianceNarrative:
    """Generate review-ready compliance narrative from scan results.

    Args:
        report: The AIBOMReport to analyse.
        framework: Optional framework slug to generate a single-framework
            narrative.  When None (default), all frameworks are included.
            Supported slugs are the tag-mapped slugs in
            agent_bom.compliance_coverage.TAG_MAPPED_FRAMEWORKS.

    Returns:
        A ComplianceNarrative dataclass suitable for JSON serialisation.

    Raises:
        ValueError: If an unknown framework slug is provided.
    """
    # Validate slug early so we fail fast before any computation
    if framework is not None:
        framework = normalize_framework_slug(framework)
        _get_catalog(framework)  # raises ValueError for unknown slugs

    # Build a lightweight list-of-dicts from blast_radii (avoids re-importing models)
    blast_dicts: list[dict] = []
    for br in report.blast_radii:
        blast_dicts.append(
            {
                "vulnerability_id": br.vulnerability.id,
                "severity": br.vulnerability.severity.value,
                "package": f"{br.package.name}@{br.package.version}" if br.package.version else br.package.name,
                "fixed_version": br.vulnerability.fixed_version,
                "risk_score": br.risk_score,
                "is_kev": br.vulnerability.is_kev,
                "affected_agents": [a.name for a in br.affected_agents],
                "affected_servers": [s.name for s in br.affected_servers],
                "exposed_credentials": br.exposed_credentials,
                "finding_type": getattr(br, "finding_type", None) or "CVE",
                "cwe_ids": list(getattr(br.vulnerability, "cwe_ids", None) or []),
                "title": getattr(br, "title", None),
                "owner": getattr(br, "owner", None),
                "sla_due_at": getattr(br, "sla_due_at", None),
                **{field: list(getattr(br, field, []) or []) for field in COMPLIANCE_TAG_FIELDS},
            }
        )

    slugs = [framework] if framework is not None else ALL_FRAMEWORK_SLUGS

    # Scan evidence for detective controls, derived the same conservative way as
    # the nist_800_53_catalog line below (see ``DetectiveScanEvidence.for_report``).
    scan_evidence = DetectiveScanEvidence.for_report(report, has_findings=bool(blast_dicts))

    framework_narratives: list[FrameworkNarrative] = [
        _build_framework_narrative(slug, blast_dicts, scan_evidence=scan_evidence) for slug in slugs
    ]

    remediation_impact = _build_remediation_impact(blast_dicts, framework)

    total_vulns = len(blast_dicts)
    critical_count = sum(1 for b in blast_dicts if (b.get("severity") or "") == "critical")

    generated_at = datetime.now(timezone.utc).isoformat()

    risk_narrative = _build_risk_narrative(
        blast_dicts,
        total_agents=report.total_agents,
        total_vulns=total_vulns,
        critical_count=critical_count,
        finding_label=finding_label,
    )

    executive_summary = _build_executive_summary(
        framework_narratives=framework_narratives,
        total_agents=report.total_agents,
        total_packages=report.total_packages,
        total_vulns=total_vulns,
        critical_count=critical_count,
        generated_at=scan_evidence.latest_scan or generated_at,
        finding_label=finding_label,
    )

    # Catalog-backed NIST 800-53 line (vendor-asserted, scored over evaluated
    # controls only). The narrative path has no CIS Foundations checks, so CIS
    # statuses are empty; scan_count is 1 when the report carries findings (a
    # scan ran) so an unmapped estate reads no_data, never a false pass. Included
    # for the full narrative and the nist-800-53 single-framework narrative only.
    nist_800_53_catalog: dict = {}
    if framework is None or framework == "nist-800-53":
        from agent_bom.compliance_nist_catalog import build_nist_800_53_catalog_line

        nist_800_53_catalog = build_nist_800_53_catalog_line(blast_dicts, {}, 1 if blast_dicts else 0)

    from agent_bom.output.executive_headline import build_executive_headline

    headline = build_executive_headline(
        {
            **{key: b.get(key) for key in ("severity", "risk_score", "affected_agents", "owner", "sla_due_at", "suppressed")},
            "id": b["vulnerability_id"],
            "title": b.get("title") or _headline_title(b),
        }
        for b in blast_dicts
    )

    return ComplianceNarrative(
        executive_summary=executive_summary,
        framework_narratives=framework_narratives,
        remediation_impact=remediation_impact,
        risk_narrative=risk_narrative,
        generated_at=generated_at,
        claim_boundary=COMPLIANCE_CLAIM_BOUNDARY,
        nist_800_53_catalog=nist_800_53_catalog,
        executive_headline=asdict(headline),
    )


def generate_compliance_narrative_from_findings(
    findings: list[Mapping[str, object]],
    *,
    total_agents: int,
    total_packages: int,
    generated_at: str | None = None,
    framework: str | None = None,
) -> ComplianceNarrative:
    """Generate the narrative from the canonical persisted finding stream.

    The control plane stores complete unified findings, not Python model
    instances. Re-running a scanner or padding a model with ``agent-0`` and
    ``pkg-0`` placeholders makes the narrative answer a different question from
    the finding queue. This adapter preserves each persisted finding and its
    control mappings, then reuses the established narrative calculation.
    """
    blast_radii = blast_radii_from_finding_rows(findings)

    observed_at: datetime | None = None
    if generated_at:
        try:
            observed_at = datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
        except ValueError:
            observed_at = None
    report = cast(
        "AIBOMReport",
        SimpleNamespace(
            blast_radii=blast_radii,
            total_agents=max(0, int(total_agents)),
            total_packages=max(0, int(total_packages)),
            generated_at=observed_at,
        ),
    )
    return generate_compliance_narrative(report, framework=framework, finding_label="security finding")
