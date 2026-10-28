"""Unified finding model and source-specific evidence projections."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_bom.advisory_ids import vulnerability_enrichment_metadata
from agent_bom.canonical_ids import agent_graph_id_for, mcp_server_graph_id_for
from agent_bom.core.exploitability import fused_triage_priority
from agent_bom.core.packages import synthesize_purl
from agent_bom.core.severity import severity_basis
from agent_bom.core.versions.prerelease_fix import upgrade_remediation
from agent_bom.domain.finding_model import Asset as Asset
from agent_bom.domain.finding_model import Finding as Finding
from agent_bom.domain.finding_types import _CIS_BENCHMARK_FRAMEWORKS as _CIS_BENCHMARK_FRAMEWORKS
from agent_bom.domain.finding_types import _LEGACY_CONTROL_VERSION_BY_FRAMEWORK as _LEGACY_CONTROL_VERSION_BY_FRAMEWORK
from agent_bom.domain.finding_types import _OCCURRENCE_EVIDENCE_KEYS as _OCCURRENCE_EVIDENCE_KEYS
from agent_bom.domain.finding_types import EXTERNAL_SOURCE_PREFIX as EXTERNAL_SOURCE_PREFIX
from agent_bom.domain.finding_types import FINDING_SCHEMA_VERSION as FINDING_SCHEMA_VERSION
from agent_bom.domain.finding_types import LEGACY_CONTROL_FIELDS as LEGACY_CONTROL_FIELDS
from agent_bom.domain.finding_types import ControlTag as ControlTag
from agent_bom.domain.finding_types import FindingSource as FindingSource
from agent_bom.domain.finding_types import FindingType as FindingType
from agent_bom.domain.finding_types import _control_tag_from_compliance_tag as _control_tag_from_compliance_tag
from agent_bom.domain.finding_types import _dedupe_control_tags as _dedupe_control_tags
from agent_bom.domain.finding_types import _occurrence_evidence_qualifier as _occurrence_evidence_qualifier
from agent_bom.domain.finding_types import _stable_id as _stable_id
from agent_bom.domain.finding_types import stable_id as stable_id

if TYPE_CHECKING:
    from collections.abc import Callable


# Provenance label prefix for evidence imported from an external scanner report.


from agent_bom.domain.finding_evidence import _evidence_key_looks_like_path as _evidence_key_looks_like_path
from agent_bom.domain.finding_evidence import _evidence_key_looks_like_url as _evidence_key_looks_like_url
from agent_bom.domain.finding_evidence import _evidence_key_looks_sensitive as _evidence_key_looks_sensitive
from agent_bom.domain.finding_evidence import _evidence_payload as _evidence_payload
from agent_bom.domain.finding_evidence import _package_occurrence_evidence as _package_occurrence_evidence
from agent_bom.domain.finding_evidence import _sanitized_evidence_field as _sanitized_evidence_field
from agent_bom.domain.finding_evidence import _sanitized_evidence_value as _sanitized_evidence_value


def _source_for_blast_radius(br: object) -> FindingSource:
    """Derive finding source from the actual affected surface.

    Generic package/image/SBOM findings should not inherit MCP/AI framework
    applicability just because they flowed through the blast-radius shim.
    """
    surfaces = [getattr(server, "surface", None) for server in getattr(br, "affected_servers", []) or []]
    surface_values = {getattr(surface, "value", str(surface)) for surface in surfaces if surface is not None}
    if any(getattr(server, "is_mcp_surface", False) for server in getattr(br, "affected_servers", []) or []):
        return FindingSource.MCP_SCAN
    if {"container-image", "oci-tarball"} & surface_values:
        return FindingSource.CONTAINER
    if "filesystem" in surface_values:
        return FindingSource.FILESYSTEM
    native_surfaces = surface_values - {"external-scan"}
    if "external-scan" in surface_values and not native_surfaces:
        return FindingSource.EXTERNAL
    if "sast" in surface_values:
        return FindingSource.SAST
    if {"sbom", "os-packages"} & surface_values:
        return FindingSource.SBOM
    return FindingSource.SBOM


def _provenance_labels_for_blast_radius(br: object) -> list[str]:
    """Return producer labels when external evidence contributed to a finding.

    Native-only findings return an empty list so their payload shape is
    unchanged; any external contribution keeps both the native label and the
    external tool label instead of relabelling the finding as external.
    """
    surfaces = {
        str(getattr(getattr(server, "surface", None), "value", getattr(server, "surface", "")) or "")
        for server in getattr(br, "affected_servers", []) or []
    }
    vuln = getattr(br, "vulnerability", None)
    external_labels = [str(label) for label in getattr(vuln, "advisory_sources", []) or [] if str(label).startswith(EXTERNAL_SOURCE_PREFIX)]
    has_external_surface = "external-scan" in surfaces
    if not external_labels and not has_external_surface:
        return []
    labels: list[str] = []
    if surfaces - {"external-scan", ""}:
        labels.append("native")
    labels.extend(external_labels or ["external"])
    return labels


def _remediation_guidance_for_vulnerability(vuln: object, pkg: object) -> str:
    """Return actionable guidance for vulnerability findings.

    Some upstream parsers attach explicit remediation text dynamically. When
    they do not, derive a conservative fix from the normalized vulnerability
    model so JSON/SARIF/API consumers do not receive a null remediation field
    for fixable CVEs.
    """
    explicit = getattr(vuln, "remediation", None) or getattr(vuln, "recommendation", None)
    if isinstance(explicit, str) and explicit.strip():
        return explicit.strip()

    package_name = getattr(pkg, "name", "the affected package") or "the affected package"
    if getattr(pkg, "is_malicious", False):
        reason = getattr(pkg, "malicious_reason", None)
        detail = f" ({reason})" if isinstance(reason, str) and reason.strip() else ""
        return f"Remove {package_name} from all environments immediately{detail}."

    ecosystem = getattr(pkg, "ecosystem", None)
    fixed_version = _forward_fixed_version(getattr(vuln, "fixed_version", None), getattr(pkg, "version", None), ecosystem)
    if isinstance(fixed_version, str) and fixed_version.strip():
        return upgrade_remediation(package_name, fixed_version.strip(), ecosystem, bool(getattr(vuln, "fix_is_prerelease", False)))

    vuln_id = getattr(vuln, "id", None)
    if getattr(vuln, "is_kev", False):
        cve_context = f" {vuln_id}" if vuln_id else ""
        return f"Prioritize vendor mitigation for{cve_context}; it is listed in CISA KEV and no fixed version is recorded."

    references = getattr(vuln, "references", None) or []
    if references:
        return "Review the linked advisory references and apply the vendor-recommended mitigation or upgrade path."
    return "Review the advisory and apply the vendor-recommended mitigation, upgrade path, or compensating control."


def _forward_fixed_version(fixed_version: str | None, current_version: str | None, ecosystem: str | None) -> str | None:
    """Return ``fixed_version`` only when it is a forward upgrade for ``current_version``."""
    if not isinstance(fixed_version, str) or not fixed_version.strip():
        return None
    fixed = fixed_version.strip()
    current = (current_version or "").strip()
    if not current:
        return fixed
    from agent_bom.version_utils import compare_versions

    eco = (ecosystem or "").strip()
    if compare_versions(current, fixed, eco):
        return fixed
    return None


def _safe_secret_preview(value: object) -> str:
    """Return a display-only secret preview that cannot carry raw secret bytes."""
    from agent_bom.security import sanitize_text

    preview = sanitize_text(value, max_len=160).strip()
    if not preview:
        return "***REDACTED***"
    lowered = preview.lower()
    if "redact" in lowered or "***" in preview or "[secret_" in lowered or "[credential_" in lowered or "[pii_" in lowered:
        return preview
    return "***REDACTED***"


_AST_FLOW_CRITICAL_MARKERS = ("command_execution", "unsafe_deserialization", "dynamic_code_execution")
_AST_FLOW_HIGH_MARKERS = (
    "credential_file_access",
    "dangerous",
    "unguarded_tool_sink",
    "command_string",
    "dynamic_require",
    "path_access",
    "path_traversal",
    "privilege_escalation",
    "sql",
    "ssrf",
    "xss",
)
_AST_SECURITY_FLOW_MARKERS = (*_AST_FLOW_CRITICAL_MARKERS, *_AST_FLOW_HIGH_MARKERS)
_AST_FLOW_CWE_BY_MARKER = {
    "command_execution": "CWE-78",
    "unsafe_deserialization": "CWE-502",
    "path_access": "CWE-22",
    "path_traversal": "CWE-22",
    "sql": "CWE-89",
    "ssrf": "CWE-918",
    "xss": "CWE-79",
}


def is_ast_security_flow(raw: dict) -> bool:
    """Return whether an AST side-block row represents a security risk."""
    from agent_bom.security import sanitize_text

    category = sanitize_text(raw.get("category", "") or "", max_len=120).lower()
    return any(marker in category for marker in _AST_SECURITY_FLOW_MARKERS)


def ast_flow_dict_to_finding(raw: dict) -> "Finding":
    """Promote one native AST flow result into the unified finding stream."""
    from agent_bom.security import sanitize_text

    category = sanitize_text(raw.get("category", "ast_flow") or "ast_flow", max_len=120).lower()
    file_path = sanitize_text(raw.get("file", "") or "", max_len=500)
    entrypoint = sanitize_text(raw.get("entrypoint", "") or "", max_len=200)
    sink = sanitize_text(raw.get("sink", "") or "", max_len=200)
    raw_line = raw.get("line")
    line = raw_line if isinstance(raw_line, int) and raw_line > 0 else 1
    severity = "critical" if any(marker in category for marker in _AST_FLOW_CRITICAL_MARKERS) else "high"
    if not any(marker in category for marker in _AST_SECURITY_FLOW_MARKERS):
        severity = "medium"
    cwe_ids = sorted({cwe for marker, cwe in _AST_FLOW_CWE_BY_MARKER.items() if marker in category})
    title = sanitize_text(raw.get("title", "") or f"Unsafe flow reaches {sink or 'a sensitive sink'}", max_len=300)
    detail = sanitize_text(raw.get("detail", "") or title, max_len=2_000)
    call_path = [sanitize_text(item, max_len=200) for item in raw.get("call_path", []) if isinstance(item, str)][:20]

    finding = Finding(
        finding_type=FindingType.SAST,
        source=FindingSource.SAST,
        asset=Asset(
            name=f"{entrypoint or sink or category} in {file_path}" if file_path else entrypoint or sink or category,
            asset_type="source_file",
            identifier=file_path or None,
            location=file_path or None,
        ),
        severity=severity,
        title=title,
        description=detail,
        cwe_ids=cwe_ids,
        remediation_guidance=(
            "Validate and constrain tool-controlled input before it reaches the sensitive sink; "
            "prefer structured APIs over shell, path, query, or deserialization string construction."
        ),
        evidence={
            "category": category,
            "file": file_path,
            "line": line,
            "entrypoint": entrypoint,
            "sink": sink,
            "source": sanitize_text(raw.get("source", "") or "", max_len=200),
            "call_path": call_path,
        },
        risk_score=9.5 if severity == "critical" else 8.0 if severity == "high" else 6.0,
        exposed_tools=[entrypoint] if entrypoint else [],
        id=stable_id("ast-flow", file_path, str(line), entrypoint, sink, category),
    )
    from agent_bom.compliance_hub import apply_hub_classification

    return apply_hub_classification(finding)


def enforcement_dict_to_finding(raw: dict) -> "Finding":
    """Promote MCP audit rows through the owning evidence adapter."""
    from agent_bom.parsers.mcp_audit_findings import enforcement_dict_to_finding as convert

    return convert(raw)


def secret_dict_to_finding(secret: dict) -> "Finding":
    """Convert a secret_scanner result dict into a unified Finding.

    The secret *value* is never carried — only the already-redacted preview,
    type, category, and file:line — so a machine consumer (JSON / SARIF) sees
    that a secret is hardcoded and where, without the secret bytes ever leaking.

    The finding type follows the scanner's ``category``. Personal data is not a
    credential: emitting ``CREDENTIAL_EXPOSURE`` for a matched ``pii`` row told
    operators to *rotate* a value that cannot be rotated (a matched IPv4
    literal), and folded personal-data hygiene into credential dashboards.
    """
    from agent_bom.security import sanitize_text

    file_path = sanitize_text(secret.get("file", "") or "", max_len=500)
    raw_line = secret.get("line")
    line = raw_line if isinstance(raw_line, int) else sanitize_text(raw_line, max_len=40) if raw_line is not None else None
    secret_type = sanitize_text(secret.get("type", "secret") or "secret", max_len=120)
    category = sanitize_text(secret.get("category", "secret") or "secret", max_len=120)
    severity = sanitize_text(secret.get("severity", "medium") or "medium", max_len=40)
    loc = f"{file_path}:{line}" if line else file_path
    is_pii = category.strip().lower() == "pii"
    if is_pii:
        title = f"Personal data in source: {secret_type}"
        description = (
            f"Personal data ({secret_type}) appears at {loc}. Committed personal data is a "
            "privacy and data-handling concern, not a credential."
        )
        remediation = (
            "Confirm the value is not real personal data. If it is, remove it from the file and "
            "its history, and load or generate the value at runtime instead."
        )
    else:
        title = f"Hardcoded {category}: {secret_type}"
        description = (
            f"A {category} ({secret_type}) was found hardcoded at {loc}. "
            "Secrets must live only as OS/shell environment variables or in a "
            "secret manager — never committed in code."
        )
        remediation = "Remove the hardcoded value, rotate it, and load it from an environment variable or secret manager."
    finding = Finding(
        finding_type=FindingType.PII_EXPOSURE if is_pii else FindingType.CREDENTIAL_EXPOSURE,
        source=FindingSource.SECRET_SCAN,
        asset=Asset(
            name=f"{secret_type} in {file_path}" if file_path else secret_type,
            asset_type="file",
            identifier=file_path or None,
            location=file_path or None,
        ),
        severity=severity,
        title=title,
        description=description,
        remediation_guidance=remediation,
        evidence={
            "file": file_path,
            "line": line,
            "secret_type": secret_type,
            **(
                {"validation_status": secret["validation_status"]}
                if isinstance(secret.get("validation_status"), str) and secret["validation_status"] in {"valid", "invalid", "unknown"}
                else {}
            ),
            "category": category,
            "redacted_preview": _safe_secret_preview(secret.get("preview")),
            **(
                {"downgrade_reason": sanitize_text(secret["downgrade_reason"], max_len=200)}
                if isinstance(secret.get("downgrade_reason"), str) and secret["downgrade_reason"]
                else {}
            ),
        },
        id=stable_id("secret", file_path, str(line or ""), secret_type, category),
    )
    from agent_bom.compliance_hub import apply_hub_classification

    return apply_hub_classification(finding)


def cloud_cis_check_to_finding(check: dict, provider: str) -> "Finding":
    """Convert one failed or unevaluable cloud posture check into a Finding.

    Lifts cloud posture failures out of the side-block (``*_cis_benchmark_data``) into
    the unified findings stream so ``--fail-on-severity``, SARIF, and severity
    rollups see them — previously a ``cloud`` scan exited 0 even with HIGH/CRITICAL
    misconfigurations. CIS providers retain CIS identity; vendor best-practice
    providers remain explicitly non-CIS.
    """
    from agent_bom.security import sanitize_text

    check_id = sanitize_text(str(check.get("check_id", "") or "unknown"), max_len=40)
    title = sanitize_text(str(check.get("title", "") or check_id), max_len=300)
    # A control that reports no severity is unrated, not medium. Defaulting to a
    # rated band published a judgement the evidence does not support and folded
    # unevaluable controls into the medium tile; ``unknown`` normalizes to the
    # explicit ``unrated`` bucket, still counted and still visible (#4631).
    severity = sanitize_text(str(check.get("severity") or "unknown"), max_len=40)
    evidence_text = sanitize_text(str(check.get("evidence", "") or ""), max_len=600)
    recommendation = sanitize_text(str(check.get("recommendation", "") or ""), max_len=600)
    # A benchmark check carries its fix under "remediation" (a structured block)
    # while the prose summary lives under "recommendation". The live scanner
    # emits both; the demo overlay and several vendor payloads emit only the
    # former, so reading "recommendation" alone left every one of those findings
    # with no guidance at all and no copy-pasteable command.
    check_fix = check.get("remediation")
    check_fix = check_fix if isinstance(check_fix, dict) else {}
    if not recommendation:
        recommendation = sanitize_text(
            str(check_fix.get("fix_console") or check_fix.get("fix_cli") or ""),
            max_len=600,
        )
    resource_ids = [sanitize_text(str(r), max_len=300) for r in (check.get("resource_ids") or []) if str(r).strip()]
    primary = resource_ids[0] if resource_ids else f"{provider}-account"
    attack = [str(t) for t in (check.get("attack_techniques") or []) if str(t).strip()]
    is_vendor_best_practice = provider.lower() == "databricks"
    compliance = ([] if is_vendor_best_practice else [f"CIS-{check_id}"]) + [
        str(t) for t in (check.get("compliance_tags") or []) if str(t).strip()
    ]
    cis_section = sanitize_text(str(check.get("cis_section", "") or ""), max_len=200)
    benchmark_version = sanitize_text(str(check.get("benchmark_version", "") or ""), max_len=40)
    status = str(check.get("status", "FAIL") or "FAIL").upper()
    if is_vendor_best_practice:
        finding_type = FindingType.CLOUD_BEST_PRACTICE_ERROR if status == "ERROR" else FindingType.CLOUD_BEST_PRACTICE_FAIL
    else:
        finding_type = FindingType.CIS_ERROR if status == "ERROR" else FindingType.CIS_FAIL
    benchmark_label = "Security best-practice" if is_vendor_best_practice else "CIS benchmark"

    # Explicit scope (issue #3946): the converter already knows the provider and
    # the resource id/ARN — parse the account/region out of the ARN, prefer an
    # explicit ``account_id`` on the check, and normalize into one account ref.
    from agent_bom.finding_scope import account_ref_from_arn, normalize_account_ref, region_from_arn

    raw_account = str(check.get("account_id") or "").strip() or account_ref_from_arn(primary)
    account_ref = normalize_account_ref(provider, raw_account)
    region = sanitize_text(str(check.get("region") or "" or region_from_arn(primary) or ""), max_len=64) or None
    environment = sanitize_text(str(check.get("environment") or ""), max_len=64) or None

    finding = Finding(
        finding_type=finding_type,
        source=FindingSource.CLOUD_SECURITY if is_vendor_best_practice else FindingSource.CLOUD_CIS,
        asset=Asset(
            name=primary,
            asset_type="cloud_resource",
            identifier=primary,
            location=provider,
            provider=provider,
            account_ref=account_ref,
            region=region,
            environment=environment,
        ),
        severity=severity,
        severity_source="vendor" if is_vendor_best_practice else "benchmark-mapped",
        provider=provider,
        account_ref=account_ref,
        region=region,
        environment=environment,
        # Prefix the outcome: the control title describes the expected state.
        title=(
            f"{'Unevaluated' if status == 'ERROR' else 'Failed'} "
            f"{'Databricks best practice' if is_vendor_best_practice else 'CIS'} {check_id} — {title}"
        ),
        description=evidence_text
        or (
            f"{benchmark_label} control {check_id} could not be evaluated for {provider}."
            if status == "ERROR"
            else f"{benchmark_label} control {check_id} failed for {provider}."
        ),
        remediation_guidance=recommendation or None,
        compliance_tags=sorted(set(compliance)),
        controls=(
            [
                ControlTag(
                    framework=f"cis_{provider.lower()}_benchmark",
                    control=check_id,
                    version=benchmark_version or "bundled",
                    confidence=1.0,
                    source="cloud_cis_check",
                    via="check_id",
                )
            ]
            if not is_vendor_best_practice
            else []
        ),
        attack_tags=sorted(set(attack)),
        evidence={
            "provider": provider,
            "check_id": check_id,
            "control_title": title,
            # The check's own fix outranks a generic catalog entry keyed only by
            # check id: it names this resource, in this account.
            **({"remediation_fix": check_fix} if check_fix else {}),
            "status": status,
            "cis_section": cis_section,
            "benchmark_version": benchmark_version,
            "resource_ids": resource_ids,
            "benchmark": "Databricks Security Best Practices" if is_vendor_best_practice else "CIS",
        },
    )
    # Populate applicable_frameworks via the hub selection table, consistent with
    # every other finding generator (blast_radius/malicious/auth). Previously this
    # converter set only compliance_tags, leaving applicable_frameworks empty so
    # the finding was invisible in the hub posture aggregation. CIS providers
    # resolve to the CIS framework only (no fabricated SOC2/ISO/NIST crosswalk);
    # vendor best-practice providers keep their source baseline.
    from agent_bom.compliance_hub import apply_hub_classification

    apply_hub_classification(finding)

    # Reference pattern for the advisory-remediation foundation: attach the
    # structured fix + least-privilege-to-apply + runbook artifact. Advisory
    # only — agent-bom recommends, the user applies.
    from agent_bom.remediation import build_remediation as _build_remediation

    finding.remediation = _build_remediation(finding)
    return finding


def iac_finding_to_finding(iac: dict) -> "Finding":
    """Convert one IaC misconfiguration into a unified Finding.

    IaC (Terraform / CloudFormation / K8s / Dockerfile) joins the unified stream so
    totals, ``--fail-on-severity`` and rollups count it. Modeled as a ``CIS_FAIL`` carrying the
    ``iac`` evidence marker so :func:`agent_bom.finding_scope.security_domain_for`
    keeps its primary CSPM lane while :func:`_is_iac_misconfig` also adds the ASPM
    lens. The rule's declared 800-53 controls become scored tags; SARIF renders it
    via its dedicated IaC loop, which the unified SARIF loop skips.
    """
    from agent_bom.security import sanitize_text

    rule_id = sanitize_text(str(iac.get("rule_id", "") or "unknown"), max_len=80)
    file_path = sanitize_text(str(iac.get("file_path", "") or "unknown"), max_len=400)
    line_number = iac.get("line_number") or 0
    try:
        line_number = int(line_number)
    except (TypeError, ValueError):
        line_number = 0
    category = sanitize_text(str(iac.get("category", "iac") or "iac"), max_len=64).lower()
    severity = sanitize_text(str(iac.get("severity", "medium") or "medium"), max_len=40)
    title = sanitize_text(str(iac.get("title", "") or rule_id), max_len=300)
    message = sanitize_text(str(iac.get("message", "") or ""), max_len=600)
    remediation = sanitize_text(str(iac.get("remediation", "") or ""), max_len=600)
    compliance = [str(t) for t in (iac.get("compliance") or []) if str(t).strip()]
    attack = [str(t) for t in (iac.get("attack_techniques") or []) if str(t).strip()]

    finding = Finding(
        finding_type=FindingType.CIS_FAIL,
        source=FindingSource.IAC_SCAN,
        asset=Asset(
            name=file_path,
            asset_type="iac_resource",
            identifier=file_path,
            location=file_path,
        ),
        severity=severity,
        severity_source="rule",
        title=f"IaC misconfiguration {rule_id}: {title}" if title != rule_id else f"IaC misconfiguration {rule_id}",
        description=message or f"IaC rule {rule_id} failed for {file_path}.",
        remediation_guidance=remediation or None,
        compliance_tags=sorted(set(compliance)),
        attack_tags=sorted(set(attack)),
        evidence={
            "iac": True,
            "rule_id": rule_id,
            "category": category,
            "scan_type": "iac",
            "file_path": file_path,
            "repository_relative_path": iac.get("repository_relative_path"),
            "line_number": line_number,
            "compliance": compliance,
        },
        is_actionable=True,
        impact_category="iac_misconfiguration",
        id=stable_id("iac", rule_id, file_path, str(line_number)),
    )
    from agent_bom.evidence.iac_controls import classify_iac_finding

    return classify_iac_finding(finding, compliance)


def snowflake_governance_finding_to_finding(finding: dict, account: str) -> "Finding":
    """Convert one derived Snowflake governance finding into a unified Finding.

    Governance findings (write-access risk, sensitive-data access, agent-usage
    anomalies) live in the side block ``snowflake_governance_data['findings']``.
    Lift severity-bearing ones into the unified stream so ``--fail-on-severity``,
    SARIF, and severity rollups see them — otherwise a ``cloud`` scan exits 0 even
    when governance surfaced HIGH/CRITICAL access risks.
    """
    from agent_bom.security import sanitize_text

    category = sanitize_text(str(finding.get("category", "") or "access"), max_len=60)
    severity = sanitize_text(str(finding.get("severity", "medium") or "medium"), max_len=40)
    title = sanitize_text(str(finding.get("title", "") or category), max_len=300)
    description = sanitize_text(str(finding.get("description", "") or ""), max_len=600)
    agent_or_role = sanitize_text(str(finding.get("agent_or_role", "") or ""), max_len=300)
    object_name = sanitize_text(str(finding.get("object_name", "") or ""), max_len=300)
    primary = object_name or agent_or_role or f"snowflake:{account or 'account'}"

    from agent_bom.finding_scope import normalize_account_ref

    account_ref = normalize_account_ref("snowflake", account)
    return Finding(
        finding_type=FindingType.CIS_FAIL,
        source=FindingSource.CLOUD_CIS,
        asset=Asset(
            name=primary,
            asset_type="cloud_resource",
            identifier=primary,
            location="snowflake",
            provider="snowflake",
            account_ref=account_ref,
        ),
        severity=severity,
        provider="snowflake",
        account_ref=account_ref,
        title=f"Snowflake governance: {title}",
        description=description or f"Snowflake governance risk ({category}) for {primary}.",
        compliance_tags=[f"SNOWFLAKE-GOVERNANCE-{category.upper()}"],
        evidence={
            "provider": "snowflake",
            "account": account,
            "category": category,
            "agent_or_role": agent_or_role,
            "object_name": object_name,
            "details": finding.get("details", {}) or {},
        },
    )


def cloud_org_architecture_finding_to_finding(finding: dict, *, provider: str, org_id: str = "") -> "Finding":
    """Convert an AWS/GCP org-architecture finding into a unified Finding."""
    from agent_bom.finding_scope import normalize_account_ref
    from agent_bom.security import sanitize_text

    provider_key = sanitize_text(str(provider or "cloud"), max_len=40).lower() or "cloud"
    check_id = sanitize_text(str(finding.get("check_id") or finding.get("title") or "ORG"), max_len=80)
    severity = sanitize_text(str(finding.get("severity") or "medium"), max_len=40).lower() or "medium"
    title = sanitize_text(str(finding.get("title") or check_id), max_len=300)
    detail = sanitize_text(str(finding.get("detail") or ""), max_len=800)
    org_label = sanitize_text(str(org_id or "standalone"), max_len=120)
    account_ref = normalize_account_ref(provider_key, org_label)

    return Finding(
        finding_type=FindingType.CLOUD_BEST_PRACTICE_FAIL,
        source=FindingSource.CLOUD_SECURITY,
        asset=Asset(
            name=f"{provider_key}-org:{org_label}",
            asset_type="cloud_resource",
            identifier=f"{provider_key}-org:{org_label}",
            location=provider_key,
            provider=provider_key,
            account_ref=account_ref,
        ),
        severity=severity,
        provider=provider_key,
        account_ref=account_ref,
        title=title,
        description=detail or title,
        compliance_tags=[f"CLOUD-ORG-{check_id}"],
        evidence={
            "provider": provider_key,
            "org_id": org_id,
            "check_id": check_id,
            "category": finding.get("category") or "estate_architecture",
            "account_count": finding.get("account_count"),
            "hierarchy_depth": finding.get("hierarchy_depth"),
        },
        is_actionable=True,
        impact_category="estate_architecture",
        id=stable_id("cloud-org", provider_key, check_id, org_label),
    )


def _tool_name(tool: Any) -> str:
    return str(tool.get("name", "") if isinstance(tool, dict) else getattr(tool, "name", "") or "")


def _agent_server_graph_links(br: Any, entity_name: "Callable[[object], str]") -> tuple[list[dict[str, str]], list[str], list[str]]:
    """Observed agent→server pairs plus the graph ids every surface shares.

    Refs are derived from the same canonical helpers the graph builder uses, so
    an exposure path names graph nodes rather than display labels.
    """
    affected = {getattr(server, "stable_id", ""): server.name for server in br.affected_servers}
    tools = {_tool_name(tool) for tool in br.exposed_tools}
    credentials = set(br.exposed_credentials)
    links: list[dict[str, str]] = []
    tool_refs: dict[str, None] = {}
    credential_refs: dict[str, None] = {}
    for agent in br.affected_agents:
        for server in getattr(agent, "mcp_servers", []) or []:
            server_name = affected.get(getattr(server, "stable_id", ""))
            if not server_name:
                continue
            server_ref = mcp_server_graph_id_for(server, agent)
            links.append(
                {"agent": entity_name(agent), "server": server_name, "agent_ref": agent_graph_id_for(agent), "server_ref": server_ref}
            )
            tool_names = (_tool_name(tool) for tool in getattr(server, "tools", []) or [])
            tool_refs.update((f"tool:{server_ref}:{name}", None) for name in tool_names if name and name in tools)
            credential_names = getattr(server, "credential_names", []) or []
            credential_refs.update((f"cred:{server_ref}:{name}", None) for name in credential_names if name in credentials)
    return links, list(tool_refs), list(credential_refs)


def blast_radius_to_finding(br: object) -> "Finding":
    """Convert a BlastRadius instance to a unified Finding.

    This is the Phase 1 migration shim. BlastRadius objects remain the primary
    output format; this produces a parallel Finding for the unified stream.
    """
    from agent_bom.models import BlastRadius  # local import to avoid circular deps

    if not isinstance(br, BlastRadius):
        raise TypeError(f"Expected BlastRadius, got {type(br)}")

    from agent_bom.asset_provenance import package_discovery_provenance, package_version_provenance

    vuln = br.vulnerability
    pkg = br.package

    def entity_name(entity: object) -> str:
        """Return the cheap display name without eagerly rendering dataclasses."""
        name = getattr(entity, "name", None)
        return str(name) if name else str(entity)

    affected_server_surfaces = {
        server.name: str(getattr(getattr(server, "surface", None), "value", None) or getattr(server, "surface", ""))
        for server in br.affected_servers
    }
    agent_server_links, graph_tool_refs, graph_credential_refs = _agent_server_graph_links(br, entity_name)

    # Asset: a real MCP server when the vulnerable package is installed behind
    # one; otherwise the package itself. Filesystem, SBOM, image, repository,
    # and AI-inventory wrappers share the server-shaped storage model but must
    # not be published as MCP server assets.
    primary_server = next(
        (server for server in br.affected_servers if getattr(server, "is_mcp_surface", False)),
        None,
    )
    if primary_server is not None:
        from agent_bom.security import sanitize_launch_command

        asset = Asset(
            name=primary_server.name,
            asset_type="mcp_server",
            identifier=None,
            location=sanitize_launch_command(primary_server.command, primary_server.args) or None,
        )
    else:
        asset = Asset(
            name=pkg.name,
            asset_type="package",
            identifier=pkg.purl or synthesize_purl(pkg.name, pkg.version, pkg.ecosystem),
        )

    evidence: dict = {
        "package_name": pkg.name,
        "package_version": pkg.version,
        "ecosystem": pkg.ecosystem,
        "package_is_direct": pkg.is_direct,
        "package_parent": pkg.parent_package,
        "package_dependency_depth": pkg.dependency_depth,
        "package_dependency_scope": pkg.dependency_scope,
        "package_reachability_evidence": pkg.reachability_evidence,
        "affected_server_count": len(br.affected_servers),
        "affected_server_surfaces": _sanitized_evidence_field(affected_server_surfaces),
        "agent_server_links": _sanitized_evidence_field(agent_server_links),
        "graph_tool_refs": _sanitized_evidence_field(graph_tool_refs),
        "graph_credential_refs": _sanitized_evidence_field(graph_credential_refs),
        "package_purl": pkg.purl,
        "exposed_credential_count": len(br.exposed_credentials),
        "server_credentials": _sanitized_evidence_field(sorted(set(getattr(br, "all_server_credentials", []) or []))),
        "exposed_tool_count": len(br.exposed_tools),
        "hop_depth": getattr(br, "hop_depth", 1),
        "delegation_chain": _sanitized_evidence_field(getattr(br, "delegation_chain", [])),
        "transitive_agents": _sanitized_evidence_field(getattr(br, "transitive_agents", [])),
        "transitive_servers": _sanitized_evidence_field(getattr(br, "transitive_servers", [])),
        "transitive_packages": _sanitized_evidence_field(getattr(br, "transitive_packages", [])),
        "transitive_credential_count": len(getattr(br, "transitive_credentials", []) or []),
        "transitive_risk_score": getattr(br, "transitive_risk_score", 0.0),
        "dependency_reachable": getattr(br, "dependency_reachable", None),
        "dependency_min_hop_distance": getattr(br, "dependency_min_hop_distance", None),
        "dependency_reachable_from_agents": _sanitized_evidence_field(getattr(br, "dependency_reachable_from_agents", [])),
        "graph_reachable": getattr(br, "graph_reachable", None),
        "graph_min_hop_distance": getattr(br, "graph_min_hop_distance", None),
        "graph_reachable_from_agents": _sanitized_evidence_field(getattr(br, "graph_reachable_from_agents", [])),
        "symbol_reachability": getattr(br, "symbol_reachability", None),
        "reachable_affected_symbols": _sanitized_evidence_field(getattr(br, "reachable_affected_symbols", [])),
        "symbol_reachability_reason": getattr(br, "symbol_reachability_reason", None),
        "runtime_dependency_chain": _sanitized_evidence_field(getattr(br, "runtime_dependency_chain", [])),
        "layer_attribution": _sanitized_evidence_field([_package_occurrence_evidence(occ) for occ in br.layer_attribution]),
        "published_at": getattr(vuln, "published_at", None),
        "modified_at": getattr(vuln, "modified_at", None),
        "severity_source": getattr(vuln, "severity_source", None),
        "severity_basis": severity_basis(getattr(vuln, "severity_source", None)),
        "cvss_vector": getattr(vuln, "cvss_vector", None),
        "attack_vector": getattr(vuln, "attack_vector", None),
        "attack_complexity": getattr(vuln, "attack_complexity", None),
        "privileges_required": getattr(vuln, "privileges_required", None),
        "user_interaction": getattr(vuln, "user_interaction", None),
        "network_exploitable": getattr(vuln, "network_exploitable", False),
        **vulnerability_enrichment_metadata(vuln),
        "vulnerability_compliance_tags": _sanitized_evidence_field(getattr(vuln, "compliance_tags", {}) or {}),
    }
    package_provenance = package_discovery_provenance(pkg)
    if package_provenance:
        evidence["package_discovery_provenance"] = package_provenance
    evidence["package_version_provenance"] = package_version_provenance(pkg)
    from agent_bom.checksums import integrity_verdict

    integrity = integrity_verdict(pkg)
    if integrity is not None:
        # --verify-integrity verdict travels with the finding so SARIF/CSV and
        # the findings API carry it, not just the package-shaped SBOM formats.
        for key, value in integrity.items():
            evidence[f"package_{key}"] = value
    if getattr(pkg, "is_malicious", False):
        evidence["package_is_malicious"] = True
        reason = getattr(pkg, "malicious_reason", None)
        if isinstance(reason, str) and reason.strip():
            evidence["malicious_reason"] = reason.strip()
    if vuln.references:
        evidence["references"] = _sanitized_evidence_field(vuln.references[:5])

    tier = getattr(vuln, "match_confidence_tier", None)
    if tier:
        evidence["match_confidence_tier"] = tier
    if getattr(vuln, "vex_status", None):
        evidence["vex_status"] = vuln.vex_status
    if getattr(vuln, "vex_justification", None):
        evidence["vex_justification"] = vuln.vex_justification
    if getattr(vuln, "vex_source", None):
        evidence["vex_source"] = vuln.vex_source
    if getattr(vuln, "aliases", None):
        evidence["advisory_aliases"] = _sanitized_evidence_field(list(vuln.aliases))
    from agent_bom.advisory_ids import all_cve_identifiers

    cve_ids = all_cve_identifiers(vuln.id, getattr(vuln, "aliases", []) or [])
    if cve_ids:
        evidence["cve_ids"] = cve_ids
    if getattr(br, "symbol_reachability", None):
        from agent_bom.reachability_cve import extract_advisory_identifiers

        reach_ids = extract_advisory_identifiers(vuln)
        if reach_ids.cwe_ids:
            evidence["reachability_advisory_cwe_ids"] = list(reach_ids.cwe_ids)
        if reach_ids.cpe_ids:
            evidence["reachability_advisory_cpe_ids"] = list(reach_ids.cpe_ids)

    sev = vuln.severity.value if hasattr(vuln.severity, "value") else str(vuln.severity)
    evidence["triage_priority"] = fused_triage_priority(
        severity=sev,
        is_kev=bool(vuln.is_kev),
        epss_score=getattr(vuln, "epss_score", None),
        network_exploitable=bool(getattr(vuln, "network_exploitable", False)),
        impact_category=getattr(br, "impact_category", None),
        reachable=getattr(br, "graph_reachable", None),
        exposed_credential_count=len(br.exposed_credentials),
        exposed_tool_count=len(br.exposed_tools),
        symbol_reachability=getattr(br, "symbol_reachability", None),
    )

    from agent_bom.compliance_hub import apply_hub_classification

    # Deterministic graph FKs — package/vuln node ids match builder conventions
    # so investigation can join without CVE-label heuristics alone.
    from agent_bom.package_utils import canonical_package_key
    from agent_bom.vex import is_vex_suppressed, vex_suppression_reason

    package_node_id = f"pkg:{canonical_package_key(pkg.name, pkg.version or '', pkg.ecosystem or '', getattr(pkg, 'purl', None))}"
    finding_node_id = f"vuln:{vuln.id}" if vuln.id else None

    from agent_bom.evidence.finding_response_fields import frozen_atlas_mapping_fields
    from agent_bom.framework_mapping import iso_control_provenance_for_cwes

    evidence.update(frozen_atlas_mapping_fields(br))
    iso_provenance = iso_control_provenance_for_cwes(getattr(vuln, "cwe_ids", []) or [])
    iso_controls = []
    for control in br.iso_27001_tags:
        nist_controls = iso_provenance.get(control)
        if nist_controls:
            iso_controls.append(
                ControlTag(
                    framework="iso_27001",
                    control=control,
                    version="2022",
                    confidence=1.0,
                    source="authority:NIST-OLIR",
                    via=f"vendor-asserted:CWE-to-NIST:{','.join(nist_controls)}",
                )
            )
        else:
            iso_controls.append(
                ControlTag(
                    framework="iso_27001",
                    control=control,
                    version="2022",
                    confidence=0.75,
                    source="vendor-asserted:agent-bom",
                    via="blast-radius-signal",
                )
            )

    finding = Finding(
        finding_type=FindingType.CVE,
        source=_source_for_blast_radius(br),
        asset=asset,
        severity=sev,
        node_id=package_node_id or None,
        finding_node_id=finding_node_id,
        vendor_severity=getattr(vuln, "vendor_severity", None),
        cvss_severity=getattr(vuln, "cvss_severity", None),
        title=f"{vuln.id}: {pkg.name}@{pkg.version or 'unknown'}",
        description=vuln.summary or "",
        cve_id=vuln.id,  # Vulnerability.id is the CVE/OSV ID
        cwe_ids=list(getattr(vuln, "cwe_ids", []) or []),
        cvss_score=vuln.cvss_score,
        cvss_vector=getattr(vuln, "cvss_vector", None),
        attack_vector=getattr(vuln, "attack_vector", None),
        attack_complexity=getattr(vuln, "attack_complexity", None),
        privileges_required=getattr(vuln, "privileges_required", None),
        user_interaction=getattr(vuln, "user_interaction", None),
        network_exploitable=bool(getattr(vuln, "network_exploitable", False)),
        epss_score=vuln.epss_score,
        is_kev=bool(vuln.is_kev),
        is_malicious=bool(getattr(pkg, "is_malicious", False)),
        malicious_reason=getattr(pkg, "malicious_reason", None),
        fixed_version=_forward_fixed_version(vuln.fixed_version, pkg.version, pkg.ecosystem),
        remediation_guidance=_remediation_guidance_for_vulnerability(vuln, pkg),
        owasp_tags=list(br.owasp_tags),
        atlas_tags=list(br.atlas_tags),
        attack_tags=list(br.attack_tags),
        nist_ai_rmf_tags=list(br.nist_ai_rmf_tags),
        owasp_mcp_tags=list(br.owasp_mcp_tags),
        owasp_agentic_tags=list(br.owasp_agentic_tags),
        eu_ai_act_tags=list(br.eu_ai_act_tags),
        nist_csf_tags=list(br.nist_csf_tags),
        controls=iso_controls,
        iso_27001_tags=list(br.iso_27001_tags),
        soc2_tags=list(br.soc2_tags),
        cis_tags=list(br.cis_tags),
        cmmc_tags=list(getattr(br, "cmmc_tags", [])),
        nist_800_53_tags=list(getattr(br, "nist_800_53_tags", [])),
        fedramp_tags=list(getattr(br, "fedramp_tags", [])),
        pci_dss_tags=list(getattr(br, "pci_dss_tags", [])),
        evidence=evidence,
        risk_score=br.risk_score,
        reachability=getattr(br, "reachability", None),
        graph_reachable=getattr(br, "graph_reachable", None),
        graph_min_hop_distance=getattr(br, "graph_min_hop_distance", None),
        graph_reachable_from_agents=list(getattr(br, "graph_reachable_from_agents", []) or []),
        is_actionable=getattr(br, "is_actionable", None),
        impact_category=getattr(br, "impact_category", None),
        suppressed=bool(getattr(br, "suppressed", False)) or is_vex_suppressed(vuln),
        suppression_id=getattr(br, "suppression_id", None),
        suppression_state=getattr(br, "suppression_state", None) or ("vex" if is_vex_suppressed(vuln) else None),
        suppression_reason=getattr(br, "suppression_reason", None) or (vex_suppression_reason(vuln) if is_vex_suppressed(vuln) else None),
        unsuppressed_risk_score=getattr(br, "unsuppressed_risk_score", None),
        ai_risk_context=getattr(br, "ai_risk_context", None),
        ai_summary=getattr(br, "ai_summary", None),
        attack_vector_summary=getattr(br, "attack_vector_summary", None),
        affected_servers=[s.name for s in br.affected_servers],
        affected_agents=[entity_name(a) for a in br.affected_agents],
        exposed_credentials=list(br.exposed_credentials),
        exposed_tools=[entity_name(t) for t in br.exposed_tools],
        sources=_provenance_labels_for_blast_radius(br),
    )
    return apply_hub_classification(finding)


def malicious_package_to_finding(
    pkg: object,
    *,
    affected_agents: list[str],
    affected_servers: list[str],
) -> Finding:
    """Synthesize a unified finding for a malicious package with no CVE BlastRadius."""
    from agent_bom.package_utils import normalize_package_ecosystem

    name = str(getattr(pkg, "name", "") or "unknown")
    version = str(getattr(pkg, "version", "") or "unknown")
    ecosystem = normalize_package_ecosystem(str(getattr(pkg, "ecosystem", "") or ""))
    purl = getattr(pkg, "purl", None)
    identifier = str(purl) if purl else f"pkg:{ecosystem}/{name}@{version}"
    reason = str(getattr(pkg, "malicious_reason", "") or "").strip() or "Known malicious or typosquat package"
    evidence_payload: dict[str, object] = {
        "package_name": name,
        "package_version": version,
        "ecosystem": ecosystem,
        "package_is_malicious": True,
        "malicious_reason": reason,
        "finding_kind": "malicious-package",
    }
    finding = Finding(
        finding_type=FindingType.MALICIOUS_PACKAGE,
        source=FindingSource.MCP_SCAN,
        asset=Asset(name=name, asset_type="package", identifier=identifier),
        severity="critical",
        title=f"Malicious package: {name}@{version}",
        description=reason,
        is_malicious=True,
        malicious_reason=reason,
        is_actionable=True,
        risk_score=10.0,
        affected_agents=list(affected_agents),
        affected_servers=list(affected_servers),
        evidence=evidence_payload,
    )
    from agent_bom.compliance_hub import apply_hub_classification

    return apply_hub_classification(finding)
