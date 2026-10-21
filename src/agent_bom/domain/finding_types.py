"""Unified finding model and source-specific evidence projections."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from agent_bom.canonical_ids import canonical_id

FINDING_SCHEMA_VERSION = "1"

EXTERNAL_SOURCE_PREFIX = "external:"


def _stable_id(*parts: str) -> str:
    """Compute a deterministic UUID v5 from content parts.

    Same inputs always produce the same UUID. Use this for asset IDs
    and finding IDs so the same entity is tracked consistently across scans.
    """
    return canonical_id(*parts)


def stable_id(*parts: str) -> str:
    """Public alias for _stable_id — importable for use across modules."""
    return _stable_id(*parts)


class FindingType(str, Enum):
    """What category of issue this finding represents."""

    CVE = "CVE"  # Legacy software-vulnerability value (from OSV/GHSA/NVIDIA)
    CIS_FAIL = "CIS_FAIL"  # CIS benchmark control failure
    CIS_ERROR = "CIS_ERROR"  # CIS control could not be evaluated reliably
    CLOUD_BEST_PRACTICE_FAIL = "CLOUD_BEST_PRACTICE_FAIL"
    CLOUD_BEST_PRACTICE_ERROR = "CLOUD_BEST_PRACTICE_ERROR"
    CREDENTIAL_EXPOSURE = "CREDENTIAL_EXPOSURE"  # Credential found in environment/config
    TOOL_DRIFT = "TOOL_DRIFT"  # MCP tool description changed (rug pull)
    INJECTION = "INJECTION"  # Prompt/argument injection in MCP tool
    PROMPT_SECURITY = "PROMPT_SECURITY"  # Prompt template or prompt content security finding
    EXFILTRATION = "EXFILTRATION"  # Data exfiltration pattern detected by proxy
    CLOAKING = "CLOAKING"  # Invisible chars / SVG cloaking in response
    SAST = "SAST"  # Static analysis finding (CWE-mapped)
    SKILL_RISK = "SKILL_RISK"  # Behavioral risk in AI skill file
    BROWSER_EXT = "BROWSER_EXT"  # Suspicious browser extension
    LICENSE = "LICENSE"  # License compliance violation
    RATE_LIMIT = "RATE_LIMIT"  # Rate limit abuse by MCP tool
    MCP_BLOCKLIST = "MCP_BLOCKLIST"  # Curated malicious/suspicious MCP server match
    COMBINATION = "COMBINATION"  # Toxic combination — multiple signals chained into one exploitable path
    MALICIOUS_PACKAGE = "MALICIOUS_PACKAGE"  # Known-malicious / typosquat package with no CVE row
    MALICIOUS_MODEL = "MALICIOUS_MODEL"  # Content-confirmed executable payload in a model artifact
    MODEL_INTEGRITY = "MODEL_INTEGRITY"  # Model artifact provenance/integrity gap (tampered, unsigned, unscanned)
    CIEM_OVER_PRIVILEGE = "CIEM_OVER_PRIVILEGE"  # Cloud identity granted permissions it never uses (right-sizing)
    SENSITIVE_DATA = "SENSITIVE_DATA"  # Content-confirmed sensitive data at rest (DSPM object/database sampling)
    PII_EXPOSURE = "PII_EXPOSURE"  # Personal data literal committed in source/config (not a credential)
    SHADOW_AI = "SHADOW_AI"  # Agent or tool observed at runtime with no exact inventory match


class FindingSource(str, Enum):
    """Which scanner or subsystem produced this finding."""

    IAC_SCAN = "IAC_SCAN"  # Repository infrastructure templates
    MCP_SCAN = "MCP_SCAN"  # agent discovery + CVE scanner
    CONTAINER = "CONTAINER"  # container image scan (Syft/Grype/Trivy ingestion)
    SBOM = "SBOM"  # SBOM ingest (CycloneDX / SPDX)
    CLOUD_CIS = "CLOUD_CIS"  # cloud CIS benchmark (AWS/Azure/GCP/Snowflake)
    CLOUD_SECURITY = "CLOUD_SECURITY"  # vendor-authored cloud security best practices
    PROXY = "PROXY"  # runtime proxy detector
    SAST = "SAST"  # static analysis (Semgrep)
    SKILL = "SKILL"  # skill file auditor
    BROWSER_EXT = "BROWSER_EXT"  # browser extension scanner
    EXTERNAL = "EXTERNAL"  # ingested from external scanner (Trivy/Grype/Syft JSON)
    FILESYSTEM = "FILESYSTEM"  # filesystem mount scan
    PROMPT_SCAN = "PROMPT_SCAN"  # prompt template/content scanner
    SECRET_SCAN = "SECRET_SCAN"  # hardcoded secret / PII scanner
    GRAPH_ANALYSIS = "GRAPH_ANALYSIS"  # graph-level correlation (toxic combinations, attack-path fusion)
    DSPM = "DSPM"  # data security posture content classifier (S3/GCS/Azure Blob/database sampling)
    MODEL_SCAN = "MODEL_SCAN"  # static model-artifact safety scanner


@dataclass(frozen=True)
class ControlTag:
    """Normalized framework control attached to a finding.

    Legacy finding payloads expose framework-specific arrays such as
    ``owasp_tags`` and ``soc2_tags``. ``ControlTag`` gives new consumers one
    structured list while those legacy arrays remain serialized for backward
    compatibility.
    """

    framework: str
    control: str
    version: Optional[str] = None
    confidence: Optional[float] = None
    source: Optional[str] = None
    via: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        return {
            "framework": self.framework,
            "control": self.control,
            "version": self.version,
            "confidence": self.confidence,
            "source": self.source,
            "via": self.via,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "ControlTag":
        raw_confidence = payload.get("confidence")
        confidence: Optional[float] = None
        if isinstance(raw_confidence, (int, float, str)):
            try:
                confidence = float(raw_confidence)
            except ValueError:
                confidence = None
        raw_source = payload.get("source") or payload.get("via")
        raw_via = payload.get("via")

        return cls(
            framework=str(payload.get("framework") or ""),
            control=str(payload.get("control") or ""),
            version=str(payload["version"]) if payload.get("version") is not None else None,
            confidence=confidence,
            source=str(raw_source) if raw_source else None,
            via=str(raw_via) if raw_via else None,
        )


LEGACY_CONTROL_FIELDS: tuple[tuple[str, str], ...] = (
    ("compliance_tags", "generic"),
    ("owasp_tags", "owasp_llm"),
    ("atlas_tags", "mitre_atlas"),
    ("attack_tags", "mitre_attack"),
    ("nist_ai_rmf_tags", "nist_ai_rmf"),
    ("owasp_mcp_tags", "owasp_mcp"),
    ("owasp_agentic_tags", "owasp_agentic"),
    ("eu_ai_act_tags", "eu_ai_act"),
    ("nist_csf_tags", "nist_csf"),
    ("iso_27001_tags", "iso_27001"),
    ("soc2_tags", "soc2"),
    ("cis_tags", "cis"),
    ("cmmc_tags", "cmmc"),
    ("nist_800_53_tags", "nist_800_53"),
    ("fedramp_tags", "fedramp"),
    ("pci_dss_tags", "pci_dss"),
)

_LEGACY_CONTROL_VERSION_BY_FRAMEWORK: dict[str, str] = {
    "generic": "legacy",
    "owasp_llm": "2025",
    "mitre_atlas": "bundled",
    "mitre_attack": "enterprise-bundled",
    "nist_ai_rmf": "1.0",
    "owasp_mcp": "2025",
    "owasp_agentic": "2026",
    "eu_ai_act": "2024",
    "nist_csf": "2.0",
    "iso_27001": "2022",
    "soc2": "2017",
    "cis": "v8",
    "cmmc": "2.0",
    "nist_800_53": "rev5",
    "fedramp": "moderate",
    "pci_dss": "4.0",
}


def _dedupe_control_tags(tags: list[ControlTag]) -> list[ControlTag]:
    seen: set[tuple[str, str]] = set()
    out: list[ControlTag] = []
    for tag in tags:
        if not tag.framework or not tag.control:
            continue
        key = (tag.framework, tag.control)
        if key in seen:
            continue
        seen.add(key)
        out.append(tag)
    return out


_CIS_BENCHMARK_FRAMEWORKS: dict[str, str] = {
    "AWS": "cis_aws_foundations",
    "AZURE": "cis_azure_foundations",
    "GCP": "cis_gcp_foundations",
    "DOCKER": "cis_docker_benchmark",
    "K8S": "cis_kubernetes_benchmark",
    "KUBERNETES": "cis_kubernetes_benchmark",
}


def _control_tag_from_compliance_tag(value: str) -> ControlTag:
    """Type one legacy compliance identifier without inventing a crosswalk.

    IaC scanners historically placed every identifier in ``compliance_tags``.
    Treating that mixed array as one ``generic`` framework made real NIST
    controls unjoinable and, worse, could make a cloud Foundations benchmark
    look like CIS Controls v8.  Prefix parsing preserves the identifier's own
    namespace only; it does not claim equivalence between frameworks.
    """
    source = "legacy:compliance_tags"
    upper = value.upper()
    if upper.startswith("NIST-CSF-"):
        return ControlTag(
            framework="nist_csf",
            control=value[len("NIST-CSF-") :],
            version="2.0",
            confidence=1.0,
            source=source,
            via="compliance_tags",
        )
    if upper.startswith("NIST-AI-RMF-"):
        return ControlTag(
            framework="nist_ai_rmf",
            control=value[len("NIST-AI-RMF-") :],
            version="1.0",
            confidence=1.0,
            source=source,
            via="compliance_tags",
        )
    # Only the two-letter 800-53 family shape claims 800-53. A looser ``NIST-``
    # prefix match would file NIST-AI-RMF and other NIST publications under a
    # catalog that never contained them.
    if nist_match := re.fullmatch(r"NIST-([A-Z]{2})-(.+)", upper):
        return ControlTag(
            framework="nist_800_53",
            control=f"{nist_match.group(1)}-{nist_match.group(2)}",
            version="rev5",
            confidence=1.0,
            source=source,
            via="compliance_tags",
        )
    if upper.startswith("SOC2-"):
        return ControlTag(
            framework="soc2",
            control=value[len("SOC2-") :],
            version="2017",
            confidence=1.0,
            source=source,
            via="compliance_tags",
        )
    cis_match = re.fullmatch(r"CIS-([A-Za-z0-9]+)-(.+)", value)
    if cis_match:
        provider, control = cis_match.groups()
        framework = _CIS_BENCHMARK_FRAMEWORKS.get(provider.upper())
        if framework:
            return ControlTag(
                framework=framework,
                control=control,
                version="benchmark",
                confidence=1.0,
                source=source,
                via="compliance_tags",
            )
    return ControlTag(
        framework="generic",
        control=value,
        version="legacy",
        confidence=0.75,
        source=source,
        via="compliance_tags",
    )


_OCCURRENCE_EVIDENCE_KEYS: tuple[str, ...] = (
    "occurrence_id",
    "occurrence_key",
    "source_finding_id",
    "external_tool",
    "repository",
    "repository_url",
    "path",
    "file",
    "file_path",
    "manifest_path",
    "config_path",
    "location",
    "source_location",
    "line",
    "line_number",
    "start_line",
    "column",
    "column_number",
    "start_column",
    "rule",
    "rule_id",
    "check_id",
    "control_id",
    "resource_id",
    "resource_arn",
    "resource_uri",
    "uri",
    "symbol",
    "function",
    "method",
    "server_name",
    "tool_name",
    "model_id",
    "dataset_id",
    "indicator_ref",
)


def _occurrence_evidence_qualifier(evidence: object) -> dict[str, object]:
    """Return stable location/source fields that distinguish one occurrence.

    Findings deliberately ignore volatile evidence such as confidence, score,
    timestamps, code revisions, and remediation state so repeated scans preserve identity. The
    allowlist contains source-native locators that identify *where* the issue
    occurred; when present, those locators prevent two occurrences on the same
    canonical asset from silently collapsing.
    """
    if not isinstance(evidence, dict):
        return {}
    return {key: value for key in _OCCURRENCE_EVIDENCE_KEYS if (value := evidence.get(key)) not in (None, "", [], {})}
