"""Core data models for AI-BOM inventory."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from agent_bom.canonical_ids import (
    canonical_package_id,
)
from agent_bom.core.package_artifacts import normalize_artifact_version, package_lookup_names
from agent_bom.core.packages import normalize_package_name as normalize_package_name
from agent_bom.core.severity import Severity as Severity
from agent_bom.domain.vulnerability_model import Vulnerability
from agent_bom.package_utils import parse_debian_source_name as parse_debian_source_name  # noqa: F401


@dataclass
class PackageOccurrence:
    """Concrete package observation metadata for layered/container surfaces."""

    layer_index: int
    layer_id: str
    package_path: Optional[str] = None
    layer_path: Optional[str] = None
    created_by: Optional[str] = None
    dockerfile_instruction: Optional[str] = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""
        return {
            "layer_index": self.layer_index,
            "layer_id": self.layer_id,
            "layer_path": self.layer_path,
            "package_path": self.package_path,
            "created_by": self.created_by,
            "dockerfile_instruction": self.dockerfile_instruction,
        }


@dataclass
class Package:
    """A software package dependency."""

    name: str
    version: str
    ecosystem: str  # npm, pypi, cargo, go, etc.
    purl: Optional[str] = None  # Package URL
    source_package: Optional[str] = None  # Debian/OS source package name for advisory matching
    distro_name: Optional[str] = None  # OS distribution family for OS packages (e.g. debian, ubuntu, alpine)
    distro_version: Optional[str] = None  # OS distribution version for OS packages (e.g. 13, 24.04, 3.21)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    is_direct: bool | None = True  # None when the supplied evidence does not establish directness
    parent_package: Optional[str] = None  # Name of parent package (for transitive deps)
    dependency_depth: int = 0  # 0 for direct, 1+ for transitive
    dependency_scope: str = "runtime"  # runtime, optional, peer, extra, conditional, dev, unknown
    reachability_evidence: str = "runtime_dependency"  # runtime_dependency, declaration_only, lockfile, unknown
    resolved_from_registry: bool = False  # True if resolved dynamically vs from lock file
    registry_version: Optional[str] = None  # Latest version from registry (for drift comparison)
    version_source: str = "detected"  # "detected" | "manifest" | "registry_fallback"
    declared_version: Optional[str] = None  # Version/ref declared by command or manifest (may be latest/floating)
    resolved_version: Optional[str] = None  # Exact version selected after resolution, when known
    version_confidence: Optional[str] = None  # ADR-007 confidence enum for the resolved version
    version_resolved_at: Optional[str] = None  # Timestamp when version was resolved
    version_evidence: list[dict[str, Any]] = field(default_factory=list)  # Structured evidence for version source
    version_conflicts: list[dict[str, Any]] = field(default_factory=list)  # Conflicting source/version observations
    floating_reference: bool = False  # True when the package/source ref is mutable (latest/main/no digest)
    floating_reference_reason: Optional[str] = None  # Why the ref is mutable
    is_malicious: bool = False  # True if flagged as known malicious (MAL- prefix in OSV)
    malicious_reason: Optional[str] = None  # Why this package is flagged (e.g. "MAL-2024-1234")
    license: Optional[str] = None  # SPDX license identifier (e.g. "MIT", "Apache-2.0")
    license_expression: Optional[str] = None  # Full SPDX expression (e.g. "Apache-2.0 AND MIT")
    deps_dev_resolved: bool = False  # True if resolved via deps.dev API

    # Supply chain metadata (populated by deps.dev enrichment or SBOM ingestion)
    supplier: Optional[str] = None  # Organization or individual that supplied the package
    author: Optional[str] = None  # Package author (name or email)
    description: Optional[str] = None  # Short package description
    homepage: Optional[str] = None  # Project homepage URL
    repository_url: Optional[str] = None  # Source repository URL (git, svn)
    download_url: Optional[str] = None  # Artifact download location
    copyright_text: Optional[str] = None  # Copyright notice

    # OpenSSF Scorecard enrichment (populated by --scorecard flag)
    scorecard_score: Optional[float] = None  # 0.0-10.0 overall score
    scorecard_checks: dict[str, int] = field(default_factory=dict)  # check_name -> score (-1 to 10)
    scorecard_repo: Optional[str] = None  # Resolved GitHub owner/repo when available
    scorecard_lookup_state: Optional[str] = None  # enriched | unresolved | failed
    scorecard_lookup_reason: Optional[str] = None  # why enrichment did not succeed

    # Per-component checksums keyed by canonical algorithm (e.g. "SHA-512"),
    # value is lowercase hex. Populated from lockfile integrity / registry
    # digests where the source provides them; surfaced in SBOM output.
    checksums: dict[str, str] = field(default_factory=dict)

    # Provenance / supply chain attestation (populated by --verify-integrity)
    integrity_verified: Optional[bool] = None  # SHA256/SRI verified against registry
    # ``None`` = the registry never answered (not asked, or asked and it was
    # unreachable). ``provenance_status`` says which; see
    # ``integrity.PROVENANCE_UNKNOWN_STATUSES``.
    provenance_attested: Optional[bool] = None  # SLSA/PEP740/sum.golang.org attestation found
    provenance_source: Optional[str] = None  # "npm_slsa", "pypi_pep740", "go_sumdb"
    # Registry's own answer: verified | not_published | not_provenance | partial | unavailable
    provenance_status: Optional[str] = None

    # Auto-discovery metadata (populated when not in bundled registry)
    auto_risk_level: Optional[str] = None
    auto_risk_justification: Optional[str] = None
    maintainer_count: Optional[int] = None
    source_repo: Optional[str] = None
    occurrences: list[PackageOccurrence] = field(default_factory=list)  # Layer/file provenance for concrete package observations
    discovery_provenance: Optional[dict[str, Any]] = None  # Sanitized discovery provenance contract for this package asset

    def __post_init__(self) -> None:
        normalize_artifact_version(self)

    @property
    def stable_id(self) -> str:
        """Deterministic ID for this package instance.

        Same ecosystem/name/version (or purl when available) always produces
        the same ID across scans — enables first-seen/last-seen tracking.
        """
        return canonical_package_id(self.name, self.version, self.ecosystem, self.purl)

    @property
    def canonical_id(self) -> str:
        """Canonical alias for stable_id used by report and graph consumers."""
        return self.stable_id

    @property
    def lookup_names(self) -> list[str]:
        """Candidate package names for vulnerability matching."""
        return package_lookup_names(self)

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def primary_occurrence(self) -> Optional[PackageOccurrence]:
        """First observed occurrence in deterministic layer order."""
        if not self.occurrences:
            return None
        return min(self.occurrences, key=lambda occ: (occ.layer_index, occ.layer_id, occ.package_path or ""))

    @property
    def layer_count(self) -> int:
        """Number of unique image layers that contributed this package."""
        return len({(occ.layer_index, occ.layer_id) for occ in self.occurrences})

    @property
    def max_severity(self) -> Severity:
        if not self.vulnerabilities:
            return Severity.NONE
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for sev in severity_order:
            if any(v.severity == sev for v in self.vulnerabilities):
                return sev
        return Severity.NONE
