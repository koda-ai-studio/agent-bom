"""Unified finding model and source-specific evidence projections."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Optional

from agent_bom.advisory_ids import derive_cve_from_advisory_id, finding_advisory_metadata
from agent_bom.canonical_ids import canonical_finding_id, source_ids
from agent_bom.core.asset_types import entity_type_for_asset_type
from agent_bom.core.sla import finding_owner, finding_sla_fields
from agent_bom.evidence.finding_lanes import model_lane_fields

if TYPE_CHECKING:
    from agent_bom.domain.remediation_model import Remediation

from agent_bom.domain.finding_types import (
    _LEGACY_CONTROL_VERSION_BY_FRAMEWORK,
    FINDING_SCHEMA_VERSION,
    LEGACY_CONTROL_FIELDS,
    ControlTag,
    FindingSource,
    FindingType,
    _control_tag_from_compliance_tag,
    _dedupe_control_tags,
    _occurrence_evidence_qualifier,
    _stable_id,
    stable_id,
)


@dataclass
class Asset:
    """What is affected by this finding."""

    name: str  # human-readable name (server name, package name, cloud resource ID)
    asset_type: str  # "mcp_server" | "package" | "container" | "cloud_resource" | "agent"
    identifier: Optional[str] = None  # purl, ARN, image digest, etc.
    location: Optional[str] = None  # file path, URL, cloud region

    # Explicit scope — where this asset lives. Optional/nullable so non-cloud
    # assets (packages, files) serialize unchanged. ``account_ref`` is a single
    # normalized string (e.g. ``aws:123456789012``) built by finding_scope.
    provider: Optional[str] = None  # aws | azure | gcp | snowflake | ...
    account_ref: Optional[str] = None  # normalized ``<provider>:<account>``
    region: Optional[str] = None
    environment: Optional[str] = None  # prod | staging | dev | ...

    @property
    def stable_id(self) -> str:
        """Deterministic UUID derived from asset content.

        Same asset type + identifier always produces the same ID across scans.
        This enables tracking: first seen, last seen, resolved, re-emerged.
        """
        identifier = self.identifier or f"{self.name}:{self.location or ''}"
        return _stable_id(self.asset_type, identifier)

    @property
    def canonical_id(self) -> str:
        """Canonical alias for stable_id used by reports and graph joins."""
        return self.stable_id

    @property
    def source_ids(self) -> dict[str, str]:
        """Original source identifiers retained as provenance."""
        return source_ids(identifier=self.identifier, location=self.location)


@dataclass
class Finding:
    """Unified finding — one model for all issue types across all sources.

    Carries CVE, cloud, secret, source-analysis and runtime evidence with source
    identity and scope. BlastRadius remains a supported compatibility input.
    """

    # Core identity
    finding_type: FindingType
    source: FindingSource
    asset: Asset
    severity: str  # mirrors Severity enum value; str for forward-compat

    # Explicit scope (issue #3946) — carried on the finding for query/filter
    # convenience and mirrored onto the asset at ingest. All optional/nullable
    # so existing findings serialize unchanged.
    provider: Optional[str] = None  # aws | azure | gcp | snowflake | ...
    account_ref: Optional[str] = None  # normalized ``<provider>:<account>``
    region: Optional[str] = None
    environment: Optional[str] = None  # prod | staging | dev | ...

    # Vendor severity (from source scanner) vs normalised CVSS severity
    severity_source: Optional[str] = None  # cvss, vendor, benchmark-mapped, rule, or collector label
    vendor_severity: Optional[str] = None  # severity as reported by vendor/scanner
    cvss_severity: Optional[str] = None  # normalised from CVSS base score

    # Finding content
    title: str = ""
    description: str = ""
    cve_id: Optional[str] = None  # e.g. "CVE-2024-1234"
    cwe_ids: list[str] = field(default_factory=list)  # e.g. ["CWE-79"]
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    network_exploitable: bool = False
    epss_score: Optional[float] = None
    is_kev: bool = False  # CISA Known Exploited Vulnerability
    is_malicious: bool = False  # Known-malicious package (MAL- IDs, typosquat, etc.)
    malicious_reason: Optional[str] = None

    # Remediation
    fixed_version: Optional[str] = None
    remediation_guidance: Optional[str] = None
    # Structured advisory remediation (fix + least-privilege-to-apply + optional
    # artifact). Additive + optional: findings without it serialize unchanged.
    # Read-only forever — agent-bom recommends, the user applies.
    remediation: Optional["Remediation"] = None

    # Compliance mappings (same tags as BlastRadius for parity)
    compliance_tags: list[str] = field(default_factory=list)  # all framework tags combined
    # Framework slugs that govern this finding (set by compliance_hub.apply_hub_classification).
    # Distinct from the per-framework `*_tags` fields below, which hold control codes.
    applicable_frameworks: list[str] = field(default_factory=list)
    controls: list[ControlTag] = field(default_factory=list)
    owasp_tags: list[str] = field(default_factory=list)
    atlas_tags: list[str] = field(default_factory=list)
    attack_tags: list[str] = field(default_factory=list)
    nist_ai_rmf_tags: list[str] = field(default_factory=list)
    owasp_mcp_tags: list[str] = field(default_factory=list)
    owasp_agentic_tags: list[str] = field(default_factory=list)
    eu_ai_act_tags: list[str] = field(default_factory=list)
    nist_csf_tags: list[str] = field(default_factory=list)
    iso_27001_tags: list[str] = field(default_factory=list)
    soc2_tags: list[str] = field(default_factory=list)
    cis_tags: list[str] = field(default_factory=list)
    cmmc_tags: list[str] = field(default_factory=list)
    nist_800_53_tags: list[str] = field(default_factory=list)
    fedramp_tags: list[str] = field(default_factory=list)
    pci_dss_tags: list[str] = field(default_factory=list)

    # Graph / correlation
    related_findings: list[str] = field(default_factory=list)  # IDs of related findings
    evidence: dict = field(default_factory=dict)  # raw evidence payload
    # Provenance labels when more than one producer observed this finding, e.g.
    # ["native", "external:<tool>"]. Empty for single-producer native findings.
    sources: list[str] = field(default_factory=list)
    # First-class graph FKs (optional, additive). ``node_id`` is the estate /
    # asset UnifiedNode this finding attaches to; ``finding_node_id`` is the
    # vulnerability/misconfiguration node (e.g. ``vuln:CVE-…``) when materialised.
    # ``entity_type`` mirrors EntityType.value for the asset node when known.
    node_id: Optional[str] = None
    finding_node_id: Optional[str] = None
    entity_type: Optional[str] = None

    # Risk
    # 0-10 unified risk score; None when no scorer assessed this finding (never a silent 0).
    risk_score: Optional[float] = None
    reachability: Optional[str] = None
    graph_reachable: Optional[bool] = None
    graph_min_hop_distance: Optional[int] = None
    graph_reachable_from_agents: list[str] = field(default_factory=list)
    is_actionable: Optional[bool] = None
    impact_category: Optional[str] = None

    # Suppression state (mirrors BlastRadius; preserved through the unified stream
    # so a suppressed finding never appears unsuppressed downstream)
    suppressed: bool = False
    suppression_id: Optional[str] = None
    suppression_state: Optional[str] = None
    suppression_reason: Optional[str] = None
    unsuppressed_risk_score: Optional[float] = None

    # AI-native risk context (mirrors BlastRadius)
    ai_risk_context: Optional[str] = None
    ai_summary: Optional[str] = None
    attack_vector_summary: Optional[str] = None

    # Reach / blast-radius lists — kept structured rather than collapsed to counts
    affected_servers: list[str] = field(default_factory=list)  # MCP server names on the impacted path
    affected_agents: list[str] = field(default_factory=list)  # agent names reachable along the path
    exposed_credentials: list[str] = field(default_factory=list)  # credential env-var names at risk
    exposed_tools: list[str] = field(default_factory=list)  # tool names accessible through the path

    # CWPP runtime/EDR workload evidence (optional, additive). Never implies the
    # workload is clean — summaries carry clean_workload_assertion=False.
    workload_runtime_evidence: Optional[dict] = None

    # Ownership + remediation SLA (additive, optional). ``first_seen`` anchors
    # the SLA window (scan-observation time for a fresh scan); ``owner`` surfaces
    # the triage assignee when one exists; ``sla_due_at`` is severity-derived
    # from ``first_seen`` with a KEV override. All left None by default so
    # existing findings serialize unchanged and to_dict() derives on demand.
    first_seen: Optional[str] = None
    owner: Optional[str] = None
    sla_due_at: Optional[str] = None
    sla_due_at_source: Optional[str] = None

    # Unique ID — deterministic UUID v5 based on content (computed in __post_init__)
    # Pass an explicit id= to override (e.g. when ingesting from external scanner)
    id: str = field(default="")

    # Appended after the long-standing explicit-ID slot so additive workflow
    # state does not shift legacy positional construction of this public model.
    lifecycle_status: Optional[str] = None

    def __post_init__(self) -> None:
        """Compute stable ID from finding content if not explicitly set."""
        from agent_bom.core.severity import normalize_severity

        self.severity = normalize_severity(self.severity)
        # Keep finding scope and asset scope consistent: mirror finding-level
        # scope down to the asset when the asset does not already carry it (and
        # lift asset scope up when only the asset was populated). Non-cloud
        # findings leave every field None, so this is a no-op for them.
        for _scope_field in ("provider", "account_ref", "region", "environment"):
            finding_val = getattr(self, _scope_field)
            asset_val = getattr(self.asset, _scope_field, None)
            if finding_val is not None and asset_val is None:
                setattr(self.asset, _scope_field, finding_val)
            elif finding_val is None and asset_val is not None:
                setattr(self, _scope_field, asset_val)
        if self.vendor_severity is not None:
            self.vendor_severity = normalize_severity(self.vendor_severity)
        if self.cvss_severity is not None:
            self.cvss_severity = normalize_severity(self.cvss_severity)
        self.controls = _dedupe_control_tags(
            [
                *(tag if isinstance(tag, ControlTag) else ControlTag.from_dict(tag) for tag in self.controls),
                *self._legacy_control_tags(),
            ]
        )
        # Derive entity_type from asset_type aliases without mutating asset_type
        # (asset_type feeds stable_id / finding id — must stay byte-stable).
        if not self.entity_type:
            try:
                mapped = entity_type_for_asset_type(self.asset.asset_type)
                if mapped is not None:
                    self.entity_type = mapped.value
            except Exception:  # noqa: BLE001 — finding construction must stay resilient
                pass
        if not self.id:
            # Deterministic occurrence ID: the same issue at the same location
            # on one asset stays stable, while distinct source-native locations
            # cannot silently collapse into one workflow record.
            cve_part = self.vulnerability_id or self.title
            pkg_name = ""
            pkg_version = ""
            if self.asset.asset_type == "package" and self.asset.identifier:
                # purl like "pkg:pypi/torch@2.3.0" — extract name/version
                purl = self.asset.identifier
                pkg_part = purl.split("/")[-1] if "/" in purl else purl
                if "@" in pkg_part:
                    pkg_name, pkg_version = pkg_part.rsplit("@", 1)
            elif isinstance(self.evidence, dict):
                # Asset is a server/container/etc — the affected package lives in
                # evidence. Fold it into the discriminator so two CVEs on distinct
                # packages under one asset don't collide on the same id.
                pkg_name = str(self.evidence.get("package_name") or self.evidence.get("package") or "")
                pkg_version = str(self.evidence.get("package_version") or "")
                # Several scanners expose the affected component as the compact
                # ``package=name@version`` form. Normalise that public evidence
                # shape before deriving the occurrence identity; otherwise two
                # packages attached to one container/server silently collapse.
                if pkg_name and not pkg_version and "@" in pkg_name:
                    pkg_name, pkg_version = pkg_name.rsplit("@", 1)
            qualifiers: list[object] = [pkg_name, pkg_version]
            occurrence_qualifier = _occurrence_evidence_qualifier(self.evidence)
            if occurrence_qualifier:
                qualifiers.append(occurrence_qualifier)
            self.id = canonical_finding_id(self.asset.stable_id, cve_part, *qualifiers)

    @property
    def canonical_id(self) -> str:
        """Canonical alias for id used by report and graph consumers."""
        return self.id

    @property
    def occurrence_id(self) -> str:
        """Workflow identity for this finding on this exact asset occurrence."""
        return self.id

    @property
    def finding_group_key(self) -> str:
        """Asset-independent issue identity used only for aggregate/expand views.

        The occurrence id remains authoritative for triage, lifecycle, evidence,
        and persistence.  Vulnerability groups intentionally omit the asset and
        installed version so repeated occurrences can be presented together
        without destroying their distinct workflow records.
        """
        vulnerability_id = str(self.vulnerability_id or "").strip().lower()
        if self.finding_type is not FindingType.CVE or not vulnerability_id:
            return f"occurrence:{self.occurrence_id}"
        package_name = self.asset.name if self.asset.asset_type == "package" else ""
        if not package_name and isinstance(self.evidence, dict):
            package_name = str(self.evidence.get("package_name") or "")
        package_name = package_name.strip().lower()
        return f"vulnerability:{vulnerability_id}:{package_name}"

    @property
    def finding_group_id(self) -> str:
        """Deterministic identifier for a grouped issue queue row."""
        return stable_id("finding-group", self.finding_group_key)

    @property
    def vulnerability_id(self) -> Optional[str]:
        """Canonical advisory identity, regardless of CVE/GHSA/OSV namespace.

        ``cve_id`` remains the wire-compatible legacy field. New producers may
        populate ``evidence.vulnerability_id`` and consumers should prefer this
        namespace-neutral alias when joining findings to advisories.
        """
        if self.cve_id:
            return self.cve_id
        raw = self.evidence.get("vulnerability_id") if isinstance(self.evidence, dict) else None
        return str(raw).strip() or None if raw is not None else None

    @property
    def advisory_ids(self) -> list[str]:
        """Return deterministic, de-duplicated CVE/GHSA/OSV advisory aliases."""
        raw: list[object] = [self.vulnerability_id]
        if isinstance(self.evidence, dict):
            raw.extend(self.evidence.get("cve_ids") or [])
            raw.extend(self.evidence.get("advisory_aliases") or [])
            raw.extend(self.evidence.get("advisory_ids") or [])
        seen: set[str] = set()
        result: list[str] = []
        for value in raw:
            item = str(value or "").strip()
            if item and item not in seen:
                seen.add(item)
                result.append(item)
        return result

    @property
    def finding_category(self) -> str:
        """Stable category for consumers while legacy finding types remain intact."""
        if self.finding_type is FindingType.CVE:
            return "vulnerability"
        if self.finding_type in {FindingType.CIS_FAIL, FindingType.CIS_ERROR}:
            return "compliance"
        return self.finding_type.value.lower()

    def _legacy_control_tags(self) -> list[ControlTag]:
        """Return normalized controls derived from legacy tag arrays."""
        tags: list[ControlTag] = []
        for field_name, framework in LEGACY_CONTROL_FIELDS:
            values = getattr(self, field_name)
            for value in values:
                if value:
                    if field_name == "compliance_tags":
                        tags.append(_control_tag_from_compliance_tag(str(value)))
                        continue
                    tags.append(
                        ControlTag(
                            framework=framework,
                            control=str(value),
                            version=_LEGACY_CONTROL_VERSION_BY_FRAMEWORK.get(framework, "legacy"),
                            confidence=0.75,
                            source=f"legacy:{field_name}",
                            via=field_name,
                        )
                    )
        return tags

    def normalized_controls(self) -> list[ControlTag]:
        """Return deduplicated structured controls for this finding."""
        return _dedupe_control_tags([*self.controls, *self._legacy_control_tags()])

    def all_compliance_tags(self) -> list[str]:
        """Return deduplicated union of all compliance tag lists."""
        seen: set[str] = set()
        result: list[str] = []
        for tag in (
            self.compliance_tags
            + self.owasp_tags
            + self.atlas_tags
            + self.attack_tags
            + self.nist_ai_rmf_tags
            + self.owasp_mcp_tags
            + self.owasp_agentic_tags
            + self.eu_ai_act_tags
            + self.nist_csf_tags
            + self.iso_27001_tags
            + self.soc2_tags
            + self.cis_tags
            + self.cmmc_tags
            + self.nist_800_53_tags
            + self.fedramp_tags
            + self.pci_dss_tags
            + [tag.control for tag in self.normalized_controls()]
        ):
            if tag not in seen:
                seen.add(tag)
                result.append(tag)
        return result

    def effective_severity(self) -> str:
        """Return the best severity value: vendor > cvss > base severity."""
        return self.vendor_severity or self.cvss_severity or self.severity

    @property
    def security_domain(self) -> str:
        """Derived posture lane: one of cspm/vuln/aspm/dspm/aispm.

        A pure function of source + finding type (+ evidence for the cloud
        data-vs-config split), so the overview and findings surfaces route each
        finding to exactly one coverage lane without double counting.
        """
        from agent_bom.finding_scope import security_domain_for

        return security_domain_for(self.source, self.finding_type, self.evidence)

    def to_dict(self) -> dict:
        """Return a JSON-serializable finding payload."""
        sla = finding_sla_fields(
            {
                "severity": self.effective_severity(),
                "first_seen": self.first_seen,
                "evidence": self.evidence,
                "sla_due_at": self.sla_due_at,
                "sla_due_at_source": self.sla_due_at_source or ("explicit" if self.sla_due_at is not None else None),
            }
        )
        return {
            **self._identity_payload(),
            **self._advisory_payload(),
            **self._compliance_payload(),
            **self._reach_payload(),
            **self._lineage_payload(),
            **self._workflow_payload(sla),
        }

    def _lineage_payload(self) -> dict:
        """Dependency lineage of a package-backed finding, read from the same evidence the graph projects.

        Omitted for findings that do not concern a package.
        """
        if "package_is_direct" not in self.evidence:
            return {}
        depth = self.evidence.get("package_dependency_depth")
        return {
            "is_direct": self.evidence.get("package_is_direct"),
            "dependency_depth": depth if isinstance(depth, int) and not isinstance(depth, bool) else None,
            "introduced_via": self.evidence.get("package_parent") or None,
        }

    def _identity_payload(self) -> dict:
        return {
            "schema_version": FINDING_SCHEMA_VERSION,
            "id": self.id,
            "canonical_id": self.canonical_id,
            "finding_id": self.occurrence_id,
            "occurrence_id": self.occurrence_id,
            "finding_group_id": self.finding_group_id,
            "finding_group_key": self.finding_group_key,
            "finding_type": self.finding_type.value,
            "finding_category": self.finding_category,
            "source": self.source.value,
            "asset": {
                "name": self.asset.name,
                "asset_type": self.asset.asset_type,
                "identifier": self.asset.identifier,
                "location": self.asset.location,
                "stable_id": self.asset.stable_id,
                "canonical_id": self.asset.canonical_id,
                "source_ids": self.asset.source_ids,
                "provider": self.asset.provider,
                "account_ref": self.asset.account_ref,
                "region": self.asset.region,
                "environment": self.asset.environment,
            },
            # First-class scope + taxonomy (issue #3946)
            "provider": self.provider,
            "account_ref": self.account_ref,
            "region": self.region,
            "environment": self.environment,
            "security_domain": self.security_domain,
            "severity": self.severity,
            "effective_severity": self.effective_severity(),
            **model_lane_fields(self),
            "vendor_severity": self.vendor_severity,
            "cvss_severity": self.cvss_severity,
            "title": self.title,
            "description": self.description,
            "cve_id": self.cve_id,
            "vulnerability_id": self.vulnerability_id,
            "advisory_ids": self.advisory_ids,
            "cve_ids": self.evidence.get("cve_ids") or ([cve] if (cve := derive_cve_from_advisory_id(self.cve_id or "")) else []),
            "match_confidence_tier": self.evidence.get("match_confidence_tier"),
            "cwe_ids": self.cwe_ids,
        }

    def _advisory_payload(self) -> dict:
        return {
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "attack_vector": self.attack_vector,
            "attack_complexity": self.attack_complexity,
            "privileges_required": self.privileges_required,
            "user_interaction": self.user_interaction,
            "network_exploitable": self.network_exploitable,
            **finding_advisory_metadata(self.evidence),
            "epss_score": self.epss_score,
            "is_kev": self.is_kev,
            "is_malicious": self.is_malicious,
            "malicious_reason": self.malicious_reason,
            "fixed_version": self.fixed_version,
            "remediation_guidance": self.remediation_guidance,
            # Advisory remediation is omitted when absent.
            **({"remediation": self.remediation.to_dict()} if self.remediation is not None else {}),
        }

    def _compliance_payload(self) -> dict:
        return {
            "compliance_tags": self.all_compliance_tags(),
            "applicable_frameworks": list(self.applicable_frameworks),
            "controls": [tag.to_dict() for tag in self.normalized_controls()],
            "owasp_tags": self.owasp_tags,
            "atlas_tags": self.atlas_tags,
            "attack_tags": self.attack_tags,
            "nist_ai_rmf_tags": self.nist_ai_rmf_tags,
            "owasp_mcp_tags": self.owasp_mcp_tags,
            "owasp_agentic_tags": self.owasp_agentic_tags,
            "eu_ai_act_tags": self.eu_ai_act_tags,
            "nist_csf_tags": self.nist_csf_tags,
            "iso_27001_tags": self.iso_27001_tags,
            "soc2_tags": self.soc2_tags,
            "cis_tags": self.cis_tags,
            "cmmc_tags": self.cmmc_tags,
            "nist_800_53_tags": self.nist_800_53_tags,
            "fedramp_tags": self.fedramp_tags,
            "pci_dss_tags": self.pci_dss_tags,
        }

    def _reach_payload(self) -> dict:
        return {
            "related_findings": self.related_findings,
            "evidence": self.evidence,
            **({"sources": list(self.sources)} if self.sources else {}),
            "node_id": self.node_id,
            "finding_node_id": self.finding_node_id,
            "entity_type": self.entity_type,
            "risk_score": self.risk_score,
            "reachability": self.reachability,
            "graph_reachable": self.graph_reachable,
            "graph_min_hop_distance": self.graph_min_hop_distance,
            "graph_reachable_from_agents": list(self.graph_reachable_from_agents),
            "is_actionable": self.is_actionable,
            "impact_category": self.impact_category,
            # Ownership + remediation SLA (derived, single source of truth in
            # agent_bom.core.sla). ``owner`` is an explicit None when nobody is
            # assigned (an honest absence for the API/exports; the CLI/UI render
            # it as "Unassigned"); ``sla_due_at`` is None when no deadline can be
            # derived (unrated severity + no anchor/KEV date).
        }

    def _workflow_payload(self, sla: dict) -> dict:
        return {
            "first_seen": self.first_seen,
            "owner": finding_owner(self.owner),
            **sla,
            "status": self.lifecycle_status,
            "lifecycle_status": self.lifecycle_status,
            # Suppression state — a suppressed finding must never surface as
            # unsuppressed downstream (mirrors BlastRadius / SARIF suppressions[]).
            "suppressed": self.suppressed,
            "suppression_id": self.suppression_id,
            "suppression_state": self.suppression_state,
            "suppression_reason": self.suppression_reason,
            "unsuppressed_risk_score": self.unsuppressed_risk_score,
            # AI-native risk context
            "ai_risk_context": self.ai_risk_context,
            "ai_summary": self.ai_summary,
            "attack_vector_summary": self.attack_vector_summary,
            # Structured reach / blast-radius lists (not collapsed to counts)
            "affected_servers": list(self.affected_servers),
            "affected_agents": list(self.affected_agents),
            "exposed_credentials": list(self.exposed_credentials),
            "exposed_tools": list(self.exposed_tools),
            # CWPP runtime/EDR — omit when unset so plain findings stay unchanged
            **(
                {"workload_runtime_evidence": dict(self.workload_runtime_evidence)}
                if isinstance(self.workload_runtime_evidence, dict)
                else {}
            ),
        }
