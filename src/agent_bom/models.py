"""Core data models for AI-BOM inventory."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import import_module
from typing import TYPE_CHECKING, Any, Optional, Union

from agent_bom.core.reachability import assess_reachability
from agent_bom.core.severity import severity_rank
from agent_bom.domain.agent_model import Agent as Agent
from agent_bom.domain.mcp_model import MCPServer, MCPTool
from agent_bom.domain.package_model import Package, PackageOccurrence
from agent_bom.domain.report_payloads import (
    BenchmarkPayload,
    LicenseReportPayload,
    RuntimeCorrelationPayload,
    VexReportPayload,
    VulnerabilityFreshnessPayload,
)
from agent_bom.domain.vulnerability_model import Vulnerability

if TYPE_CHECKING:
    from agent_bom.ai_schemas import AIFindingAssessment
    from agent_bom.domain.agent_model import classify_agent_kind as classify_agent_kind
    from agent_bom.domain.inventory_types import AgentStatus as AgentStatus
    from agent_bom.domain.inventory_types import AgentType as AgentType
    from agent_bom.domain.inventory_types import ServerSurface as ServerSurface
    from agent_bom.domain.inventory_types import TransportType as TransportType
    from agent_bom.domain.inventory_types import _utc_now_iso as _utc_now_iso
    from agent_bom.domain.mcp_model import CredentialIdentityBinding as CredentialIdentityBinding
    from agent_bom.domain.mcp_model import MCPPrompt as MCPPrompt
    from agent_bom.domain.mcp_model import MCPResource as MCPResource
    from agent_bom.domain.mcp_model import MCPServer as MCPServer
    from agent_bom.domain.mcp_model import MCPTool as MCPTool
    from agent_bom.domain.mcp_model import PermissionProfile as PermissionProfile
    from agent_bom.domain.package_model import Package as Package
    from agent_bom.domain.package_model import PackageOccurrence as PackageOccurrence
    from agent_bom.domain.vulnerability_model import Vulnerability as Vulnerability
    from agent_bom.domain.vulnerability_model import compute_confidence as compute_confidence
    from agent_bom.finding import Finding

from agent_bom.core.packages import normalize_package_name as normalize_package_name
from agent_bom.core.severity import Severity as Severity
from agent_bom.domain.codeowners import apply_codeowners
from agent_bom.evidence.scan_run import ScanRun
from agent_bom.package_utils import parse_debian_source_name as parse_debian_source_name  # noqa: F401


@dataclass
class BlastRadius:
    """Blast radius analysis for a vulnerability."""

    vulnerability: Vulnerability
    package: Package
    affected_servers: list[MCPServer]
    affected_agents: list[Agent]
    exposed_credentials: list[str]  # Credential env var names at risk
    exposed_tools: list[MCPTool]  # Introspected / confirmed tools on the impacted path
    phantom_tools: list[MCPTool] = field(default_factory=list)  # Registry-only, unverified tools (listed, not scored)
    risk_score: Optional[float] = None  # 0-10; None until calculate_risk_score() assesses it
    ai_risk_context: Optional[str] = None  # AI-native risk explanation when relevant
    owasp_tags: list[str] = field(default_factory=list)  # OWASP LLM Top 10 codes, e.g. ["LLM03", "LLM02"]
    atlas_tags: list[str] = field(default_factory=list)  # MITRE ATLAS technique IDs (AI/ML-specific), e.g. ["AML.T0010"]
    atlas_mapping_evidence: dict[str, dict[str, Any]] = field(default_factory=dict)  # Catalog receipts frozen when tags are assigned
    attack_tags: list[str] = field(default_factory=list)  # MITRE ATT&CK Enterprise technique IDs, e.g. ["T1059", "T1190"]
    nist_ai_rmf_tags: list[str] = field(default_factory=list)  # NIST AI RMF subcategories, e.g. ["MAP-4.1"]
    owasp_mcp_tags: list[str] = field(default_factory=list)  # OWASP MCP Top 10 codes, e.g. ["MCP04", "MCP01"]
    owasp_agentic_tags: list[str] = field(default_factory=list)  # OWASP Agentic Top 10, e.g. ["ASI04"]
    eu_ai_act_tags: list[str] = field(default_factory=list)  # EU AI Act articles, e.g. ["ART-15"]
    nist_csf_tags: list[str] = field(default_factory=list)  # NIST CSF 2.0, e.g. ["ID.RA-01"]
    iso_27001_tags: list[str] = field(default_factory=list)  # ISO 27001:2022, e.g. ["A.8.8"]
    soc2_tags: list[str] = field(default_factory=list)  # SOC 2 TSC, e.g. ["CC7.1"]
    cis_tags: list[str] = field(default_factory=list)  # CIS Controls v8, e.g. ["CIS-07.1"]
    cmmc_tags: list[str] = field(default_factory=list)  # CMMC 2.0 Level 2, e.g. ["RA.L2-3.11.2"]
    nist_800_53_tags: list[str] = field(default_factory=list)  # NIST 800-53 Rev 5, e.g. ["RA-5", "SI-2"]
    fedramp_tags: list[str] = field(default_factory=list)  # FedRAMP Moderate baseline, e.g. ["RA-5"]
    pci_dss_tags: list[str] = field(default_factory=list)  # PCI DSS v4.0, e.g. ["Req-6.3"]
    ai_summary: Optional[str] = None  # LLM-generated contextual risk narrative
    suppressed: bool = False  # True when a tenant suppression/feedback rule covers this finding
    suppression_id: Optional[str] = None
    suppression_state: Optional[str] = None
    suppression_reason: Optional[str] = None
    unsuppressed_risk_score: Optional[float] = None

    # CWE-aware impact context
    impact_category: str = "unknown"  # CWE-derived: code-execution, file-access, availability, etc.
    all_server_credentials: list[str] = field(default_factory=list)  # Full credential set before CWE filtering
    all_server_tools: list[MCPTool] = field(default_factory=list)  # Full tool set before CWE filtering
    attack_vector_summary: Optional[str] = None  # Human-readable attack path description

    # Legacy multi-hop fields retained for stored-report compatibility.
    # Inventory-only scans do not populate these as access or execution proof.
    hop_depth: int = 1  # How many hops from the vulnerable package (1 = direct)
    delegation_chain: list[str] = field(default_factory=list)  # e.g. ["server1→agent1→server2→agent2"]
    transitive_agents: list[dict[str, Any]] = field(default_factory=list)  # Agents reached via delegation
    transitive_credentials: list[str] = field(default_factory=list)  # Credentials exposed transitively
    transitive_risk_score: float = 0.0  # Risk score weighted by hop distance

    # Evidence-backed attack-path reachability. These fields are populated
    # only by a matched persisted attack path (or another equally strong
    # path proof), never by structural dependency closure alone.
    graph_reachable: Optional[bool] = None
    graph_min_hop_distance: Optional[int] = None
    graph_reachable_from_agents: list[str] = field(default_factory=list)

    # Function-level symbol reachability (populated by
    # agent_bom.reachability_cve via apply_symbol_reachability_to_blast_radii
    # after AST symbol-reach is available). ``None`` means the join did not
    # run. Otherwise one of "function_reachable" / "package_reachable" /
    # "unreachable"; ``reachable_affected_symbols`` carries the matched
    # advisory symbols when function-reachable.
    symbol_reachability: Optional[str] = None
    reachable_affected_symbols: list[str] = field(default_factory=list)
    symbol_reachability_reason: Optional[str] = None
    runtime_dependency_chain: list[str] = field(default_factory=list)

    # Appended after the existing reachability fields to preserve positional
    # construction compatibility. Structural closure proves an agent-to-package
    # topology exists; it does not by itself prove an exploitable path.
    dependency_reachable: Optional[bool] = None
    dependency_min_hop_distance: Optional[int] = None
    dependency_reachable_from_agents: list[str] = field(default_factory=list)

    # One-hop taint evidence on a function_reachable verdict: True when the
    # call site's argument traces to a parameter of the calling function, or
    # to a direct untrusted-source call (agent_bom.reachability_cve.classify_
    # reachability / ReachabilitySignal.tainted_argument). Additive evidence
    # only — never upgrades/downgrades symbol_reachability or risk scoring.
    # None means not assessed; False means the bounded analysis found no taint.
    # Python-only today; unsupported ecosystems remain unassessed.
    # Appended after the existing reachability fields to preserve positional
    # construction compatibility (see the comment above dependency_reachable).
    symbol_reachability_tainted_argument: Optional[bool] = None

    def calculate_risk_score(self) -> float:
        """Calculate contextual risk score based on blast radius.

        All weights and thresholds are configurable via ``AGENT_BOM_RISK_*``
        environment variables.  See :mod:`agent_bom.config` for defaults and
        documentation.
        """
        from agent_bom.vex import is_vex_suppressed

        if self.suppressed or is_vex_suppressed(self.vulnerability):
            self.risk_score = 0.0
            self.transitive_risk_score = 0.0
            return self.risk_score

        from agent_bom.config import (
            EPSS_CRITICAL_THRESHOLD,
            RISK_AGENT_CAP,
            RISK_AGENT_WEIGHT,
            RISK_AI_BOOST,
            RISK_BASE_CRITICAL,
            RISK_BASE_HIGH,
            RISK_BASE_LOW,
            RISK_BASE_MEDIUM,
            RISK_CRED_CAP,
            RISK_CRED_WEIGHT,
            RISK_EPSS_BOOST,
            RISK_KEV_BOOST,
            RISK_SCORECARD_TIER1_BOOST,
            RISK_SCORECARD_TIER1_THRESHOLD,
            RISK_SCORECARD_TIER2_BOOST,
            RISK_SCORECARD_TIER2_THRESHOLD,
            RISK_SCORECARD_TIER3_BOOST,
            RISK_SCORECARD_TIER3_THRESHOLD,
            RISK_TOOL_CAP,
            RISK_TOOL_WEIGHT,
        )

        severity_scores = {
            Severity.CRITICAL: RISK_BASE_CRITICAL,
            Severity.HIGH: RISK_BASE_HIGH,
            Severity.MEDIUM: RISK_BASE_MEDIUM,
            Severity.LOW: RISK_BASE_LOW,
        }
        base = severity_scores.get(self.vulnerability.severity, 0.0)
        if self.vulnerability.severity in (Severity.NONE, Severity.UNKNOWN) and (
            self.vulnerability.is_kev or (self.vulnerability.epss_score or 0) >= EPSS_CRITICAL_THRESHOLD
        ):
            # An unrated advisory with active-exploitation evidence must not
            # rank below an otherwise-equivalent LOW advisory.
            base = RISK_BASE_LOW

        # Reach factors — each dimension is weight × count, capped
        agent_factor = min(len(self.affected_agents) * RISK_AGENT_WEIGHT, RISK_AGENT_CAP)
        cred_factor = min(len(self.exposed_credentials) * RISK_CRED_WEIGHT, RISK_CRED_CAP)
        tool_factor = min(len(self.exposed_tools) * RISK_TOOL_WEIGHT, RISK_TOOL_CAP)

        # AI framework boost: when AI context + at least one exposure vector (creds OR tools)
        ai_signals = sum([bool(self.ai_risk_context), bool(self.exposed_credentials), bool(self.exposed_tools)])
        ai_boost = RISK_AI_BOOST if ai_signals >= 2 else 0.0

        # Actively exploited (KEV) and high exploit probability (EPSS) boosts
        kev_boost = RISK_KEV_BOOST if self.vulnerability.is_kev else 0.0
        epss_boost = RISK_EPSS_BOOST if (self.vulnerability.epss_score or 0) >= EPSS_CRITICAL_THRESHOLD else 0.0

        # Poorly-maintained package boost (low OpenSSF Scorecard)
        scorecard_boost = 0.0
        if self.package.scorecard_score is not None:
            if self.package.scorecard_score < RISK_SCORECARD_TIER1_THRESHOLD:
                scorecard_boost = RISK_SCORECARD_TIER1_BOOST
            elif self.package.scorecard_score < RISK_SCORECARD_TIER2_THRESHOLD:
                scorecard_boost = RISK_SCORECARD_TIER2_BOOST
            elif self.package.scorecard_score < RISK_SCORECARD_TIER3_THRESHOLD:
                scorecard_boost = RISK_SCORECARD_TIER3_BOOST

        # Graph-walk reachability adjustment. When the engine has run AND
        # produced a definitive answer, apply a small contextual nudge so
        # operators triaging by score see reachable findings rise above
        # otherwise-equivalent unreachable ones. ``None`` (engine did not
        # run) leaves scoring unchanged so non-graph callsites stay stable.
        from agent_bom.config import (
            RISK_REACHABLE_BOOST,
            RISK_UNREACHABLE_PENALTY,
        )

        reach = assess_reachability(
            graph_reachable=self.graph_reachable,
            symbol_reachability=self.symbol_reachability,
            dependency_reachable=self.dependency_reachable,
            direct_dependency=self.package.is_direct,
            affected_agents=bool(self.affected_agents),
            exposed_credentials=bool(self.exposed_credentials),
            exposed_tools=bool(self.exposed_tools),
            declaration_only=self.package.reachability_evidence == "declaration_only",
            match_confidence_tier=self.vulnerability.match_confidence_tier,
        )
        reach_adjustment = 0.0
        if reach.verdict == "confirmed" or "graph_path" in reach.basis:
            reach_adjustment = RISK_REACHABLE_BOOST
        elif reach.verdict == "unlikely":
            reach_adjustment = -RISK_UNREACHABLE_PENALTY

        self.risk_score = max(
            0.0,
            min(
                base + agent_factor + cred_factor + tool_factor + ai_boost + kev_boost + epss_boost + scorecard_boost + reach_adjustment,
                10.0,
            ),
        )
        return self.risk_score

    @property
    def reachability(self) -> str:
        """Classify how reachable this vulnerability is through the blast radius.

        Returns:
            "confirmed"  — function-level (or runtime) evidence proves reach
            "likely"     — a graph path or package/dependency evidence supports reach
            "unlikely"   — graph/symbol/dependency evidence disproves reach
            "unknown"    — structural or exposure context without path proof
        """
        return assess_reachability(
            graph_reachable=self.graph_reachable,
            symbol_reachability=self.symbol_reachability,
            dependency_reachable=self.dependency_reachable,
            direct_dependency=self.package.is_direct,
            affected_agents=bool(self.affected_agents),
            exposed_credentials=bool(self.exposed_credentials),
            exposed_tools=bool(self.exposed_tools),
            declaration_only=self.package.reachability_evidence == "declaration_only",
            match_confidence_tier=self.vulnerability.match_confidence_tier,
        ).verdict

    @property
    def is_actionable(self) -> bool:
        """Whether this finding warrants user attention in default output.

        LOW/MEDIUM transitive deps with no blast radius context are noise.
        Users can still see them with --verbose.
        """
        from agent_bom.vex import is_vex_suppressed

        if self.suppressed or is_vex_suppressed(self.vulnerability):
            return False
        if self.vulnerability.is_kev:
            return True  # KEV = always actionable
        if self.vulnerability.severity in (Severity.CRITICAL, Severity.HIGH):
            return True
        if self.exposed_credentials or self.exposed_tools:
            return True
        if self.package.is_direct:
            return True
        if self.package.is_malicious:
            return True
        return False

    @property
    def layer_attribution(self) -> list[PackageOccurrence]:
        """Concrete package occurrences that carry this vulnerability."""
        return sorted(self.package.occurrences, key=lambda occ: (occ.layer_index, occ.layer_id, occ.package_path or ""))


@dataclass
class AIBOMReport:
    """Complete AI-BOM report."""

    agents: list[Agent] = field(default_factory=list)
    blast_radii: list[BlastRadius] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_id: str = ""  # Deterministic UUID v5 from scan inputs (set by CLI after discovery)
    tool_version: str = ""
    executive_summary: Optional[str] = None  # LLM-generated executive summary
    ai_threat_chains: list[str] = field(default_factory=list)  # LLM-generated threat chain analyses
    mcp_config_analysis: Optional[dict[str, Any]] = None  # LLM-powered MCP config security analysis
    ai_enrichment_metadata: Optional[dict[str, Any]] = None  # Non-secret provider/model provenance for AI-generated fields
    ai_finding_assessments: list[AIFindingAssessment] = field(default_factory=list)
    skill_audit_data: Optional[dict[str, Any]] = None  # Serialized SkillAuditResult (set by CLI)
    trust_assessment_data: Optional[dict[str, Any]] = None  # Serialized TrustAssessmentResult (set by CLI)
    prompt_scan_data: Optional[dict[str, Any]] = None  # Serialized PromptScanResult (set by CLI)
    model_files: list[dict[str, Any]] = field(default_factory=list)
    model_manifests: list[dict[str, Any]] = field(default_factory=list)
    model_provenance: list[dict[str, Any]] = field(default_factory=list)  # HuggingFace provenance results
    model_hash_verification_data: Optional[dict[str, Any]] = None  # Serialized model hash verification report
    model_supply_chain_data: Optional[dict[str, Any]] = None  # Consolidated model file/provenance/hash summary
    enforcement_data: Optional[dict[str, Any]] = None  # Serialized EnforcementReport (set by CLI)
    context_graph_data: Optional[dict[str, Any]] = None  # Serialized context graph (set by CLI)
    license_report: Optional[LicenseReportPayload] = None  # Serialized license compliance report
    vex_data: Optional[VexReportPayload] = None  # Serialized VEX document
    toxic_combinations: Optional[list[Any]] = None  # Serialized ToxicCombination list
    prioritized_findings: Optional[list[Any]] = None  # Priority-ordered findings
    sast_data: Optional[dict[str, Any]] = None  # Serialized SAST scan results (Semgrep)
    aws_organization_data: Optional[dict[str, Any]] = None  # AWS Organizations: org/OUs/accounts/SCPs hierarchy
    cis_benchmark_data: Optional[BenchmarkPayload] = None  # Serialized CIS AWS Benchmark results
    snowflake_cis_benchmark_data: Optional[BenchmarkPayload] = None  # Serialized CIS Snowflake Benchmark results
    snowflake_object_graph_data: Optional[dict[str, Any]] = None  # Snowflake tables/views + OBJECT_DEPENDENCIES lineage
    snowflake_login_anomalies_data: Optional[dict[str, Any]] = None  # Snowflake impossible-travel / login-anomaly detection
    snowflake_exfil_graph_data: Optional[dict[str, Any]] = None  # Snowflake egress: outbound shares, external stages, sensitive objects
    snowflake_auth_posture_data: Optional[dict[str, Any]] = (
        None  # Snowflake per-user auth matrix + network policies (MFA/key-pair/password)
    )
    snowflake_services_data: Optional[dict[str, Any]] = None  # Snowflake compute (warehouses) + database/schema containment hierarchy
    snowflake_pipeline_data: Optional[dict[str, Any]] = None  # Snowflake data-pipeline objects: tasks, streams, pipes
    snowflake_integrations_data: Optional[dict[str, Any]] = (
        None  # Snowflake account integrations: storage/API/external-access/security/catalog
    )
    snowflake_external_data_data: Optional[dict[str, Any]] = None  # Snowflake open-table-format + external data: iceberg + external tables
    snowflake_governance_data: Optional[dict[str, Any]] = (
        None  # Snowflake governance: ACCESS_HISTORY reads + Cortex agent telemetry + derived findings
    )
    snowflake_activity_data: Optional[dict[str, Any]] = (
        None  # Snowflake activity timeline: QUERY_HISTORY (365d) + AI observability events (summarized)
    )
    azure_cis_benchmark_data: Optional[BenchmarkPayload] = None  # Serialized CIS Azure Benchmark results
    gcp_cis_benchmark_data: Optional[BenchmarkPayload] = None  # Serialized CIS GCP Benchmark results
    databricks_security_data: Optional[dict[str, Any]] = None  # Serialized Databricks Security Best Practices results (canonical)
    aisvs_benchmark_data: Optional[BenchmarkPayload] = None  # Serialized AISVS compliance results
    vector_db_scan_data: Optional[list[Any]] = None  # Serialized vector DB security assessments
    gpu_infra_data: Optional[dict[str, Any]] = None  # Serialized GPU/AI compute infra scan results
    # Serialized IaC misconfiguration findings. Set by the CLI scan path and by the
    # API repo_url tree scan (api/repo_tree_scan.py). NOT yet populated for API
    # local-estate/inventory scans or the MCP scan tool — those surfaces do not run
    # the IaC scanner, so /v1/findings shows the IaC category only for repo scans.
    iac_findings_data: Optional[dict[str, Any]] = None
    # Graph toxic-combination findings (serialized Finding dicts; set at the graph-build call site).
    # Rehydrated into the unified Finding stream by to_findings() so they reach --fail-on-severity.
    toxic_combination_findings_data: Optional[list[Any]] = None
    # NHI/CIEM governance findings (over-grant, dormant/orphaned, high-risk NHIs)
    # materialized from the unified graph at the scan call site. Held as Finding
    # objects (not serialized directly); folded into the unified stream by
    # to_findings() so the API path reaches CLI parity for identity governance.
    nhi_governance_findings: list["Finding"] = field(default_factory=list)
    # CIEM over-privilege findings (serialized Finding dicts; set at the graph-build call site).
    # Right-sizing from AWS Access-Advisor usage evidence; rehydrated by to_findings().
    ciem_over_privilege_findings_data: Optional[list[Any]] = None
    # Estate-wide cloud asset inventory; one provider payload or a per-provider list (opt-in AGENT_BOM_CLOUD_INVENTORY)
    cloud_inventory_data: Optional[Union[dict[str, Any], list[Any]]] = None
    identity_discovery_data: Optional[dict[str, Any]] = None  # Discovered non-human identities (opt-in AGENT_BOM_OKTA/ENTRA_DISCOVERY)
    # Cloud audit-trail behavioral payload(s); per-provider list of aggregated
    # (principal, resource, action) edges + findings (opt-in AGENT_BOM_AUDIT_TRAIL, read-only)
    cloud_audit_trail_data: Optional[Union[dict[str, Any], list[Any]]] = None
    runtime_correlation: Optional[RuntimeCorrelationPayload] = None  # Runtime ↔ scan correlation (proxy audit vs CVE findings)
    delta_data: Optional[dict[str, Any]] = None  # Baseline/delta comparison metadata for CI gate outputs
    scan_performance_data: Optional[dict[str, Any]] = None  # Cache coverage / scan latency metadata
    vuln_data_freshness: Optional[VulnerabilityFreshnessPayload] = (
        None  # Vuln-data source/age/staleness snapshot (set by CLI; surfaced to API/MCP)
    )
    training_pipelines: Optional[dict[str, Any]] = None  # Serialized TrainingPipelineScanResult
    dataset_cards: Optional[dict[str, Any]] = None  # Serialized DatasetScanResult
    serving_configs: Optional[list[Any]] = None  # Serialized ServingConfig list
    browser_extensions: Optional[dict[str, Any]] = None  # Serialized browser extension scan results
    endpoint_inventory_data: Optional[dict[str, Any]] = None  # Bounded workstation app/process/service/runtime inventory
    ai_inventory_data: Optional[dict[str, Any]] = None  # AI component source scan results (SDK imports, models, keys)
    project_inventory_data: Optional[dict[str, Any]] = None  # Project manifest / lockfile inventory summary
    # Optional GitHub trust card from --repo / repo_url scans (stars, contributors,
    # license, pushed_at, …). Best-effort read-only API metadata — never required
    # for the security scan itself.
    repo_trust_data: Optional[dict[str, Any]] = None
    # Ownership parsed from the repository's CODEOWNERS file, carried as
    # provenance so graph overlays never need filesystem access. Two shapes are
    # accepted and round-trip unchanged: ordered ``{"pattern", "owners"}`` rules
    # (full CODEOWNERS precedence, used to assign source-finding owners) and the
    # flattened ``{path_prefix: owner}`` map the repo-tree scan produces.
    codeowners: Union[list[dict[str, Any]], dict[str, str]] = field(default_factory=list)
    introspection_data: Optional[dict[str, Any]] = None  # Runtime MCP introspection results (tools, resources, drift)
    health_check_data: Optional[dict[str, Any]] = None  # MCP server reachability/health results
    runtime_session_graph: Optional[dict[str, Any]] = None  # Structured runtime session graph/timeline evidence

    # Explicit unified findings coexist with the legacy blast-radius projection.
    # to_findings() reconciles CVE representations and appends scanner payload
    # findings, including secrets, cloud controls and governance evidence.
    findings: list["Finding"] = field(default_factory=list)

    # Scan context metadata — what input sources were actually processed.
    # Populated by the CLI/API after scan completes. Consumers use this to
    # determine which UI panels, compliance frameworks, and graphs apply.
    scan_sources: list[str] = field(default_factory=list)  # e.g. ["agent_discovery", "image", "sbom"]

    # Execution quality is separate from security/policy verdicts. Consumers
    # must not interpret a complete scan with findings as an incomplete scan.
    scan_run: ScanRun = field(default_factory=ScanRun)

    # Per-release vulnerability-coverage gaps detected during the scan. Each item
    # is a serialized agent_bom.coverage.CoverageWarning (ecosystem, release,
    # reason, detail, package_count, advisory_rows). A non-empty list means the
    # data source does not carry advisories for an OS release present in the scan
    # target (typically end-of-life) — a low/zero count there must NOT be read as
    # a clean bill of health.
    coverage_warnings: list[dict[str, Any]] = field(default_factory=list)

    @property
    def has_mcp_context(self) -> bool:
        """True if scan discovered real MCP servers (not synthetic SBOM/image wrappers).

        Uses explicit server surface classification rather than command heuristics.
        """
        return any(s.is_mcp_surface for a in self.agents for s in a.mcp_servers)

    @property
    def has_agent_context(self) -> bool:
        """True if scan discovered real AI agents (not synthetic SBOM/image wrappers).

        Synthetic agents (SBOM ingest, image scan) use ``AgentType.CUSTOM`` with
        names prefixed by ``sbom:`` or ``image:``.  Real discovered agents have
        specific agent types (CLAUDE_DESKTOP, CURSOR, etc.).
        """
        return any(a.agent_type != AgentType.CUSTOM for a in self.agents)

    @property
    def agent_class_counts(self) -> dict[str, int]:
        """Real agents split by display class: AI clients vs background agents.

        Excludes synthetic SBOM/image wrappers. ``client`` = discovered AI
        host apps; ``background`` = framework/service agent definitions. See
        :func:`classify_agent_kind`.
        """
        counts = {"client": 0, "background": 0}
        for agent in self.agents:
            kind = classify_agent_kind(agent)
            if kind in counts:
                counts[kind] += 1
        return counts

    def __post_init__(self) -> None:
        if not self.tool_version:
            from agent_bom import __version__

            self.tool_version = __version__

    @property
    def databricks_cis_benchmark_data(self) -> Optional[dict[str, Any]]:
        """Deprecated alias for ``databricks_security_data``.

        Databricks has no official CIS benchmark; the canonical field is
        ``databricks_security_data`` (vendor security best practices). This
        CIS-named property is retained for backward compatibility with existing
        clients and delegates both read and write to the canonical field.
        """
        return self.databricks_security_data

    @databricks_cis_benchmark_data.setter
    def databricks_cis_benchmark_data(self, value: Optional[dict[str, Any]]) -> None:
        self.databricks_security_data = value

    @property
    def total_agents(self) -> int:
        return len(self.agents)

    @property
    def total_servers(self) -> int:
        # Package manifests, SBOMs, and container layers reuse MCPServer as a
        # dependency-bearing surface model. They are not MCP servers and must
        # not inflate the public MCP inventory count.
        return sum(agent.total_mcp_servers for agent in self.agents)

    @property
    def total_packages(self) -> int:
        return sum(a.total_packages for a in self.agents)

    @property
    def total_vulnerabilities(self) -> int:
        return sum(a.total_vulnerabilities for a in self.agents)

    @property
    def critical_vulns(self) -> list[BlastRadius]:
        from agent_bom.vex import active_blast_radii

        return [br for br in active_blast_radii(self.blast_radii) if br.vulnerability.severity == Severity.CRITICAL]

    def _secret_findings(self) -> "list[Finding]":
        """Hardcoded-secret findings, lifted from ``ai_inventory_data['secrets']``.

        The secret scanner stores its results in a side block; surface them in the
        unified stream so they reach JSON/SARIF/CSV — redacted, never the value.
        """
        block = (self.ai_inventory_data or {}).get("secrets") if self.ai_inventory_data else None
        if not isinstance(block, dict):
            return []
        from agent_bom.finding import secret_dict_to_finding

        return [secret_dict_to_finding(s) for s in block.get("findings", []) if isinstance(s, dict)]

    def _ast_flow_findings(self) -> "list[Finding]":
        """Native AST flow risks promoted from the source-analysis side block."""
        inventory = self.ai_inventory_data or {}
        block = inventory.get("ast_analysis") if isinstance(inventory, dict) else None
        if not isinstance(block, dict):
            return []
        from agent_bom.finding import ast_flow_dict_to_finding, is_ast_security_flow

        by_sink: dict[tuple[object, ...], Finding] = {}
        for raw in block.get("flow_findings", []):
            if not isinstance(raw, dict) or not is_ast_security_flow(raw):
                continue
            finding = ast_flow_dict_to_finding(raw)
            key = (
                finding.asset.location,
                finding.evidence.get("line"),
                finding.evidence.get("entrypoint"),
                finding.evidence.get("sink") or finding.evidence.get("category"),
            )
            current = by_sink.get(key)
            categories = {str(finding.evidence.get("category", ""))}
            if current is not None:
                categories.add(str(current.evidence.get("category", "")))
                categories.update(str(item) for item in current.evidence.get("detector_categories", []))
            categories.discard("")
            if current is None or severity_rank(finding.severity) > severity_rank(current.severity):
                finding.evidence["detector_categories"] = sorted(categories)
                by_sink[key] = finding
            else:
                current.evidence["detector_categories"] = sorted(categories)
        return list(by_sink.values())

    def _toxic_combination_findings(self) -> "list[Finding]":
        """Rehydrate graph toxic findings for severity gates and JSON/SARIF/CSV."""
        if not self.toxic_combination_findings_data:
            return []
        from agent_bom.domain.finding_rehydrate import findings_from_dicts

        return findings_from_dicts(self.toxic_combination_findings_data)

    def _nhi_governance_findings(self) -> "list[Finding]":
        """NHI/CIEM governance findings, surfaced from the graph-derived side block.

        The scan call site (CLI + API) computes these over the unified graph and
        stores the Finding objects on ``nhi_governance_findings``. Surfacing them
        here routes identity over-grant / dormant / orphaned risks through
        ``--fail-on-severity`` and every machine output, matching the CLI path.
        """
        return list(self.nhi_governance_findings or [])

    def _mcp_tool_rule_findings(self) -> "list[Finding]":
        """MCP tool-schema rule violations lifted into the unified stream.

        The MCP analyzer stores its violations on each ``MCPTool.schema_rule_findings``
        and previously only emitted them inside JSON tool blocks — so the severity
        gate and SARIF never saw them. Convert each stored rule dict to a Finding.
        Derived on the fly from the report's own tools, so it needs no side block
        and stays idempotent (stable ids from rule id + tool).
        """
        from agent_bom.mcp_tool_rules import mcp_rule_finding_to_finding

        findings: list[Finding] = []
        seen: set[str] = set()
        for agent in self.agents:
            for server in getattr(agent, "mcp_servers", []) or []:
                for tool in getattr(server, "tools", []) or []:
                    for raw in getattr(tool, "schema_rule_findings", []) or []:
                        if not isinstance(raw, dict):
                            continue
                        finding = mcp_rule_finding_to_finding(
                            raw,
                            tool_name=getattr(tool, "name", ""),
                            tool_stable_id=getattr(tool, "canonical_id", None),
                            server_name=getattr(server, "name", ""),
                            agent_name=getattr(agent, "name", ""),
                        )
                        if finding.id in seen:
                            continue
                        seen.add(finding.id)
                        findings.append(finding)
        return findings

    def _ciem_over_privilege_findings(self) -> "list[Finding]":
        """Rehydrate CIEM right-sizing findings for severity gates and JSON/SARIF/CSV."""
        if not self.ciem_over_privilege_findings_data:
            return []
        from agent_bom.domain.finding_rehydrate import findings_from_dicts

        return findings_from_dicts(self.ciem_over_privilege_findings_data)

    def _enforcement_findings(self) -> "list[Finding]":
        """MCP description/enforcement findings promoted from the side block."""
        if not isinstance(self.enforcement_data, dict):
            return []
        from agent_bom.finding import enforcement_dict_to_finding

        return [enforcement_dict_to_finding(raw) for raw in self.enforcement_data.get("findings", []) or [] if isinstance(raw, dict)]

    def to_findings(self) -> "list[Finding]":
        """Return unified findings reconciled with legacy and scanner evidence.

        Reconcile explicit findings with the legacy blast-radius projection,
        retaining non-CVE findings when both representations are present.
        Convert supported scanner payloads and append secret evidence so
        machine consumers (JSON/SARIF/CSV) share the same finding stream.
        """
        from agent_bom.finding import FindingType, blast_radius_to_finding

        # Keep explicit non-CVE findings even when the legacy blast-radius
        # projection is also present. API/VEX paths can update the projection
        # after the unified stream was built; dropping either side makes JSON
        # disagree with CSV/SARIF and hides policy findings from consumers.
        base = list(self.findings)

        def _materialized_cve_key(finding: "Finding") -> tuple[str, str, str, str, tuple[str, ...], tuple[str, ...]]:
            evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
            return (
                str(finding.vulnerability_id or ""),
                str(evidence.get("package_name") or ""),
                str(evidence.get("package_version") or ""),
                str(evidence.get("ecosystem") or ""),
                tuple(sorted(finding.affected_agents or [])),
                tuple(sorted(finding.affected_servers or [])),
            )

        materialized_cve_keys = sorted(_materialized_cve_key(finding) for finding in base if finding.finding_type is FindingType.CVE)
        blast_radius_keys = sorted(
            (
                str(br.vulnerability.id or ""),
                str(br.package.name or ""),
                str(br.package.version or ""),
                str(br.package.ecosystem or ""),
                tuple(sorted(str(getattr(agent, "name", "") or "") for agent in br.affected_agents)),
                tuple(sorted(str(getattr(server, "name", "") or "") for server in br.affected_servers)),
            )
            for br in self.blast_radii
        )
        if materialized_cve_keys != blast_radius_keys:
            existing_ids = {getattr(f, "canonical_id", getattr(f, "id", None)) for f in base}
            for br in self.blast_radii:
                finding = blast_radius_to_finding(br)
                finding_id = getattr(finding, "canonical_id", getattr(finding, "id", None))
                if finding_id not in existing_ids:
                    base.append(finding)
                    existing_ids.add(finding_id)
        # Avoid double-counting if a dual-write path ever adds the same secret
        # finding, but do not suppress unrelated secret findings in the side block.
        existing_ids = {getattr(f, "canonical_id", getattr(f, "id", None)) for f in base}
        base.extend(finding for finding in self._secret_findings() if finding.id not in existing_ids)
        ast_existing = {getattr(f, "id", None) for f in base}
        base.extend(finding for finding in self._ast_flow_findings() if finding.id not in ast_existing)
        cis_existing = existing_ids | {getattr(f, "id", None) for f in base}
        base.extend(finding for finding in self._cloud_cis_findings() if finding.id not in cis_existing)
        toxic_existing = {getattr(f, "id", None) for f in base}
        base.extend(finding for finding in self._toxic_combination_findings() if finding.id not in toxic_existing)
        nhi_existing = {getattr(f, "id", None) for f in base}
        base.extend(finding for finding in self._nhi_governance_findings() if finding.id not in nhi_existing)
        ciem_existing = {getattr(f, "id", None) for f in base}
        base.extend(finding for finding in self._ciem_over_privilege_findings() if finding.id not in ciem_existing)
        enforcement_existing = {getattr(f, "id", None) for f in base}
        base.extend(finding for finding in self._enforcement_findings() if finding.id not in enforcement_existing)
        mcp_existing = {getattr(f, "id", None) for f in base}
        base.extend(finding for finding in self._mcp_tool_rule_findings() if finding.id not in mcp_existing)
        iac_existing = {getattr(f, "id", None) for f in base}
        base.extend(finding for finding in self._iac_findings() if finding.id not in iac_existing)
        gov_existing = {getattr(f, "id", None) for f in base}
        base.extend(finding for finding in self._snowflake_governance_findings() if finding.id not in gov_existing)
        org_existing = {getattr(f, "id", None) for f in base}
        base.extend(finding for finding in self._cloud_org_architecture_findings() if finding.id not in org_existing)
        malicious_existing = {getattr(f, "id", None) for f in base}
        base.extend(finding for finding in self._malicious_package_findings() if finding.id not in malicious_existing)
        from agent_bom.domain.finding_merge import merge_external_code_findings

        base = merge_external_code_findings(base)
        if self.codeowners:
            apply_codeowners(base, self.codeowners)
        return base

    def _malicious_package_findings(self) -> "list[Finding]":
        """Malicious/typosquat packages with no CVE BlastRadius row."""
        from agent_bom.finding import malicious_package_to_finding

        covered: set[tuple[str, str, str]] = {
            (br.package.name, br.package.version or "", br.package.ecosystem or "") for br in self.blast_radii
        }
        grouped: dict[tuple[str, str, str], tuple[object, set[str], set[str]]] = {}
        for agent in self.agents:
            for server in agent.mcp_servers:
                for pkg in server.packages:
                    if not getattr(pkg, "is_malicious", False):
                        continue
                    key = (pkg.name, pkg.version or "", pkg.ecosystem or "")
                    if key in covered:
                        continue
                    if key not in grouped:
                        grouped[key] = (pkg, set(), set())
                    pkg_ref, agents, servers = grouped[key]
                    agents.add(agent.name)
                    servers.add(server.name)
                    grouped[key] = (pkg_ref, agents, servers)
        return [
            malicious_package_to_finding(
                pkg,
                affected_agents=sorted(agents),
                affected_servers=sorted(servers),
            )
            for pkg, agents, servers in grouped.values()
        ]

    def _snowflake_governance_findings(self) -> "list[Finding]":
        """Snowflake governance findings lifted into the unified findings stream.

        The derived governance findings live in a side block
        (``snowflake_governance_data['findings']``) and never reached the unified
        stream — so ``cloud`` scans exited 0 even on HIGH/CRITICAL access risks and
        ``--fail-on-severity`` was blind to governance posture. Convert each one to a
        Finding so the gate, SARIF, and severity rollups converge.
        """
        from agent_bom.finding import snowflake_governance_finding_to_finding

        data = self.snowflake_governance_data
        if not isinstance(data, dict):
            return []
        account = str(data.get("account", "") or "")
        findings: list[Finding] = []
        for raw in data.get("findings", []) or []:
            if isinstance(raw, dict):
                findings.append(snowflake_governance_finding_to_finding(raw, account))
        return findings

    def _cloud_org_architecture_findings(self) -> "list[Finding]":
        """AWS/GCP org-architecture findings (single-account / flat hierarchy)."""
        from agent_bom.finding import cloud_org_architecture_finding_to_finding

        payloads: list[tuple[str, dict[str, Any]]] = []
        aws = self.aws_organization_data
        if isinstance(aws, dict):
            payloads.append(("aws", aws))
        inventory = self.cloud_inventory_data
        inv_list = inventory if isinstance(inventory, list) else ([inventory] if isinstance(inventory, dict) else [])
        for entry in inv_list:
            if isinstance(entry, dict) and isinstance(entry.get("gcp_organization"), dict):
                payloads.append(("gcp", entry["gcp_organization"]))

        findings: list[Finding] = []
        for provider, payload in payloads:
            org_id = str(payload.get("org_id") or "")
            for raw in payload.get("findings", []) or []:
                if isinstance(raw, dict):
                    findings.append(cloud_org_architecture_finding_to_finding(raw, provider=provider, org_id=org_id))
        return findings

    def _iac_findings(self) -> "list[Finding]":
        """IaC misconfiguration findings lifted into the unified stream.

        The IaC scanner stores results in the ``iac_findings_data`` side block; they
        reached only JSON + SARIF's dedicated IaC loop, so exec ``total_findings``,
        ``--fail-on-severity``, and severity rollups under-counted them. Convert each
        to a Finding (mirrors the CIS / secret side-block pattern). SARIF continues
        to render IaC via its dedicated loop and skips these in the unified loop, so
        each IaC finding appears exactly once.
        """
        from agent_bom.finding import iac_finding_to_finding

        data = self.iac_findings_data
        if not isinstance(data, dict):
            return []
        findings: list[Finding] = []
        for raw in data.get("findings", []) or []:
            if isinstance(raw, dict):
                findings.append(iac_finding_to_finding(raw))
        return findings

    def _cloud_cis_findings(self) -> "list[Finding]":
        """Cloud CIS failures and evaluation errors lifted into findings.

        Each provider's CIS results live in a side block (``*_cis_benchmark_data``)
        and never reached the unified stream. Convert FAILED controls and ERROR
        controls to distinct CLOUD_CIS findings so severity gates fail closed on
        unevaluable high-risk controls. Genuine NOT_APPLICABLE controls remain
        outside the findings stream.
        """
        from agent_bom.finding import cloud_cis_check_to_finding

        findings: list[Finding] = []
        for provider, data in (
            ("aws", self.cis_benchmark_data),
            ("azure", self.azure_cis_benchmark_data),
            ("gcp", self.gcp_cis_benchmark_data),
            ("snowflake", self.snowflake_cis_benchmark_data),
            ("databricks", self.databricks_security_data),
        ):
            if not isinstance(data, dict):
                continue
            for check in data.get("checks", []) or []:
                if isinstance(check, dict) and str(check.get("status", "")).upper() in {"FAIL", "ERROR"}:
                    check_with_version = {**check, "benchmark_version": data.get("benchmark_version")}
                    findings.append(cloud_cis_check_to_finding(check_with_version, provider))
        return findings

    def cve_findings(self) -> "list[Finding]":
        """Return only CVE-type findings from the unified stream."""
        from agent_bom.finding import FindingType

        return [f for f in self.to_findings() if f.finding_type == FindingType.CVE]


_MODEL_EXPORTS = {
    "_utc_now_iso": "agent_bom.domain.inventory_types",
    "AgentType": "agent_bom.domain.inventory_types",
    "TransportType": "agent_bom.domain.inventory_types",
    "ServerSurface": "agent_bom.domain.inventory_types",
    "AgentStatus": "agent_bom.domain.inventory_types",
    "Vulnerability": "agent_bom.domain.vulnerability_model",
    "compute_confidence": "agent_bom.domain.vulnerability_model",
    "PackageOccurrence": "agent_bom.domain.package_model",
    "Package": "agent_bom.domain.package_model",
    "MCPTool": "agent_bom.domain.mcp_model",
    "MCPResource": "agent_bom.domain.mcp_model",
    "MCPPrompt": "agent_bom.domain.mcp_model",
    "PermissionProfile": "agent_bom.domain.mcp_model",
    "CredentialIdentityBinding": "agent_bom.domain.mcp_model",
    "MCPServer": "agent_bom.domain.mcp_model",
    "classify_agent_kind": "agent_bom.domain.agent_model",
}


def __getattr__(name: str) -> Any:
    module_name = _MODEL_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value
