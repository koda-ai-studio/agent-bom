"""Pydantic models for the agent-bom API."""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum
from importlib import import_module
from typing import TYPE_CHECKING, Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, computed_field, field_serializer, field_validator, model_validator

from agent_bom.ai_schemas import AIFindingAssessment as _CoreAIFindingAssessment
from agent_bom.ai_schemas import AIProvenance as _CoreAIProvenance
from agent_bom.api import policy_inputs as _policy_inputs
from agent_bom.api.push_models import PushEvidencePayload as _PushEvidencePayload
from agent_bom.api.report_types import ReportFormat as ReportFormat
from agent_bom.api.report_types import ReportJobRequest as _ReportJobRequest
from agent_bom.config import API_MAX_BATCH_SCAN_TARGETS
from agent_bom.evidence.semantics import EvidenceCompletenessLedger as _CoreEvidenceCompletenessLedger
from agent_bom.evidence.semantics import SecurityDimensions as _CoreSecurityDimensions
from agent_bom.finding_scope import FindingClass
from agent_bom.identity.join_contract import IdentityResourceJoinContract as _CoreIdentityResourceJoinContract

# ─── Enums ─────────────────────────────────────────────────────────────────


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


# ─── Scan Models ───────────────────────────────────────────────────────────


class AIProvenance(_CoreAIProvenance):
    """Public schema contract for model-derived scan evidence."""


class AIFindingAssessment(_CoreAIFindingAssessment):
    """Public schema contract for one advisory AI assessment."""

    provenance: AIProvenance


class EvidenceCompletenessLedger(_CoreEvidenceCompletenessLedger):
    """Public contract for explicit collection and analysis completeness."""


class SecurityDimensions(_CoreSecurityDimensions):
    """Public contract keeping security dimensions and evidence independent."""


class IdentityResourceJoinContract(_CoreIdentityResourceJoinContract):
    """Public shape for evidence-backed cross-provider identity/resource joins.

    JSON Schema enforces local field/status constraints. Cross-record identity,
    resource, freshness, and evidence-anchor invariants require the executable
    Pydantic validator inherited from the core contract.
    """


# Fields that fan out one child scan job per element when a request carries more
# than one explicit target. Mirrors scan_batches.BATCH_*_TARGET_FIELDS (kept
# local to avoid a models -> scan_batches import cycle).
_BATCH_LIST_TARGET_FIELDS = (
    "images",
    "tf_dirs",
    "agent_projects",
    "jupyter_dirs",
    "connectors",
    "filesystem_paths",
)
_BATCH_SINGLE_TARGET_FIELDS = ("inventory", "gha_path", "sbom", "external_scan", "vex", "repo_url")

_SCAN_PATH_MAX_LENGTH = 4096
_SCAN_IMAGE_REF_MAX_LENGTH = 512
_SCAN_CONNECTOR_MAX_LENGTH = 128
_SCAN_GLOB_MAX_LENGTH = 256

ScanPathEntry = Annotated[str, Field(max_length=_SCAN_PATH_MAX_LENGTH)]
ScanImageRef = Annotated[str, Field(max_length=_SCAN_IMAGE_REF_MAX_LENGTH)]
ScanConnectorName = Annotated[str, Field(max_length=_SCAN_CONNECTOR_MAX_LENGTH)]
ScanGlobPattern = Annotated[str, Field(max_length=_SCAN_GLOB_MAX_LENGTH)]
ScanSinglePath = Annotated[str, Field(max_length=_SCAN_PATH_MAX_LENGTH)]

_SCAN_SEVERITY_ORDER = ("low", "medium", "high", "critical")


def _stabilize_scan_severity_schema(schema: dict[str, Any]) -> None:
    """Keep OpenAPI output stable across Python ``Literal`` implementations."""
    for variant in schema.get("anyOf", ()):
        if "enum" in variant:
            variant["enum"] = list(_SCAN_SEVERITY_ORDER)


class _BoundedProgress(list[str]):
    """List that keeps only the latest configured API progress events."""

    def _trim(self) -> None:
        from agent_bom.config import API_MAX_JOB_PROGRESS_EVENTS

        if API_MAX_JOB_PROGRESS_EVENTS > 0 and len(self) > API_MAX_JOB_PROGRESS_EVENTS:
            del self[: len(self) - API_MAX_JOB_PROGRESS_EVENTS]

    def append(self, item: str) -> None:
        super().append(item)
        self._trim()

    def extend(self, iterable: Iterable[str]) -> None:
        super().extend(iterable)
        self._trim()


class ScanRequest(BaseModel):
    """Options accepted by POST /v1/scan — mirrors agent-bom scan CLI flags."""

    model_config = ConfigDict(extra="forbid")

    inventory: ScanSinglePath | None = None
    """Path to agents.json inventory file."""

    images: list[ScanImageRef] = Field(default_factory=list)
    """Docker image references to scan (e.g. ['myapp:latest', 'redis:7'])."""

    k8s: bool = False
    """Scan running Kubernetes pods via kubectl."""

    k8s_namespace: str | None = None
    """Kubernetes namespace (None = all)."""

    tf_dirs: list[ScanPathEntry] = Field(default_factory=list)
    """Terraform directories to scan."""

    gha_path: ScanSinglePath | None = None
    """Path to a Git repo to scan GitHub Actions workflows."""

    repo_url: str | None = Field(default=None, max_length=2048)
    """Public ``http(s)`` git repository URL to shallow-clone and scan statically."""

    agent_projects: list[ScanPathEntry] = Field(default_factory=list)
    """Python project directories using AI agent frameworks."""

    jupyter_dirs: list[ScanPathEntry] = Field(default_factory=list)
    """Directories to scan for Jupyter notebooks (.ipynb) with AI library usage."""

    sbom: ScanSinglePath | None = None
    """Path to an existing CycloneDX / SPDX SBOM file."""

    external_scan: ScanSinglePath | None = None
    """Path to an external scanner JSON report (Trivy, Grype, Syft, SARIF)."""

    vex: ScanSinglePath | None = None
    """Path to a VEX document (OpenVEX JSON) to apply before result serialization."""

    enrich: bool = False
    """Enrich with NVD CVSS, EPSS, and CISA KEV data."""

    ai_enrich: bool = False
    """Add advisory AI classification/triage and narratives without changing deterministic findings."""

    ai_model: str = Field(default="openai/gpt-4o-mini", max_length=256)
    """Provider/model identifier used when ``ai_enrich`` is enabled."""

    ai_deterministic: bool | None = None
    """Optional per-request temperature-zero override; ``None`` inherits deployment policy."""

    offline: bool = False
    """Use the local vulnerability DB only; do not perform network vulnerability lookups."""

    dry_run: bool = False
    """Validate and preview the scan request without discovery, vulnerability scanning, or result side effects."""

    no_scan: bool = False
    """Run discovery and package extraction only; skip vulnerability scanning and result side effects."""

    auto_update_db: bool = False
    """Explicitly refresh the local vulnerability DB before scanning when stale."""

    db_sources: str | None = None
    """Comma-separated vulnerability DB sources to refresh when auto_update_db is enabled."""

    connectors: list[ScanConnectorName] = Field(default_factory=list)
    """SaaS connectors to discover from (e.g. ['jira', 'servicenow', 'slack'])."""

    filesystem_paths: list[ScanPathEntry] = Field(default_factory=list)
    """Filesystem directories or tar archives to scan via Syft."""

    format: Literal["json", "cyclonedx", "sarif", "spdx", "html", "text"] = "json"
    """Output format for the completed result.

    ``json`` (the default) leaves the AI-BOM JSON in ``ScanJob.result``; every
    other value renders that report through
    :func:`agent_bom.output.scan_document.render_scan_document` into
    ``ScanJob.result_document``. The enum must stay identical to
    ``SCAN_DOCUMENT_FORMATS`` — a published value with no renderer behind it is
    a false contract (locked by ``tests/api/test_api_scan_format_contract.py``).
    """

    dynamic_discovery: bool = False
    """Enable dynamic content-based MCP config discovery."""

    dynamic_max_depth: int = 4
    """Max directory depth for dynamic discovery."""

    discover_host: bool = False
    """Also discover the server host's ambient MCP configuration (~/.claude,
    ~/.cursor, …). Off by default: on the hosted/multi-tenant scan path the
    server host is not the tenant's estate, so sweeping it would fold the
    server's own AI clients into a tenant's results. Opt in only for
    self-hosted single-tenant deployments where the host IS the scan target.
    Requires operator-enabled local scans and AGENT_BOM_API_HOST_DISCOVERY_TENANT
    matching the authenticated tenant; the request flag cannot grant access."""

    scope_agents: list[ScanGlobPattern] = Field(default_factory=list)
    """Filter discovered agents by name (glob patterns, e.g. ['claude-*', 'cursor'])."""

    scope_servers: list[ScanGlobPattern] = Field(default_factory=list)
    """Filter discovered MCP servers by name (glob patterns)."""

    exclude_agents: list[ScanGlobPattern] = Field(default_factory=list)
    """Exclude agents matching these name patterns."""

    exclude_servers: list[ScanGlobPattern] = Field(default_factory=list)
    """Exclude MCP servers matching these name patterns."""

    min_severity: Annotated[
        Literal["low", "medium", "high", "critical"] | None,
        Field(json_schema_extra=_stabilize_scan_severity_schema),
    ] = None
    """Minimum severity to include in results (low/medium/high/critical)."""

    @field_validator("format", "min_severity", mode="before")
    @classmethod
    def _normalize_enum_case(cls, value: Any) -> Any:
        """Accept case/whitespace variants (e.g. ``HIGH``/``JSON``) before the
        Literal constraint validates, so tightening the field does not reject
        inputs the pipeline previously lower-cased at read time."""
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @model_validator(mode="after")
    def _enforce_batch_target_cap(self) -> "ScanRequest":
        """Bound per-request fan-out so one request cannot enqueue unbounded work."""
        total = sum(len(getattr(self, name)) for name in _BATCH_LIST_TARGET_FIELDS)
        total += sum(1 for name in _BATCH_SINGLE_TARGET_FIELDS if getattr(self, name))
        if self.k8s:
            total += 1
        if total > API_MAX_BATCH_SCAN_TARGETS:
            raise ValueError(f"scan request expands to {total} targets; maximum is {API_MAX_BATCH_SCAN_TARGETS} per request")
        return self

    @model_validator(mode="after")
    def _validate_repo_url_exclusive(self) -> "ScanRequest":
        """``repo_url`` mirrors CLI ``--repo`` and cannot mix with local path targets."""
        repo_url = (self.repo_url or "").strip()
        if not repo_url:
            return self
        if self.offline:
            raise ValueError("offline mode cannot clone a remote repo_url; drop offline or scan a local path instead")
        conflicts: list[str] = []
        if self.agent_projects:
            conflicts.append("agent_projects")
        if self.gha_path:
            conflicts.append("gha_path")
        if self.tf_dirs:
            conflicts.append("tf_dirs")
        if self.inventory:
            conflicts.append("inventory")
        if self.jupyter_dirs:
            conflicts.append("jupyter_dirs")
        if self.filesystem_paths:
            conflicts.append("filesystem_paths")
        if self.sbom:
            conflicts.append("sbom")
        if self.external_scan:
            conflicts.append("external_scan")
        if self.vex:
            conflicts.append("vex")
        if conflicts:
            joined = ", ".join(conflicts)
            raise ValueError(f"repo_url is mutually exclusive with local path targets: {joined}")
        return self


class ScanJob(BaseModel):
    """Represents a running or completed scan job."""

    # Ephemeral dispatch ownership, never accepted from or serialized to clients.
    _dispatch_claim_owner: str | None = PrivateAttr(default=None)

    job_id: str
    tenant_id: str = "default"
    batch_id: str | None = None
    correlation_cohort_id: str | None = None
    correlation_cohort_manifest_hash: str | None = None
    correlation_max_age_hours: int | None = None
    parent_job_id: str | None = None
    child_job_ids: list[str] = Field(default_factory=list)
    target: dict[str, Any] | None = None
    target_index: int | None = None
    target_count: int | None = None
    source_id: str | None = None
    schedule_id: str | None = None
    triggered_by: str | None = None
    status: JobStatus = JobStatus.PENDING
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    request: ScanRequest
    progress: list[str] = Field(default_factory=list)
    result: dict[str, Any] | None = None
    result_document: dict[str, Any] | str | None = None
    """The completed result rendered in ``request.format``.

    ``None`` while the job is running, and for ``format=json`` — the default —
    because ``result`` already *is* the AI-BOM JSON and a second copy would only
    double the payload. Any other requested format renders here, so the enum
    published on ``ScanRequest.format`` changes what the caller gets instead of
    being silently ignored.
    """
    error: str | None = None

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def result_format(self) -> str:
        """Which format ``result_document`` (or ``result``, for json) is in."""
        return self.request.format

    def model_post_init(self, __context: Any) -> None:
        if not isinstance(self.progress, _BoundedProgress):
            self.progress = _BoundedProgress(self.progress)

    @field_serializer("request", return_type=ScanRequest)
    def _serialize_request(self, value: ScanRequest) -> ScanRequest:
        from agent_bom.security import sanitize_sensitive_payload

        sanitized = sanitize_sensitive_payload(value.model_dump())
        payload = sanitized if isinstance(sanitized, dict) else {}
        result: ScanRequest = ScanRequest.model_validate(payload)
        return result

    @field_serializer("progress", return_type=list[str])
    def _serialize_progress(self, value: list[str]) -> list[str]:
        from agent_bom.security import sanitize_sensitive_payload

        sanitized = sanitize_sensitive_payload(value)
        return sanitized if isinstance(sanitized, list) else []


class ReportJobRequest(_ReportJobRequest):
    """Public findings report request schema."""


class ReportJob(BaseModel):
    """Async findings export job backed by streamed hub reads."""

    job_id: str
    tenant_id: str = "default"
    status: JobStatus = JobStatus.PENDING
    format: ReportFormat = ReportFormat.NDJSON
    sort: str = "effective_reach"
    severity: str | None = None
    q: str | None = None
    scan_id: str | None = None
    provider: str | None = None
    account: str | None = None
    environment: str | None = None
    domain: str | None = None
    owner: str | None = None
    sla: Literal["overdue", "due", "unassigned"] | None = None
    lane: str | None = Field(default=None, max_length=32)
    finding_class: FindingClass | None = None
    finding_status: Literal["open", "resolved", "all"] = "open"
    window_days: int | None = None
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    row_count: int | None = None
    byte_count: int | None = None
    download_token: str | None = None
    artifact_backend: Literal["local", "s3"] | None = None
    artifact_uri: str | None = None
    presigned_download_url: str | None = None
    error: str | None = None

    model_config = ConfigDict(arbitrary_types_allowed=True)


# ─── Meta Models ───────────────────────────────────────────────────────────


# ─── Fleet Models ──────────────────────────────────────────────────────────


class StateUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: str
    reason: str = ""


class FleetAgentUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    owner: str | None = None
    environment: str | None = None
    tags: list[str] | None = None
    notes: str | None = None


# ─── Gateway Models ───────────────────────────────────────────────────────


class PolicyCreate(_policy_inputs.PolicyRuleValidation):
    model_config = ConfigDict(extra="forbid")
    name: str
    description: str = ""
    mode: str = "audit"
    rules: list[dict[str, Any]] = Field(default_factory=list)
    bound_agents: list[str] = Field(default_factory=list)
    bound_agent_types: list[str] = Field(default_factory=list)
    bound_environments: list[str] = Field(default_factory=list)
    enabled: bool = True


class PolicyUpdate(_policy_inputs.PolicyRuleValidation):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    description: str | None = None
    mode: str | None = None
    rules: list[dict[str, Any]] | None = None
    bound_agents: list[str] | None = None
    bound_agent_types: list[str] | None = None
    bound_environments: list[str] | None = None
    enabled: bool | None = None


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    agent_name: str = ""
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class ProxyAuditIngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_id: str = Field(default="", max_length=200)
    session_id: str = ""
    idempotency_key: str = ""
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, Any] | None = None


class SAMLLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    saml_response: str
    relay_state: str | None = None


# ─── Scan Type Request Models ─────────────────────────────────────────────


class DatasetCardsRequest(BaseModel):
    """Request body for POST /v1/scan/dataset-cards."""

    model_config = ConfigDict(extra="forbid")

    directories: list[str]
    """Directories to scan for dataset cards (dataset_info.json, README.md, .dvc)."""


class TrainingPipelinesRequest(BaseModel):
    """Request body for POST /v1/scan/training-pipelines."""

    model_config = ConfigDict(extra="forbid")

    directories: list[str]
    """Directories to scan for ML training artifacts (MLflow, W&B, Kubeflow)."""


class BrowserExtensionsRequest(BaseModel):
    """Request body for POST /v1/scan/browser-extensions."""

    model_config = ConfigDict(extra="forbid")

    include_low_risk: bool = False
    """Include low-risk extensions (default: only medium+ risk)."""


class ModelProvenanceRequest(BaseModel):
    """Request body for POST /v1/scan/model-provenance."""

    model_config = ConfigDict(extra="forbid")

    hf_models: list[str] = Field(default_factory=list)
    """HuggingFace model IDs to check (e.g. ['meta-llama/Llama-2-7b-hf'])."""

    ollama_models: list[str] = Field(default_factory=list)
    """Ollama model names to check (e.g. ['llama2', 'codellama'])."""


class PromptScanRequest(BaseModel):
    """Request body for POST /v1/scan/prompt-scan."""

    model_config = ConfigDict(extra="forbid")

    directories: list[str] = Field(default_factory=list)
    """Directories to scan for prompt files (.prompt, prompt.yaml, etc.)."""

    files: list[str] = Field(default_factory=list)
    """Specific prompt files to scan."""


class ModelFilesRequest(BaseModel):
    """Request body for POST /v1/scan/model-files."""

    model_config = ConfigDict(extra="forbid")

    directories: list[str]
    """Directories to scan for ML model files (.pt, .pkl, .safetensors, .gguf, etc.)."""

    verify_hashes: bool = False
    """Compute SHA-256 hashes for each model file."""


# ─── Push / Schedule / Auth / Exception Models ────────────────────────────


class ScanIssuePayload(BaseModel):
    """Bounded execution issue accepted from a trusted scan producer."""

    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=1, max_length=100)
    stage: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=200)
    message: str = Field(min_length=1, max_length=1000)
    severity: Literal["warning", "error"] = "warning"
    affects_coverage: bool = True


class ScanScopePayload(BaseModel):
    """Bounded completeness metadata for one requested collection scope."""

    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100)
    status: Literal["complete", "partial", "unsupported", "unavailable", "permission_denied", "skipped"]
    requested: bool = True
    item_count: int | None = Field(default=None, ge=0)
    message: str = Field(default="", max_length=500)


class ScanRunPayload(BaseModel):
    """Canonical evidence-quality contract, separate from job lifecycle."""

    model_config = ConfigDict(extra="allow")
    outcome: Literal["complete", "partial", "failed"] = "complete"
    issues: list[ScanIssuePayload] = Field(default_factory=list, max_length=100)
    scopes: list[ScanScopePayload] = Field(default_factory=list, max_length=100)
    warning_count: int = Field(default=0, ge=0, le=100)
    requested_scope_count: int = Field(default=0, ge=0, le=100)
    complete_scope_count: int = Field(default=0, ge=0, le=100)
    incomplete_scope_count: int = Field(default=0, ge=0, le=100)


class CorrelationCohortChildReceipt(BaseModel):
    """Signed assignment for one external producer in an immutable cohort."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["agent-bom.correlation-cohort-child/v1"] = "agent-bom.correlation-cohort-child/v1"
    tenant_id: str = Field(min_length=1, max_length=256)
    correlation_cohort_id: str = Field(min_length=36, max_length=36)
    cohort_manifest_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    parent_job_id: str = Field(min_length=36, max_length=36)
    child_job_id: str = Field(min_length=36, max_length=36)
    source_id: str = Field(min_length=1, max_length=200)
    source_kind: Literal["ingest.result_push", "runtime.proxy", "runtime.gateway"]
    max_age_hours: int = Field(ge=1, le=8760)
    issued_at: str = Field(min_length=1, max_length=64)
    expires_at: str = Field(min_length=1, max_length=64)
    signature: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class PushPayload(_PushEvidencePayload):
    model_config = ConfigDict(extra="allow")

    scan_run: ScanRunPayload | None = None
    correlation_cohort_id: str | None = Field(default=None, min_length=36, max_length=36)
    correlation_child_receipt: CorrelationCohortChildReceipt | None = None


class ScheduleCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    cron_expression: str
    scan_config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    tenant_id: str = "default"


class SourceCohortRunResponse(BaseModel):
    correlation_cohort_id: str
    cohort_manifest_hash: str
    parent_job_id: str
    child_job_ids: list[str]
    source_ids: list[str]
    max_age_hours: int
    status: JobStatus
    auto_correlation: dict[str, Any] | None = None
    child_receipts: list[CorrelationCohortChildReceipt] = Field(default_factory=list)


class RuntimeEvidenceSignalIn(BaseModel):
    """One raw CWPP runtime/EDR signal in an ingest batch.

    Tenant/provider/account are NOT taken from the client here — they come from
    the authenticated source (confused-deputy guard in ``build_runtime_signal``).
    ``provider``/``account_id`` may be echoed for the source's own bookkeeping but
    a mismatch against the authenticated source is rejected.
    """

    model_config = ConfigDict(extra="forbid")
    workload_ref: str
    signal_type: str
    dedup_key: str
    severity: str = "unknown"
    observed_at: str = Field(
        ...,
        description="Source observation time in ISO-8601 form; required and normalized to fixed-width UTC on ingest.",
    )
    title: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    provider: str | None = None
    account_id: str | None = None


class RuntimeEvidenceIngestRequest(BaseModel):
    """Authenticated, tenant-scoped CWPP runtime workload-evidence ingest batch."""

    model_config = ConfigDict(extra="forbid")
    source_id: str
    validate_only: bool = False
    reason: str = Field(default="Runtime evidence ingestion", min_length=8, max_length=1024)
    signals: list[RuntimeEvidenceSignalIn] = Field(default_factory=list, max_length=1000)
    correlation_cohort_id: str | None = Field(default=None, min_length=36, max_length=36)
    correlation_child_receipt: CorrelationCohortChildReceipt | None = None


class SideScanTriggerRequest(BaseModel):
    """Trigger one cross-cloud (Azure/GCP) agentless disk side-scan (#4158 Wave 2).

    The authenticated, tenant-scoped door for the shipped
    ``run_provider_side_scan`` executor that previously ran only from the CLI.
    Read-only toward customer targets: agent-bom snapshots the disk, mounts a
    temp copy on an in-account collector read-only, records SBOM + CVE + secret
    *metadata* only, and attempts cleanup of owned temporary resources. Credentials
    are never embedded and never accepted here — the executor resolves scoped
    lifecycle credentials from the provider's default chain. AWS EBS keeps its own CLI
    entrypoint (its results are not persisted to the shared lifecycle store).
    """

    model_config = ConfigDict(extra="forbid")
    provider: Literal["azure", "gcp"]
    target_id: Annotated[str, Field(min_length=1, max_length=1024, description="Managed/persistent disk resource id to scan.")]
    account_id: Annotated[
        str, Field(min_length=1, max_length=256, description="Azure subscription id / GCP project id owning the disk + collector.")
    ]
    location: Annotated[
        str, Field(min_length=1, max_length=128, description="Azure location / GCP zone of the temp disk (must match the collector).")
    ]
    collector_id: Annotated[
        str, Field(min_length=1, max_length=256, description="In-account collector VM/instance the temp disk attaches to.")
    ]
    collector_resource_group: Annotated[
        str | None, Field(default=None, max_length=256, description="Azure only: resource group of the collector VM.")
    ] = None
    region: Annotated[
        str | None, Field(default=None, max_length=64, description="Optional provider region hint for client construction.")
    ] = None
    idempotency_key: Annotated[
        str | None, Field(default=None, max_length=128, description="Retry-safe key; the same key reuses one execution record.")
    ] = None
    scan_secrets_enabled: bool = True


class CreateKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    role: str = "viewer"
    expires_at: str | None = None
    scopes: list[str] = Field(default_factory=list)
    scim_subject_id: str | None = None
    # User this key is issued on behalf of (e.g. a SCIM user_id/user_name). Lets
    # deprovisioning revoke free-form CI keys that don't name the departing user.
    owner: str | None = None
    # Canonical stable principal id to bind this key to. When omitted the store
    # derives it from scim_subject_id → owner. Deprovisioning a subject revokes
    # every key keyed to its principal_id.
    principal_id: str | None = None

    @field_validator("scopes")
    @classmethod
    def reject_reserved_session_markers(cls, scopes: list[str]) -> list[str]:
        reserved = {"saml-session", "browser-session", "oidc-session"}
        rejected = sorted(reserved.intersection(scopes))
        if rejected:
            raise ValueError(f"reserved session marker cannot be used as an API key scope: {', '.join(rejected)}")
        return scopes


class RotateKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = None
    expires_at: str | None = None
    overlap_seconds: int | None = None


class InvitationRequest(BaseModel):
    """Body for POST /v1/auth/invitations — admin provisions a NEW tenant.

    Deliberately never accepts a provider secret / credential: the endpoint
    MINTS a key, it does not take one (connect-once model, §11). ``extra`` is
    forbidden so a stray secret field is rejected with 422 rather than ignored.
    """

    model_config = ConfigDict(extra="forbid")
    organization: str | None = None
    role: str = "admin"
    email: str | None = None
    expires_at: str | None = None


class TenantQuotaUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    active_scan_jobs: int | None = Field(default=None, ge=0)
    retained_scan_jobs: int | None = Field(default=None, ge=0)
    fleet_agents: int | None = Field(default=None, ge=0)
    schedules: int | None = Field(default=None, ge=0)
    cloud_connections: int | None = Field(default=None, ge=0)
    cloud_connections_per_provider: int | None = Field(default=None, ge=0)
    scan_credits_24h: int | None = Field(default=None, ge=0)


class ExecScoreConfigUpdateRequest(BaseModel):
    """Body for PUT /v1/overview/score-config (issue #3940).

    Lenient about *values*: they are canonicalized / clamped server-side (see
    ``agent_bom.exec_score.canonicalize_config``) so an out-of-range weight or
    an invalid display format never raises.

    Strict about *keys*, like every other write body. A misspelled top-level
    field used to be dropped silently and the response still reported the
    override as active — a config write that says it applied while having
    changed nothing.
    """

    model_config = ConfigDict(extra="forbid")
    weights: dict[str, Any] | None = None
    grade_thresholds: dict[str, Any] | None = None
    display_format: str | None = None


class ExceptionRequest(_policy_inputs.ExceptionExpiryValidation):
    model_config = ConfigDict(extra="forbid")
    vuln_id: str
    package_name: str
    server_name: str = ""
    reason: str = ""
    requested_by: str = ""
    expires_at: str = ""
    tenant_id: str = "default"


class IssueStatusUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(..., min_length=1, max_length=64)


class FalsePositiveRequest(BaseModel):
    """Request body for POST /v1/findings/false-positive."""

    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str
    package: str
    reason: str = ""
    marked_by: str = ""


FindingFeedbackState = Literal["false_positive", "accepted_risk", "not_affected", "not_applicable", "fixed_verified", "needs_review"]
FindingTriageQueueState = Literal["open", "assigned", "reviewing", "decided"]
FindingTriageDecision = Literal["not_affected", "affected", "under_investigation"]
FindingTriageJustification = Literal[
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
]


class FindingFeedbackRequest(_policy_inputs.ExceptionExpiryValidation):
    """Request body for POST /v1/findings/feedback."""

    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str = Field(..., min_length=1, max_length=128)
    package: str = Field("*", min_length=1, max_length=256)
    state: FindingFeedbackState = "false_positive"
    reason: str = Field("", max_length=2000)
    server_name: str = Field("", max_length=256)
    expires_at: str = Field("", max_length=64)


class FindingTriageRequest(_policy_inputs.ExceptionExpiryValidation):
    """Request body for POST /v1/findings/triage."""

    model_config = ConfigDict(extra="forbid")

    vulnerability_id: str = Field(..., min_length=1, max_length=128)
    package: str = Field("*", min_length=1, max_length=256)
    server_name: str = Field("", max_length=256)
    assignee: str = Field("", max_length=256)
    queue_state: FindingTriageQueueState = "open"
    decision: FindingTriageDecision = "under_investigation"
    justification: FindingTriageJustification | None = None
    decision_reason: str = Field("", max_length=2000)
    expires_at: str = Field("", max_length=64)


class FindingTriageVexIngestRequest(BaseModel):
    """Request body for POST /v1/findings/triage/vex/ingest.

    Accepts an OpenVEX (or CycloneDX/CSAF) VEX document and applies its
    ``not_affected`` / ``fixed`` statements as tenant-scoped triage suppressions.
    """

    model_config = ConfigDict(extra="forbid")

    vex: dict[str, Any] = Field(..., description="A decoded VEX document (OpenVEX @context + statements).")


class FindingTriageDecisionRequest(_policy_inputs.ExceptionExpiryValidation):
    """Request body for PUT /v1/findings/triage/{triage_id}/decision."""

    model_config = ConfigDict(extra="forbid")

    decision: FindingTriageDecision
    justification: FindingTriageJustification | None = None
    decision_reason: str = Field("", max_length=2000)
    assignee: str | None = Field(None, max_length=256)
    expires_at: str | None = Field(None, max_length=64)


class InventoryPackageResponse(BaseModel):
    """One package occurrence in the scanned estate; empty IDs are unknown."""

    name: str
    version: str
    ecosystem: str
    agent: str
    server: str
    agent_id: str = ""
    server_id: str = ""
    environment: str = ""


class InventoryResponse(BaseModel):
    scope: Literal["scanned_estate"]
    source: str
    agents: list[dict[str, Any]]
    packages: list[InventoryPackageResponse]
    jobs: list[dict[str, str]]
    count: int = Field(ge=0)
    total: int = Field(ge=0)
    package_count: int = Field(ge=0)
    package_total: int = Field(ge=0)
    job_count: int = Field(ge=0)
    job_total: int = Field(ge=0)
    limit: int = Field(ge=1, le=1000)
    offset: int = Field(ge=0)
    has_more: bool
    warnings: list[str]


class AgentBomManifestServerResponse(BaseModel):
    """Identified server entity with preserved observation membership."""

    model_config = ConfigDict(extra="allow")
    id: str
    canonical_id: str
    agent_name: str = ""
    agent_names: list[str] = Field(default_factory=list)
    agent_ids: list[str] = Field(default_factory=list)
    agent_binding: Literal["inventory_identity", "unbound"] = "unbound"
    server_stable_id: str = ""
    identity_basis: Literal["server_identity", "observation"] = "observation"
    observation_ids: list[str] = Field(default_factory=list)
    observations: list[dict[str, Any]] = Field(default_factory=list)


class AgentBomManifestResponse(BaseModel):
    """Typed identity/count boundary; other manifest sections remain additive."""

    model_config = ConfigDict(extra="allow")
    schema_version: Literal["agent-bom.manifest/v1"]
    agents: list[dict[str, Any]]
    mcp_servers: list[AgentBomManifestServerResponse]
    summary: dict[str, int]


if TYPE_CHECKING:
    from agent_bom.api.compliance_models import ComplianceAuditIntegrity as ComplianceAuditIntegrity
    from agent_bom.api.compliance_models import ComplianceEvidenceItem as ComplianceEvidenceItem
    from agent_bom.api.compliance_models import ComplianceReportBundle as ComplianceReportBundle
    from agent_bom.api.compliance_models import ComplianceReportControl as ComplianceReportControl
    from agent_bom.api.compliance_models import ComplianceReportScope as ComplianceReportScope
    from agent_bom.api.compliance_models import ComplianceReportSummary as ComplianceReportSummary
    from agent_bom.api.compliance_models import ComplianceSignatureDisclosure as ComplianceSignatureDisclosure
    from agent_bom.api.compliance_models import ComplianceThreatModel as ComplianceThreatModel
    from agent_bom.api.health_models import AnalyticsHealth as AnalyticsHealth
    from agent_bom.api.health_models import EntitlementHealth as EntitlementHealth
    from agent_bom.api.health_models import HealthResponse as HealthResponse
    from agent_bom.api.health_models import PostgresPortabilityHealth as PostgresPortabilityHealth
    from agent_bom.api.health_models import PublicHealthResponse as PublicHealthResponse
    from agent_bom.api.health_models import StorageHealth as StorageHealth
    from agent_bom.api.health_models import TracingHealth as TracingHealth
    from agent_bom.api.health_models import VersionInfo as VersionInfo
    from agent_bom.api.source_models import CredentialRefCreate as CredentialRefCreate
    from agent_bom.api.source_models import CredentialRefRecord as CredentialRefRecord
    from agent_bom.api.source_models import CredentialRefStatus as CredentialRefStatus
    from agent_bom.api.source_models import CredentialRefUpdate as CredentialRefUpdate
    from agent_bom.api.source_models import SourceCohortRunRequest as SourceCohortRunRequest
    from agent_bom.api.source_models import SourceCreate as SourceCreate
    from agent_bom.api.source_models import SourceCredentialMode as SourceCredentialMode
    from agent_bom.api.source_models import SourceKind as SourceKind
    from agent_bom.api.source_models import SourceRecord as SourceRecord
    from agent_bom.api.source_models import SourceStatus as SourceStatus
    from agent_bom.api.source_models import SourceUpdate as SourceUpdate


_MODEL_EXPORTS = {
    "SourceKind": "agent_bom.api.source_models",
    "SourceStatus": "agent_bom.api.source_models",
    "SourceCredentialMode": "agent_bom.api.source_models",
    "CredentialRefStatus": "agent_bom.api.source_models",
    "CredentialRefRecord": "agent_bom.api.source_models",
    "CredentialRefCreate": "agent_bom.api.source_models",
    "CredentialRefUpdate": "agent_bom.api.source_models",
    "SourceRecord": "agent_bom.api.source_models",
    "SourceCreate": "agent_bom.api.source_models",
    "SourceUpdate": "agent_bom.api.source_models",
    "SourceCohortRunRequest": "agent_bom.api.source_models",
    "VersionInfo": "agent_bom.api.health_models",
    "TracingHealth": "agent_bom.api.health_models",
    "AnalyticsHealth": "agent_bom.api.health_models",
    "PostgresPortabilityHealth": "agent_bom.api.health_models",
    "StorageHealth": "agent_bom.api.health_models",
    "EntitlementHealth": "agent_bom.api.health_models",
    "PublicHealthResponse": "agent_bom.api.health_models",
    "HealthResponse": "agent_bom.api.health_models",
    "ComplianceEvidenceItem": "agent_bom.api.compliance_models",
    "ComplianceReportControl": "agent_bom.api.compliance_models",
    "ComplianceReportScope": "agent_bom.api.compliance_models",
    "ComplianceReportSummary": "agent_bom.api.compliance_models",
    "ComplianceAuditIntegrity": "agent_bom.api.compliance_models",
    "ComplianceThreatModel": "agent_bom.api.compliance_models",
    "ComplianceSignatureDisclosure": "agent_bom.api.compliance_models",
    "ComplianceReportBundle": "agent_bom.api.compliance_models",
}


def __getattr__(name: str) -> Any:
    module_name = _MODEL_EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | _MODEL_EXPORTS.keys())
