"""agent-bom MCP Server — expose security scanning as MCP tools.

Start with:
    agent-bom mcp server                          # stdio (for Claude Desktop, Cursor, etc.)
    agent-bom mcp server --transport sse          # SSE transport (for remote clients)
    agent-bom mcp server --transport streamable-http

Default: 8 focused tools; select a task profile with --profile.
Full profile Tools (97):
    scan                — Full discovery → scan → output pipeline
    check               — Check a specific package for CVEs before installing
    intel_lookup        — Look up a CVE, GHSA, or OSV advisory from local threat intel
    affected_assets     — List the scanned assets an advisory affects, with patch targets
    intel_match         — Match package inventory coordinates to local advisory intel
    intel_sources       — Return canonical intel sources and local feed-run freshness
    intel_daily_brief   — Return a local analyst threat brief from governed intel sources
    youcom_search       — Search You.com for current web/news context when YDC_API_KEY is configured
    blast_radius        — Look up blast radius for a specific CVE
    exposure_paths      — Return ranked ExposurePath JSON for headless agents and MCP clients
    graph_correlate     — Create an immutable correlation from exact snapshot receipts
    graph_correlation_status — Read correlation state, receipts, and analysis bounds
    should_i_deploy     — Return allow/warn/block from every matching ExposurePath
    graph_reach         — Page what can reach a node (or what it reaches) over recorded edges
    graph_diff          — What changed between two graph snapshots (summary or paged rows)
    cross_vendor_paths  — Attack paths whose source and target sit in different vendors
    findings_query      — Query tenant findings exactly as /v1/findings, compact rows
    finding_detail      — One finding with its graph paths, reachers and triage state
    policy_check        — Evaluate a policy against scan results
    registry_lookup     — Query the MCP server security metadata registry
    generate_sbom       — Generate CycloneDX or SPDX SBOM
    compliance          — Persisted tenant compliance posture (labelled local scan fallback)
    remediate           — Generate actionable remediation plan
    skill_scan          — Scan instruction files for packages, servers, trust, and findings
    skill_verify        — Verify instruction file Sigstore provenance
    skill_trust         — ClawHub-style trust assessment for SKILL.md files
    verify              — Package integrity + SLSA provenance verification
    inventory_summary   — Unified asset-inventory counts by type and source group
    inventory_list      — Faceted, paginated asset rows across the unified graph
    inventory_asset     — Asset attributes and bounded recorded relationships
    where               — Show all MCP discovery paths + existence status
    inventory           — List agents/servers without CVE scanning
    tool_risk_assessment — Score live MCP tool capabilities and server risk
    diff                — Compare scan against baseline for new/resolved vulns
    marketplace_check   — Pre-install trust check with registry cross-reference
    code_scan           — SAST scanning via Semgrep with CWE-based compliance mapping
    context_graph       — Agent context graph with lateral movement analysis
    graph_export        — Export dependency graph (GraphML, Neo4j Cypher, DOT, JSON-LD)
    analytics_query     — Query vulnerability trends and runtime events from ClickHouse
    cis_benchmark       — Run CIS benchmark checks against cloud accounts
    kspm_cluster_posture — Evaluate live Kubernetes cluster posture vs CIS Kubernetes Benchmark
    fleet_scan          — Batch registry lookup for fleet inventories
    runtime_correlate   — Cross-reference runtime audit logs with CVE findings
    runtime_production_index — Runtime production posture summary
    runtime_blueprints  — Role/profile blueprints for runtime policy design
    runtime_blueprint_drift — Evaluate runtime posture against a blueprint
    cost_report         — LLM spend attribution per agent/model/provider with budget posture
    anomaly_scan        — Detect cost and behavior anomalies
    drift_incidents     — List open blueprint-drift incidents
    proxy_status        — Current MCP proxy metrics and alert posture
    proxy_alerts        — Recent tenant-scoped runtime proxy alerts
    gateway_status      — Gateway policy and firewall runtime statistics
    shield_status       — Shield session status without changing enforcement
    shield_start        — Start Shield enforcement with admin/scope/audit gating
    shield_unblock      — Unblock Shield enforcement with admin/scope/audit gating
    shield_break_glass  — Emergency Shield override with admin/scope/audit gating
    identity_issue      — Issue a managed agent identity with admin/scope/audit gating
    identity_rotate     — Rotate a managed identity with an overlap window
    identity_revoke     — Revoke a managed identity immediately
    identity_grant_jit  — Grant time-bound JIT access to one tool
    identity_revoke_jit — Revoke an active JIT access grant immediately
    firewall_check      — Read-only inter-agent firewall decision dry run
    audit_query         — Tenant-scoped control-plane audit records
    audit_integrity     — Control-plane and runtime audit-chain verification
    vector_db_scan      — Scan vector databases for embedding poisoning and access risks
    aisvs_benchmark     — OWASP AI Security Verification Standard benchmark
    gpu_infra_scan      — Scan GPU infrastructure for CVEs and misconfigurations
    registry_sweep_scan — Sweep a cloud registry (ECR/ACR/GAR) and scan unique images
    dataset_card_scan   — Scan dataset cards for licensing and provenance
    training_pipeline_scan — Scan training pipeline artifacts for lineage
    browser_extension_scan — Scan browser extensions for dangerous permissions
    model_provenance_scan  — Check ML model provenance from HuggingFace/Ollama
    prompt_scan         — Scan prompt templates for injection risks
    model_file_scan     — Scan model files for serialization risks
    ai_inventory_scan   — Scan source code for AI SDK imports, model references, shadow AI
    license_compliance_scan — Evaluate package licenses against SPDX compliance policy
    ingest_external_scan   — Ingest tool-agnostic SARIF, SBOM, or scanner JSON with blast radius analysis
    runtime_evidence_ingest — Ingest CWPP runtime/EDR workload signals (authenticated source; metadata only)
    cost_forecast       — Project LLM spend burn rate and budget runway
    cost_allocation     — Chargeback / showback spend rollups by cost-center and tag
    credential_expiry   — Expiring / overdue credential and rotation posture
    nhi_discover        — Discover non-human identities (Okta / Entra), reference-only
    cloud_inventory     — Estate-wide cloud asset inventory summary, opt-in per provider
    endpoint_inventory  — Scoped Jamf/Falcon inventory with freshness and collection gaps
    endpoint_sync       — Collect vendor inventory through stored credentials, admin-gated
    access_review       — List or get NHI access-review / recertification campaigns
    create_ticket       — File an ITSM ticket for a finding through a stored connector
    sync_ticket_status  — Refresh a filed ITSM ticket's status through the stored connector

Resources (6):
    registry://servers  — Browse the 1256-entry server security metadata registry
    policy://template   — Default security policy template
    metrics://tools     — MCP tool execution metrics and limits
    schema://inventory-v1 — Canonical pushed-inventory schema contract
    bestpractices://mcp-hardening — NSA-informed MCP hardening control mapping
    compliance://framework-controls — Framework coverage and evidence mapping

Security: read-mostly. Scanner, graph, audit, and runtime posture tools are
read-only. Shield write tools require explicit admin role, shield:write scope,
and audit reason, and never read credential values.
"""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import re
import time
from collections import OrderedDict, deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Awaitable, Callable, Optional, TypeVar

from mcp_types import CallToolResult, TextContent, ToolAnnotations
from pydantic import Field

from agent_bom import mcp_server_runtime as _mcp_runtime
from agent_bom import mcp_server_scan as _mcp_scan
from agent_bom.config import MCP_CALLER_RATE_LIMIT as _MCP_CALLER_RATE_LIMIT
from agent_bom.config import MCP_CALLER_WINDOW_SECONDS as _MCP_CALLER_WINDOW_SECONDS
from agent_bom.config import MCP_GLOBAL_RATE_LIMIT as _MCP_GLOBAL_RATE_LIMIT
from agent_bom.config import MCP_GLOBAL_WINDOW_SECONDS as _MCP_GLOBAL_WINDOW_SECONDS
from agent_bom.config import MCP_MAX_CALLER_STATES as _MCP_MAX_CALLER_STATES
from agent_bom.config import MCP_MAX_CONCURRENT_TOOLS as _MCP_MAX_CONCURRENT_TOOLS
from agent_bom.config import MCP_MAX_FILE_SIZE as _MAX_FILE_SIZE  # noqa: F401 - retained public test import
from agent_bom.config import MCP_MAX_REQUEST_TRACES as _MCP_MAX_REQUEST_TRACES
from agent_bom.config import MCP_MAX_RESPONSE_CHARS as _MAX_RESPONSE_CHARS
from agent_bom.config import MCP_MAX_TOOL_METRICS as _MCP_MAX_TOOL_METRICS
from agent_bom.config import MCP_TOOL_TIMEOUT_SECONDS as _MCP_TOOL_TIMEOUT_SECONDS
from agent_bom.ecosystems import SUPPORTED_PACKAGE_ECOSYSTEM_SET
from agent_bom.mcp_server_catalog import (
    attach_resources_and_prompts as _attach_resources_and_prompts,
)
from agent_bom.mcp_server_entrypoint import create_smithery_server as _create_smithery_server
from agent_bom.mcp_server_factory import (
    create_fastmcp_server as _create_fastmcp_server,
)
from agent_bom.mcp_server_metadata import (
    _SERVER_CARD_PROMPTS as _METADATA_SERVER_CARD_PROMPTS,
)
from agent_bom.mcp_server_metadata import (
    _SERVER_CARD_TOOLS as _METADATA_SERVER_CARD_TOOLS,
)
from agent_bom.mcp_server_metadata import (
    attach_metadata_routes,
)
from agent_bom.mcp_server_metadata import (
    build_server_card as _metadata_build_server_card,
)
from agent_bom.mcp_server_runtime_catalog import (
    register_runtime_catalog_tools as _register_runtime_catalog_tools,
)
from agent_bom.mcp_tools.assessment_registration import register_assessment_tools
from agent_bom.mcp_tools.graph_registration import register_graph_agent_tools
from agent_bom.mcp_tools.intel_registration import register_intel_tools
from agent_bom.mcp_tools.inventory_registration import register_inventory_asset_tool
from agent_bom.mcp_tools.profiles import _GUIDED_TOOL_NAMES as _GUIDED_TOOL_NAMES
from agent_bom.mcp_tools.request_identity import request_context as _mcp_request_ctx
from agent_bom.mcp_tools.result_store import scan_result_owner as _scan_result_owner
from agent_bom.mcp_tools.scanning_registration import register_scanning_tools
from agent_bom.security import sanitize_error
from agent_bom.storage.state_home import activate_demo_state_dir, demo_estate_default_persist

logger = logging.getLogger(__name__)
_ToolReturn = TypeVar("_ToolReturn")

# Backward-compatible exports for tests and downstream imports that still
# read metadata directly from `agent_bom.mcp_server`.
_SERVER_CARD_PROMPTS = _METADATA_SERVER_CARD_PROMPTS
_SERVER_CARD_TOOLS = _METADATA_SERVER_CARD_TOOLS

build_server_card = _metadata_build_server_card

# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

_VALID_ECOSYSTEMS = SUPPORTED_PACKAGE_ECOSYSTEM_SET

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_GHSA_RE = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.IGNORECASE)


class _StaticBearerTokenVerifier:
    """FastMCP token verifier backed by configured bearer tokens.

    The primary MCP bearer token authenticates read-only callers. A separate
    operator token can be configured for write tools so a tool argument cannot
    self-assert administrative authority.
    """

    def __init__(
        self,
        token: str,
        operator_token: str | None = None,
        *,
        token_expires_at: str | None = None,
        operator_token_expires_at: str | None = None,
    ):
        if operator_token and hmac.compare_digest(token.encode(), operator_token.encode()):
            raise ValueError("Read and operator MCP credentials must be distinct")
        self._token = token
        self._operator_token = operator_token
        now = datetime.now(timezone.utc)
        self._token_expires_at = _parse_mcp_token_expiry(token_expires_at, "AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", now=now)
        self._operator_token_expires_at = (
            _parse_mcp_token_expiry(operator_token_expires_at, "AGENT_BOM_MCP_OPERATOR_TOKEN_EXPIRES_AT", now=now)
            if operator_token
            else None
        )

    async def verify_token(self, token: str):
        from mcp.server.auth.provider import AccessToken

        if self._operator_token and token and hmac.compare_digest(token, self._operator_token):
            if _mcp_token_expired(self._operator_token_expires_at):
                return None
            return AccessToken(
                token=token,
                client_id="agent-bom-operator-token",
                scopes=[
                    "admin",
                    "cloud:write",
                    "findings:write",
                    "identity:write",
                    "scan:write",
                    "shield:write",
                    "ticketing:write",
                    "connectors:write",
                ],
                expires_at=_mcp_token_expiry_epoch(self._operator_token_expires_at),
                resource=None,
            )
        if token and hmac.compare_digest(token, self._token):
            if _mcp_token_expired(self._token_expires_at):
                return None
            return AccessToken(
                token=token,
                client_id="agent-bom-static-token",
                scopes=["read"],
                expires_at=_mcp_token_expiry_epoch(self._token_expires_at),
                resource=None,
            )
        return None


def _parse_mcp_token_expiry(value: str | None, env_name: str, *, now: datetime) -> datetime:
    """Require an absolute deadline that cannot renew when the process restarts."""
    requirement = f"{env_name} must be a timezone-aware ISO-8601 expiry in the next hour"
    if not value or not value.strip():
        raise ValueError(requirement)
    cleaned = value.strip()
    if cleaned.endswith("Z"):
        cleaned = f"{cleaned[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(cleaned)
    except ValueError:
        raise ValueError(requirement) from None
    if parsed.tzinfo is None:
        raise ValueError(requirement)
    try:
        parsed = parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        raise ValueError(requirement) from None
    if not now < parsed <= now + timedelta(hours=1):
        raise ValueError(requirement)
    return parsed


def _mcp_token_expired(expires_at: datetime | None) -> bool:
    return bool(expires_at and datetime.now(timezone.utc) >= expires_at)


def _mcp_token_expiry_epoch(expires_at: datetime | None) -> int | None:
    return int(expires_at.timestamp()) if expires_at else None


def _validate_ecosystem(ecosystem: str) -> str:
    """Return cleaned ecosystem string or raise ValueError."""
    return _mcp_runtime.validate_ecosystem(ecosystem, _VALID_ECOSYSTEMS)


def _validate_cve_id(cve_id: str) -> str:
    """Return cleaned CVE/GHSA ID or raise ValueError."""
    return _mcp_runtime.validate_cve_id(cve_id, _CVE_RE, _GHSA_RE)


def _truncate_response(response_str: str) -> str:
    """Truncate response if it exceeds _MAX_RESPONSE_CHARS."""
    return _mcp_runtime.truncate_response(response_str, _MAX_RESPONSE_CHARS)


def _json_tool_result(text: str) -> CallToolResult:
    """Wrap a JSON tool payload, flagging failed/incomplete calls with ``isError``.

    The body stays the same JSON text (and ``{"result": text}`` structured
    content, matching the tool's ``str`` output schema) either way.
    """
    return CallToolResult(
        content=[TextContent(type="text", text=str(text))],
        structured_content={"result": str(text)},
        is_error=isinstance(text, _mcp_runtime.ToolErrorPayload),
    )


def _safe_path(path_str: str) -> Path:
    """Resolve a user-provided path and validate against directory traversal."""
    return _mcp_runtime.safe_path(path_str)


def _get_tool_semaphore() -> asyncio.Semaphore:
    """Return a semaphore bound to the current running event loop."""
    return _mcp_runtime.get_tool_semaphore(
        _loop_tool_semaphores,
        max_cached_tool_loops=_MAX_CACHED_TOOL_LOOPS,
        max_concurrent_tools=_MCP_MAX_CONCURRENT_TOOLS,
    )


def _record_tool_metric(
    tool_name: str,
    *,
    elapsed_ms: int,
    success: bool,
    timed_out: bool = False,
    error: str | None = None,
) -> None:
    """Update bounded in-memory metrics for MCP tool calls."""
    _mcp_runtime.record_tool_metric(
        _tool_metrics,
        max_tool_metrics=_MCP_MAX_TOOL_METRICS,
        tool_name=tool_name,
        elapsed_ms=elapsed_ms,
        success=success,
        timed_out=timed_out,
        error=error,
    )


def _tool_metrics_snapshot() -> dict[str, Any]:
    """Return structured MCP tool metrics for resources and health checks."""
    return _mcp_runtime.tool_metrics_snapshot(
        _tool_metrics,
        caller_rate_windows=_caller_rate_windows,
        recent_tool_requests=_recent_tool_requests,
        max_concurrent_tools=_MCP_MAX_CONCURRENT_TOOLS,
        tool_timeout_seconds=_MCP_TOOL_TIMEOUT_SECONDS,
        caller_rate_limit=_MCP_CALLER_RATE_LIMIT,
        caller_window_seconds=_MCP_CALLER_WINDOW_SECONDS,
    )


def _current_tool_request() -> dict[str, str | None]:
    """Return request identity metadata when running inside an MCP request."""
    return _mcp_runtime.current_tool_request(_mcp_request_ctx.get)


def _check_caller_rate_limit(caller: str) -> float | None:
    """Return retry-after seconds when a caller exceeds the bounded MCP rate window."""
    return _mcp_runtime.check_caller_rate_limit(
        _caller_rate_windows,
        caller,
        caller_rate_limit=_MCP_CALLER_RATE_LIMIT,
        caller_window_seconds=_MCP_CALLER_WINDOW_SECONDS,
        max_caller_states=_MCP_MAX_CALLER_STATES,
        monotonic_now=time.monotonic(),
        global_rate_limit=_MCP_GLOBAL_RATE_LIMIT,
        global_window_seconds=_MCP_GLOBAL_WINDOW_SECONDS,
    )


def _record_tool_request(
    tool_name: str,
    *,
    caller: str | None,
    client_id: str | None,
    request_id: str | None,
    status: str,
    elapsed_ms: int,
    error: str | None = None,
) -> None:
    """Store a bounded trace of recent MCP tool requests."""
    _mcp_runtime.record_tool_request(
        _recent_tool_requests,
        tool_name,
        caller=caller,
        client_id=client_id,
        request_id=request_id,
        status=status,
        elapsed_ms=elapsed_ms,
        error=error,
    )


async def _execute_tool_async(
    tool_name: str,
    handler: Callable[..., Awaitable[_ToolReturn]],
    /,
    *args,
    timeout: float | None = None,
    destructive: bool = False,
    required_scope: str | None = None,
    **kwargs,
) -> _ToolReturn | str:
    """Run an async MCP tool with bounded concurrency, timeout, and metrics.

    When ``destructive`` is set, the shared dispatch fails closed for callers
    lacking an admin operator role (and the ``required_scope`` when supplied),
    enforcing the tool's ``destructiveHint`` metadata at the dispatch layer.
    """
    timeout_seconds = timeout if timeout and timeout > 0 else _MCP_TOOL_TIMEOUT_SECONDS
    return await _mcp_runtime.execute_tool_async(
        tool_name,
        handler,
        *args,
        timeout_seconds=timeout_seconds,
        request_meta_factory=_current_tool_request,
        check_caller_rate_limit_fn=_check_caller_rate_limit,
        record_tool_metric_fn=_record_tool_metric,
        record_tool_request_fn=_record_tool_request,
        truncate_response_fn=_truncate_response,
        get_tool_semaphore_fn=_get_tool_semaphore,
        sanitize_error_fn=sanitize_error,
        logger=logger,
        destructive=destructive,
        required_scope=required_scope,
        **kwargs,
    )


async def _execute_tool_sync_async(
    tool_name: str,
    handler: Callable[..., _ToolReturn],
    /,
    *args,
    tool_timeout: float | None = None,
    destructive: bool = False,
    required_scope: str | None = None,
    **kwargs,
) -> _ToolReturn | str:
    """Run a sync MCP tool under the shared async governance envelope."""
    timeout_seconds = _MCP_TOOL_TIMEOUT_SECONDS if tool_timeout is None else tool_timeout
    response_truncator = kwargs.get("_truncate_response", _truncate_response)
    return await _mcp_runtime.execute_tool_sync_async(
        tool_name,
        handler,
        *args,
        timeout_seconds=timeout_seconds,
        request_meta_factory=_current_tool_request,
        check_caller_rate_limit_fn=_check_caller_rate_limit,
        record_tool_metric_fn=_record_tool_metric,
        record_tool_request_fn=_record_tool_request,
        truncate_response_fn=response_truncator,
        get_tool_semaphore_fn=_get_tool_semaphore,
        sanitize_error_fn=sanitize_error,
        logger=logger,
        destructive=destructive,
        required_scope=required_scope,
        **kwargs,
    )


# Dep-graph builder + registry cache live in mcp_server_helpers (#1522 Phase 2).
# Re-bound to their underscore names here so the existing closures inside
# create_mcp_server() don't need to change.
from agent_bom.mcp_server_helpers import build_dep_graph_from_agents as _build_dep_graph_from_agents  # noqa: E402
from agent_bom.mcp_server_helpers import get_registry_data as _get_registry_data  # noqa: E402
from agent_bom.mcp_server_helpers import get_registry_data_raw as _get_registry_data_raw  # noqa: E402

_tool_metrics: OrderedDict[str, dict[str, Any]] = OrderedDict()
_loop_tool_semaphores: OrderedDict[int, asyncio.Semaphore] = OrderedDict()
_caller_rate_windows: OrderedDict[str, deque[float]] = OrderedDict()
_recent_tool_requests: deque[dict[str, Any]] = deque(maxlen=_MCP_MAX_REQUEST_TRACES)
_MAX_CACHED_TOOL_LOOPS = 8


# Most agent-bom MCP tools are read-only scanners. Shield write tools are
# explicitly annotated as mutating and fail closed unless an admin role,
# shield:write scope, and audit reason are supplied.
_READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True)
_WRITE_ACTION = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False)
# A tool that persists state as a side effect of a read-shaped call but is not
# destructive and yields the same result on repeat (e.g. access_review, which
# recomputes and upserts campaign status). It is a WRITE — never readOnlyHint —
# but non-destructive and idempotent.
_WRITE_IDEMPOTENT = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=True)
# Runtime capability inspection is protocol-read-only, but stdio discovery may
# launch a configured process. Advertise the host-side execution truthfully so
# MCP clients can require approval before the explicit opt-in is accepted.
_RUNTIME_INTROSPECTION = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=True)


def _check_mcp_sdk() -> None:
    """Ensure the mcp SDK is available."""
    _mcp_runtime.check_mcp_sdk()


# ---------------------------------------------------------------------------
# Shared scan pipeline helper
# ---------------------------------------------------------------------------


async def _run_scan_pipeline(
    config_path: Optional[str] = None,
    image: Optional[str] = None,
    sbom_path: Optional[str] = None,
    package: Optional[str] = None,
    enrich: bool = False,
    transitive: bool = False,
    offline: bool = False,
    ecosystem: Optional[str] = None,
    no_discover: bool = False,
):
    """Run discovery -> extraction -> scanning and return (agents, blast_radii, warnings)."""
    return await _mcp_scan.run_scan_pipeline(
        safe_path=_safe_path,
        config_path=config_path,
        image=image,
        sbom_path=sbom_path,
        package=package,
        enrich=enrich,
        transitive=transitive,
        offline=offline,
        ecosystem=ecosystem,
        no_discover=no_discover,
    )


def _persisted_finding_evidence(*, tenant_id: str, cve_id: str, scan_id: str | None = None) -> dict[str, Any]:
    """Read the API's canonical persisted finding spine without an HTTP self-call."""
    from agent_bom.api.scan_finding_read import persisted_finding_evidence

    return persisted_finding_evidence(tenant_id=tenant_id, cve_id=cve_id, scan_id=scan_id)


# ---------------------------------------------------------------------------
# MCP Server factory
# ---------------------------------------------------------------------------


def create_mcp_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    bearer_token: str | None = None,
    profile: str = "scan",
    oauth_enabled: bool = False,
):
    """Create an MCP server exposing the selected bounded tool profile.

    When the smithery SDK is installed, the server is automatically enhanced
    with session-config and CORS middleware for Smithery.ai hosted deployment.
    """
    from agent_bom.logging_config import setup_logging
    from agent_bom.mcp_tools.profiles import configure_registration, get_profile

    get_profile(profile)  # Reject unknown profiles before constructing the server.
    demo_estate_default_persist(activate_demo_state_dir())  # Before any store opens: demo state dir + the demo job DB serve uses.
    setup_logging(level="INFO")
    _check_mcp_sdk()

    from agent_bom import __version__

    mcp = _create_fastmcp_server(
        host=host,
        port=port,
        bearer_token=bearer_token,
        version=__version__,
        profile=profile,
        oauth_enabled=oauth_enabled,
        token_verifier_factory=lambda token: _StaticBearerTokenVerifier(
            token,
            os.environ.get("AGENT_BOM_MCP_OPERATOR_TOKEN"),
            token_expires_at=os.environ.get("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT"),
            operator_token_expires_at=os.environ.get("AGENT_BOM_MCP_OPERATOR_TOKEN_EXPIRES_AT"),
        ),
    )

    configure_registration(mcp, profile)

    # Import tool implementations
    from agent_bom.mcp_tools.analysis import blast_radius_impl
    from agent_bom.mcp_tools.inventory import inventory_list_impl, inventory_summary_impl

    # ── Tool 1: scan ──────────────────────────────────────────────────

    register_scanning_tools(
        mcp,
        read_only=_READ_ONLY,
        max_response_chars=_MAX_RESPONSE_CHARS,
        _execute_tool_async=_execute_tool_async,
        _json_tool_result=_json_tool_result,
        _mcp_request_ctx=_mcp_request_ctx,
        _run_scan_pipeline=lambda *args, **kwargs: _run_scan_pipeline(*args, **kwargs),
        _scan_result_owner=_scan_result_owner,
        _truncate_response=_truncate_response,
        _validate_ecosystem=_validate_ecosystem,
    )

    # ── Tool 2b: threat intel lookup ──────────────────────────────────

    register_intel_tools(mcp, read_only=_READ_ONLY, _execute_tool_async=_execute_tool_async, _truncate_response=_truncate_response)

    # ── Tool 3: blast_radius ──────────────────────────────────────────

    @mcp.tool(annotations=_READ_ONLY, title="Blast Radius Analysis")
    async def blast_radius(
        cve_id: Annotated[str, Field(description="CVE identifier to look up, e.g. 'CVE-2024-1234' or 'GHSA-xxxx'.")],
        tenant_id: Annotated[str, Field(description="Tenant scope for persisted findings. Defaults to 'default'.")] = "default",
        scan_id: Annotated[str | None, Field(description="Optional persisted scan scope.")] = None,
    ) -> str:
        """Look up the blast radius of a specific CVE across your AI agent setup.

        Reads the tenant's persisted control-plane finding evidence when it is
        available. Standalone MCP mode falls back to a local MCP configuration
        scan and labels that narrower source explicitly.

        Args:
            cve_id: The CVE identifier (e.g. "CVE-2024-1234" or "GHSA-xxxx").

        Returns:
            JSON with blast radius details including risk_score,
            affected_servers, affected_agents, exposed_credentials, and
            exposed_tools. Returns found=false if CVE not found.
        """
        return await _execute_tool_async(
            "blast_radius",
            blast_radius_impl,
            cve_id=cve_id,
            tenant_id=tenant_id,
            scan_id=scan_id,
            _validate_cve_id=_validate_cve_id,
            _run_scan_pipeline=_run_scan_pipeline,
            _get_persisted_evidence=_persisted_finding_evidence,
            _truncate_response=_truncate_response,
        )

    # Tools 4-5 (exposure_paths, should_i_deploy) live in mcp_tools.graph_registration.

    # ── Tool 6: policy_check ──────────────────────────────────────────

    register_assessment_tools(
        mcp,
        read_only=_READ_ONLY,
        _execute_tool_async=_execute_tool_async,
        _execute_tool_sync_async=_execute_tool_sync_async,
        _get_registry_data=_get_registry_data,
        _run_scan_pipeline=lambda *args, **kwargs: _run_scan_pipeline(*args, **kwargs),
        _truncate_response=_truncate_response,
        _validate_ecosystem=_validate_ecosystem,
    )

    # ── Tools 13-15: unified asset inventory (agent-native) ─────────────
    # The same faceted inventory the dashboard renders, exposed to headless MCP
    # clients over the ONE unified graph snapshot via the shared inventory
    # service — no HTTP self-call, no duplicated projection logic.

    @mcp.tool(annotations=_READ_ONLY, title="Asset Inventory Summary")
    async def inventory_summary(
        tenant_id: Annotated[str, Field(description="Tenant scope for the snapshot. Defaults to 'default'.")] = "default",
        scan_id: Annotated[str | None, Field(description="Optional historical scan ID. Omit for the current tenant estate.")] = None,
        type: Annotated[str | None, Field(description="Comma-separated asset entity types; finding types are rejected.")] = None,
        search: Annotated[str | None, Field(description="Free-text search over asset name / label / attributes.")] = None,
        environment: Annotated[str | None, Field(description="Filter by environment facet.")] = None,
        provider: Annotated[str | None, Field(description="Filter by provider facet.")] = None,
        source: Annotated[str | None, Field(description="Filter by data-source / provenance facet.")] = None,
        severity: Annotated[str | None, Field(description="Highest directly linked finding severity.")] = None,
        min_severity: Annotated[str | None, Field(description="Minimum directly linked finding severity.")] = None,
    ) -> str:
        """Return unified asset-inventory counts by type and source group.

        Counts every non-finding asset in the tenant's current graph estate —
        AI (agents, MCP servers, models, tools, credentials), cloud (resources,
        data stores, accounts), Snowflake, and identity — bucketed by OCSF entity
        type and by operator-facing group (ai / cloud / identity / secrets /
        code). Findings (CVEs, misconfigurations) are excluded; use blast_radius
        or exposure_paths for the finding queue.
        """
        return await _execute_tool_async(
            "inventory_summary",
            inventory_summary_impl,
            tenant_id=tenant_id,
            scan_id=scan_id,
            type=type,
            search=search,
            environment=environment,
            provider=provider,
            source=source,
            severity=severity,
            min_severity=min_severity,
            _truncate_response=_truncate_response,
        )

    @mcp.tool(annotations=_READ_ONLY, title="Asset Inventory List")
    async def inventory_list(
        tenant_id: Annotated[str, Field(description="Tenant scope for the snapshot. Defaults to 'default'.")] = "default",
        type: Annotated[
            str | None,
            Field(description="Comma-separated asset entity types to include, e.g. 'agent,cloud_resource'. Finding types are rejected."),
        ] = None,
        search: Annotated[str | None, Field(description="Free-text search over asset name / label / attributes.")] = None,
        environment: Annotated[str | None, Field(description="Filter by environment facet, e.g. 'production'.")] = None,
        provider: Annotated[str | None, Field(description="Filter by provider facet, e.g. 'aws', 'snowflake'.")] = None,
        source: Annotated[str | None, Field(description="Filter by data-source / provenance facet.")] = None,
        severity: Annotated[str | None, Field(description="Filter by the asset's highest directly linked finding severity.")] = None,
        min_severity: Annotated[
            str | None, Field(description="Minimum severity floor for included assets: critical / high / medium / low.")
        ] = None,
        scan_id: Annotated[str | None, Field(description="Optional historical scan ID. Omit for the current tenant estate.")] = None,
        cursor: Annotated[str | None, Field(description="Opaque keyset cursor from a previous page's pagination.next_cursor.")] = None,
        offset: Annotated[int, Field(ge=0, description="Pagination offset for non-cursor paging.")] = 0,
        limit: Annotated[int, Field(ge=1, le=200, description="Maximum asset rows to return (1-200).")] = 50,
    ) -> str:
        """Return a filtered, paginated page of inventory asset rows.

        Every filter and the exact whole-query total is evaluated natively by
        the graph store. Facets are self-excluding and never derived from the
        displayed page. Page deep with ``pagination.next_cursor``. Findings
        never appear in the list.
        """
        return await _execute_tool_async(
            "inventory_list",
            inventory_list_impl,
            tenant_id=tenant_id,
            type=type,
            search=search,
            environment=environment,
            provider=provider,
            source=source,
            severity=severity,
            min_severity=min_severity,
            scan_id=scan_id,
            cursor=cursor,
            offset=offset,
            limit=limit,
            _truncate_response=_truncate_response,
        )

    register_inventory_asset_tool(mcp, read_only=_READ_ONLY, execute_tool_async=_execute_tool_async, truncate_response=_truncate_response)
    register_graph_agent_tools(mcp, read_only=_READ_ONLY, execute_tool_async=_execute_tool_async, truncate_response=_truncate_response)

    _register_runtime_catalog_tools(
        mcp,
        read_only=_READ_ONLY,
        runtime_introspection=_RUNTIME_INTROSPECTION,
        execute_tool_sync_async=_execute_tool_sync_async,
        safe_path=_safe_path,
        truncate_response=_truncate_response,
    )

    from agent_bom.mcp_tools.registration import register_connected_tools

    register_connected_tools(
        mcp,
        safe_path=_safe_path,
        read_only=_READ_ONLY,
        write_action=_WRITE_ACTION,
        execute_tool_async=_execute_tool_async,
        truncate_response=_truncate_response,
    )

    from agent_bom.mcp_server_operator_tools import register_operator_tools

    register_operator_tools(
        mcp,
        read_only=_READ_ONLY,
        write_action=_WRITE_ACTION,
        write_idempotent=_WRITE_IDEMPOTENT,
        execute_tool_async=_execute_tool_async,
        execute_tool_sync_async=_execute_tool_sync_async,
        safe_path=_safe_path,
        run_scan_pipeline=_run_scan_pipeline,
        truncate_response=_truncate_response,
        validate_ecosystem=_validate_ecosystem,
        get_registry_data_raw=_get_registry_data_raw,
        build_dep_graph_from_agents=_build_dep_graph_from_agents,
    )

    _attach_resources_and_prompts(
        mcp,
        get_registry_data_raw=_get_registry_data_raw,
        sanitize_error_fn=sanitize_error,
        logger=logger,
        tool_metrics_snapshot=_tool_metrics_snapshot,
        profile=profile,
    )

    attach_metadata_routes(
        mcp,
        auth_required=bool(bearer_token or oauth_enabled),
        tool_metrics_snapshot=_tool_metrics_snapshot,
        profile=profile,
        oauth=oauth_enabled,
    )

    # Strict-arg contract on every registered tool (#2197 audit P1).
    # Sets `additionalProperties: false` on the JSON Schema served via
    # tools/list AND wraps each tool's runner so unknown arg keys raise
    # instead of being silently dropped. Pre-fix, AI agents passing typo
    # args (e.g. `Version` capital) got false-clean verdicts.
    from agent_bom.mcp_strict_args import harden_tool_arguments

    harden_tool_arguments(mcp)

    # Opt-in third-party MCP tool plugins (off by default). Requires both
    # AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS and AGENT_BOM_ACTIVATE_MCP_TOOL_PLUGINS.
    from agent_bom.plugin_activation import activate_mcp_tool_plugins

    activated = activate_mcp_tool_plugins(mcp) if profile == "full" else []
    if activated:
        logger.info("Activated %d third-party MCP tool plugin(s): %s", len(activated), ", ".join(sorted(activated)))
        harden_tool_arguments(mcp)

    return mcp


def create_smithery_server():
    return _create_smithery_server(create_mcp_server)
