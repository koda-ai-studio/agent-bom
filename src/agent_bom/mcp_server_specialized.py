"""Specialized MCP tool registrations for agent-bom."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from types import ModuleType
from typing import Annotated, Any, Awaitable, Callable

from pydantic import Field

from agent_bom.mcp_errors import CODE_INTERNAL_UNEXPECTED, mcp_error_json
from agent_bom.mcp_tools.dispatch import resolve_tool_path
from agent_bom.mcp_tools.tool_annotations import LOCAL_READ_ONLY
from agent_bom.security import sanitize_error  # noqa: F401 — kept for downstream importers

__all__ = ["register_specialized_ai_tools", "sanitize_error"]


@dataclass(frozen=True)
class _ToolDeps:
    mcp: Any
    read_only: Any
    write_action: Any
    execute_tool_async: Callable[..., Awaitable[Any]]
    safe_path: Callable[[str], Any]
    truncate_response: Callable[[str], str]


def register_specialized_ai_tools(
    mcp: Any,
    *,
    read_only: Any,
    write_action: Any,
    execute_tool_async: Callable[..., Awaitable[Any]],
    safe_path: Callable[[str], Any],
    truncate_response: Callable[[str], str],
) -> None:
    """Register specialized AI, model, and external-ingest MCP tools.

    Impl functions are looked up on their modules here, at registration time,
    so a server built while an impl is patched serves the patched impl.
    """
    from agent_bom.mcp_tools import cloud, compliance, runtime_evidence, specialized

    deps = _ToolDeps(mcp, read_only, write_action, execute_tool_async, safe_path, truncate_response)
    _register_posture_tools(deps, cloud, compliance)
    _register_registry_and_dataset_tools(deps, cloud, specialized)
    _register_pipeline_and_provenance_tools(deps, specialized)
    _register_prompt_and_model_tools(deps, specialized)
    _register_license_tool(deps, compliance)
    _register_runtime_evidence_tool(deps, runtime_evidence)
    _register_external_ingest_tool(deps)


def _register_posture_tools(deps: _ToolDeps, cloud: ModuleType, compliance: ModuleType) -> None:
    """Vector DB, AISVS and GPU infrastructure posture tools."""
    mcp, read_only, execute_tool_async, truncate_response = deps.mcp, deps.read_only, deps.execute_tool_async, deps.truncate_response
    vector_db_scan_impl = cloud.vector_db_scan_impl
    gpu_infra_scan_impl = cloud.gpu_infra_scan_impl
    aisvs_benchmark_impl = compliance.aisvs_benchmark_impl

    @mcp.tool(annotations=read_only, title="Vector DB Scan")
    async def vector_db_scan(
        hosts: Annotated[
            str | None,
            Field(description="Comma-separated hosts to probe (default: 127.0.0.1). Example: '127.0.0.1,10.0.0.5'."),
        ] = None,
    ) -> str:
        """Scan for running vector databases and assess their security posture."""
        return await execute_tool_async(
            "vector_db_scan",
            vector_db_scan_impl,
            hosts=hosts,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="AISVS Benchmark")
    async def aisvs_benchmark(
        checks: Annotated[
            str | None,
            Field(description=("Comma-separated AISVS check IDs to run (e.g. 'AI-4.1,AI-6.1'). Omit to run all 9 checks.")),
        ] = None,
    ) -> str:
        """Run AISVS v1.0 (AI Security Verification Standard) compliance checks."""
        return await execute_tool_async(
            "aisvs_benchmark",
            aisvs_benchmark_impl,
            checks=checks,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="GPU Infrastructure Scan")
    async def gpu_infra_scan(
        k8s_context: Annotated[
            str | None,
            Field(description="kubectl context to use for K8s GPU node discovery. Omit for current context."),
        ] = None,
        probe_dcgm: Annotated[
            bool,
            Field(description="Whether to probe DCGM exporter endpoints on port 9400 (unauthenticated metrics leak detection)."),
        ] = True,
    ) -> str:
        """Discover GPU/AI compute infrastructure: containers, K8s GPU nodes and workloads, DCGM endpoints, and GPU posture."""
        return await execute_tool_async(
            "gpu_infra_scan",
            gpu_infra_scan_impl,
            k8s_context=k8s_context,
            probe_dcgm=probe_dcgm,
            _truncate_response=truncate_response,
        )


def _register_registry_and_dataset_tools(deps: _ToolDeps, cloud: ModuleType, specialized: ModuleType) -> None:
    """Registry sweep and dataset card tools."""
    mcp, read_only, execute_tool_async, truncate_response, safe_path = (
        deps.mcp,
        deps.read_only,
        deps.execute_tool_async,
        deps.truncate_response,
        deps.safe_path,
    )
    registry_sweep_scan_impl = cloud.registry_sweep_scan_impl
    dataset_card_scan_impl = specialized.dataset_card_scan_impl

    @mcp.tool(annotations=read_only, title="Registry Image Sweep")
    async def registry_sweep_scan(
        provider: Annotated[
            str,
            Field(description="Container registry to sweep: 'ecr' (AWS), 'acr' (Azure), or 'gar' (GCP Artifact Registry)."),
        ],
        region: Annotated[str | None, Field(description="AWS region (ecr only).")] = None,
        profile: Annotated[str | None, Field(description="AWS credential profile (ecr only).")] = None,
        registry: Annotated[str | None, Field(description="ACR login server, e.g. 'myacr.azurecr.io' (acr only).")] = None,
        project: Annotated[str | None, Field(description="GCP project id (gar only).")] = None,
        location: Annotated[str | None, Field(description="GAR location/multi-region, e.g. 'us' (gar only).")] = None,
        max_images: Annotated[
            int | None,
            Field(description="Cap on images scanned (default: AGENT_BOM_REGISTRY_MAX_IMAGES or 50)."),
        ] = None,
    ) -> str:
        """Sweep an entire cloud container registry: enumerate every repo+tag, dedupe by digest, cap, and scan each (read-only)."""
        return await execute_tool_async(
            "registry_sweep_scan",
            registry_sweep_scan_impl,
            provider=provider,
            region=region,
            profile=profile,
            registry=registry,
            project=project,
            location=location,
            max_images=max_images,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Dataset Card Scan")
    async def dataset_card_scan(
        directory: Annotated[
            str,
            Field(description="Directory path to scan for dataset cards (dataset_info.json, README.md frontmatter, .dvc files)."),
        ],
        scan_pii: Annotated[
            bool,
            Field(
                description=(
                    "Also scan CSV/JSON/JSONL file contents for PII/PHI (emails, SSNs, credit cards, medical data). Default false."
                )
            ),
        ] = False,
    ) -> str:
        """Scan a directory for ML dataset card metadata, provenance, and optionally PII/PHI content."""
        return await execute_tool_async(
            "dataset_card_scan",
            dataset_card_scan_impl,
            directory=str(resolve_tool_path(safe_path, directory, argument="directory")),
            scan_pii=scan_pii,
            _truncate_response=truncate_response,
        )


def _register_pipeline_and_provenance_tools(deps: _ToolDeps, specialized: ModuleType) -> None:
    """Training pipeline, browser extension and model provenance tools."""
    mcp, read_only, execute_tool_async, truncate_response, safe_path = (
        deps.mcp,
        deps.read_only,
        deps.execute_tool_async,
        deps.truncate_response,
        deps.safe_path,
    )
    training_pipeline_scan_impl = specialized.training_pipeline_scan_impl
    browser_extension_scan_impl = specialized.browser_extension_scan_impl
    model_provenance_scan_impl = specialized.model_provenance_scan_impl

    @mcp.tool(annotations=read_only, title="Training Pipeline Scan")
    async def training_pipeline_scan(
        directory: Annotated[
            str,
            Field(description="Directory path to scan for training pipeline artifacts (MLflow, Kubeflow, W&B)."),
        ],
    ) -> str:
        """Scan a directory for ML training pipeline lineage and provenance."""
        return await execute_tool_async(
            "training_pipeline_scan",
            training_pipeline_scan_impl,
            directory=str(resolve_tool_path(safe_path, directory, argument="directory")),
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Browser Extension Scan")
    async def browser_extension_scan(
        include_low_risk: Annotated[
            bool,
            Field(description="Include low-risk extensions in results (default: only medium+ risk)."),
        ] = False,
    ) -> str:
        """Scan installed browser extensions for dangerous permissions."""
        return await execute_tool_async(
            "browser_extension_scan",
            browser_extension_scan_impl,
            include_low_risk=include_low_risk,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Model Provenance Scan")
    async def model_provenance_scan(
        model_id: Annotated[
            str,
            Field(description="HuggingFace model ID (e.g. 'meta-llama/Llama-3-8B') or Ollama model name (e.g. 'llama3')."),
        ],
        source: Annotated[
            str,
            Field(description="Model source: 'huggingface' or 'ollama' (default: huggingface)."),
        ] = "huggingface",
    ) -> str:
        """Check ML model provenance and supply chain metadata."""
        return await execute_tool_async(
            "model_provenance_scan",
            model_provenance_scan_impl,
            model_id=model_id,
            source=source,
            _truncate_response=truncate_response,
        )


def _register_prompt_and_model_tools(deps: _ToolDeps, specialized: ModuleType) -> None:
    """Prompt template, model file and AI inventory tools."""
    mcp, read_only, execute_tool_async, truncate_response, safe_path = (
        deps.mcp,
        deps.read_only,
        deps.execute_tool_async,
        deps.truncate_response,
        deps.safe_path,
    )
    prompt_scan_impl = specialized.prompt_scan_impl
    model_file_scan_impl = specialized.model_file_scan_impl
    ai_inventory_scan_impl = specialized.ai_inventory_scan_impl

    @mcp.tool(annotations=LOCAL_READ_ONLY, title="Prompt Template Scan")
    async def prompt_scan(
        directory: Annotated[
            str,
            Field(description="Directory path to scan for prompt template files (.prompt, system_prompt.*, prompts/ directories)."),
        ],
    ) -> str:
        """Scan prompt template files for prompt-injection and unsafe-interpolation risks.

        Walks the given directory for prompt assets (``.prompt`` files,
        ``system_prompt.*``, and ``prompts/`` directories), then statically
        inspects each template for injection-prone patterns and unsafe variable
        interpolation (untrusted input concatenated into instructions, missing
        delimiters, tool/role-confusion phrasing).

        Args:
            directory: Directory path to scan for prompt template files.

        Returns:
            JSON with the scanned files, per-file findings (rule id, severity,
            line, message), and a summary count by severity.

        Use this before shipping or registering agent prompts to catch
        injection exposure that package and CVE scans do not cover.
        """
        return await execute_tool_async(
            "prompt_scan",
            prompt_scan_impl,
            directory=str(resolve_tool_path(safe_path, directory, argument="directory")),
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Model File Scan")
    async def model_file_scan(
        directory: Annotated[
            str,
            Field(description="Directory path to scan for ML model files (.gguf, .safetensors, .onnx, .pt, .pkl, .h5, etc.)."),
        ],
    ) -> str:
        """Scan a directory for ML model files and assess serialization risks."""
        return await execute_tool_async(
            "model_file_scan",
            model_file_scan_impl,
            directory=str(resolve_tool_path(safe_path, directory, argument="directory")),
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="AI Inventory Scan")
    async def ai_inventory_scan(
        directory: Annotated[
            str,
            Field(description="Directory to scan for AI SDK imports, model refs, API keys, shadow AI (Python/JS/TS/Java/Go/Rust/Ruby)."),
        ],
    ) -> str:
        """Scan source code for AI component usage patterns."""
        return await execute_tool_async(
            "ai_inventory_scan",
            ai_inventory_scan_impl,
            directory=str(resolve_tool_path(safe_path, directory, argument="directory")),
            _truncate_response=truncate_response,
        )


def _register_license_tool(deps: _ToolDeps, compliance: ModuleType) -> None:
    """License compliance policy tool."""
    mcp, read_only, execute_tool_async, truncate_response = deps.mcp, deps.read_only, deps.execute_tool_async, deps.truncate_response
    license_compliance_scan_impl = compliance.license_compliance_scan_impl

    @mcp.tool(annotations=read_only, title="License Compliance Scan")
    async def license_compliance_scan(
        scan_json: Annotated[
            str,
            Field(
                description=(
                    "JSON string of a previous scan result (from the 'scan' tool) "
                    "containing agents with packages. Or a JSON array of "
                    '{"name": "pkg", "version": "1.0", "ecosystem": "npm", "license": "MIT"} objects.'
                ),
            ),
        ],
        policy_json: Annotated[
            str,
            Field(
                default="",
                description=(
                    'Optional JSON policy: {"license_block": ["GPL-*"], "license_warn": ["LGPL-*"]}. '
                    "Uses default policy (block GPL/AGPL/SSPL/BUSL/EUPL/OSL, warn LGPL/MPL/EPL/CDDL) if empty."
                ),
            ),
        ] = "",
    ) -> str:
        """Evaluate package licenses against an SPDX compliance policy.

        Takes packages (either a prior ``scan`` result JSON or an explicit array
        of ``{name, version, ecosystem, license}`` objects) and classifies each
        license as allowed, warn, or blocked. Normalizes 2,500+ SPDX IDs
        (including deprecated identifiers) and flags network-copyleft licenses
        (AGPL/SSPL/BUSL and similar).

        Args:
            scan_json: JSON of a previous scan result, or a JSON array of
                package objects with license metadata.
            policy_json: Optional JSON policy with ``license_block`` /
                ``license_warn`` glob lists. Falls back to the built-in policy
                (block strong/network copyleft, warn weak copyleft) when empty.

        Returns:
            JSON with per-package license verdicts, the matched policy rule,
            and counts of blocked / warned / allowed packages.

        Call this in release or procurement gates to enforce license policy on
        an agent's dependency set without running a full scan.
        """
        return await execute_tool_async(
            "license_compliance_scan",
            license_compliance_scan_impl,
            scan_json=scan_json,
            policy_json=policy_json,
            _truncate_response=truncate_response,
        )


def _register_runtime_evidence_tool(deps: _ToolDeps, runtime_evidence: ModuleType) -> None:
    """CWPP runtime evidence ingest tool (write action)."""
    mcp, write_action, execute_tool_async, truncate_response = deps.mcp, deps.write_action, deps.execute_tool_async, deps.truncate_response
    runtime_evidence_ingest_impl = runtime_evidence.runtime_evidence_ingest_impl

    @mcp.tool(annotations=write_action, title="Ingest CWPP Runtime Evidence")
    async def runtime_evidence_ingest(
        source_id: Annotated[str, Field(description="Pre-registered runtime evidence source id.")],
        signals_json: Annotated[
            str,
            Field(
                description=(
                    'JSON string: a list of signal objects, or {"signals": [...]} matching the '
                    "POST /v1/cloud/runtime-evidence/ingest body shape (metadata only)."
                ),
            ),
        ],
        operator_role: Annotated[
            str,
            Field(description="Operator role for this write action. Must be admin."),
        ] = "viewer",
        operator_scopes: Annotated[
            str,
            Field(description="Comma-separated operator scopes. Must include findings:write."),
        ] = "",
        reason: Annotated[
            str,
            Field(description="Human audit reason for ingesting runtime evidence."),
        ] = "",
    ) -> str:
        """Ingest CWPP runtime/EDR workload signals into the local evidence store.

        Uses the configured control-plane API with a short-lived source-scoped
        credential from the server environment. No credential is a tool argument.
        Fail-closed on auth; never writes to a customer cloud target.
        """
        return await execute_tool_async(
            "runtime_evidence_ingest",
            runtime_evidence_ingest_impl,
            destructive=True,
            required_scope="findings:write",
            source_id=source_id,
            signals_json=signals_json,
            operator_role=operator_role,
            operator_scopes=operator_scopes,
            reason=reason,
            _truncate_response=truncate_response,
        )


def _register_external_ingest_tool(deps: _ToolDeps) -> None:
    """External SARIF/SBOM/scanner report ingest tool (write action)."""
    mcp, write_action, execute_tool_async, truncate_response = deps.mcp, deps.write_action, deps.execute_tool_async, deps.truncate_response

    @mcp.tool(annotations=write_action, title="Ingest External Scanner Report")
    async def ingest_external_scan(
        scan_json: Annotated[
            str,
            Field(
                description=("JSON string containing tool-agnostic SARIF, CycloneDX, SPDX, Trivy, Grype, or Syft evidence"),
            ),
        ],
        parse_only: Annotated[
            bool,
            Field(
                description=(
                    "When true, parse locally only. When false, bulk-ingest to the control plane "
                    "when AGENT_BOM_API_URL and credentials are configured."
                ),
            ),
        ] = False,
        source: Annotated[str, Field(description="Source label stored on ingested findings.")] = "external_scan",
        reconcile_absent: Annotated[
            bool,
            Field(description="When pushing, treat this as a complete scan: resolve absent open findings on assets it names."),
        ] = False,
    ) -> str:
        """Ingest external SARIF, SBOM, or scanner JSON without executing its producer.

        This tool mutates the control plane when ``parse_only`` is false: it bulk-ingests
        findings and, with ``reconcile_absent``, resolves this source's open findings absent from the batch on the assets it names.
        That write path is gated as a destructive action requiring the ``findings:write`` scope.
        ``parse_only`` requests parse locally only and stay a read.
        """

        async def _impl(**_operator_context: object) -> str:
            return await _ingest_external_report(scan_json, parse_only, source, reconcile_absent, truncate_response)

        return await execute_tool_async(
            "ingest_external_scan",
            _impl,
            destructive=not parse_only,
            required_scope="findings:write",
        )


async def _ingest_external_report(
    scan_json: str, parse_only: bool, source: str, reconcile_absent: bool, truncate_response: Callable[[str], str]
) -> str:
    """Parse an external report and, unless ``parse_only``, bulk-ingest its findings."""
    import json as _json
    import os

    from agent_bom.client import AgentBomClient
    from agent_bom.findings_push import parse_push_report

    try:
        data = _json.loads(scan_json)
        packages, findings = parse_push_report(data, source=source)
        result: dict[str, object] = {
            "packages": len(packages),
            "findings": len(findings),
            "ingested": [
                {
                    "name": p.name,
                    "version": p.version,
                    "ecosystem": p.ecosystem,
                    "vulnerabilities": len(p.vulnerabilities),
                }
                for p in packages[:50]
            ],
        }
        if not parse_only:
            base_url = os.getenv("AGENT_BOM_API_URL")
            api_key = os.getenv("AGENT_BOM_API_KEY")
            bearer_token = os.getenv("AGENT_BOM_API_TOKEN")
            if base_url and (api_key or bearer_token):
                with contextlib.closing(
                    AgentBomClient(
                        base_url=base_url,
                        api_key=api_key,
                        bearer_token=bearer_token,
                        tenant_id=os.getenv("AGENT_BOM_TENANT_ID"),
                    )
                ) as client:
                    result["control_plane"] = client.ingest_findings(
                        findings,
                        source=source,
                        reconcile_absent=reconcile_absent,
                    )
            elif findings:
                result["control_plane"] = {
                    "skipped": True,
                    "reason": "Set AGENT_BOM_API_URL and AGENT_BOM_API_KEY or AGENT_BOM_API_TOKEN to bulk-ingest findings",
                }
        return _json.dumps(result)
    except Exception as exc:  # noqa: BLE001
        return truncate_response(mcp_error_json(CODE_INTERNAL_UNEXPECTED, exc))
