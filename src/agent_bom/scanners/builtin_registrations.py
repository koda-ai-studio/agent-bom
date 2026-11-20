"""Built-in scanner driver registrations and their capability metadata.

Grouped by scanner family; ``builtin_scanner_registrations`` concatenates the
groups in a fixed order that the registry, CLI and API listings rely on.
"""

from __future__ import annotations

from agent_bom.extensions import ExtensionCapabilities
from agent_bom.scanners.base import (
    ScannerExecutionState,
    ScannerFailureMode,
    ScannerPhase,
    ScannerRegistration,
)


def _local_read_capabilities(
    *,
    scan_modes: tuple[str, ...] = ("local",),
    guarantees: tuple[str, ...] = ("read_only",),
) -> ExtensionCapabilities:
    return ExtensionCapabilities(
        scan_modes=scan_modes,
        required_scopes=("local_project_read",),
        outbound_destinations=(),
        data_boundary="local_filesystem_read_only",
        network_access=False,
        guarantees=guarantees,
    )


def _network_read_capabilities(
    *,
    destinations: tuple[str, ...],
    scan_modes: tuple[str, ...] = ("online",),
    required_scopes: tuple[str, ...] = ("network_egress",),
) -> ExtensionCapabilities:
    return ExtensionCapabilities(
        scan_modes=scan_modes,
        required_scopes=required_scopes,
        outbound_destinations=destinations,
        data_boundary="read_only_metadata_lookup",
        network_access=True,
        guarantees=("read_only", "bounded_egress"),
    )


def _registration(
    name: str,
    module: str,
    *,
    phase: ScannerPhase,
    run_attr: str,
    input_types: tuple[str, ...],
    output_types: tuple[str, ...],
    finding_types: tuple[str, ...],
    summary: str,
    capabilities: ExtensionCapabilities,
    failure_mode: ScannerFailureMode = ScannerFailureMode.WARN_AND_CONTINUE,
    execution_state: ScannerExecutionState = ScannerExecutionState.ACTIVE,
    enabled_by_default: bool = True,
    skip_when: tuple[str, ...] = (),
    telemetry_keys: tuple[str, ...] = (),
    standards: tuple[str, ...] = (),
    source: str = "builtin",
) -> ScannerRegistration:
    return ScannerRegistration(
        name=name,
        module=module,
        capabilities=capabilities,
        source=source,
        phase=phase,
        execution_state=execution_state,
        failure_mode=failure_mode,
        enabled_by_default=enabled_by_default,
        run_attr=run_attr,
        input_types=input_types,
        output_types=output_types,
        finding_types=finding_types,
        skip_when=skip_when,
        telemetry_keys=telemetry_keys,
        standards=standards,
        summary=summary,
    )


def _code_registrations(local_read: ExtensionCapabilities) -> list[ScannerRegistration]:
    """SCA, secret and native code analysis drivers."""
    return [
        _registration(
            "sca-vulnerability",
            "agent_bom.scanners",
            phase=ScannerPhase.SCANNING,
            run_attr="scan_agents_sync",
            input_types=("agents", "packages"),
            output_types=("blast_radii", "vulnerabilities", "findings"),
            finding_types=("cve", "ghsa", "osv", "malicious-package", "dependency-confusion", "typosquat"),
            summary="SCA vulnerability matching with OSV/GHSA/local DB, enrichment, KEV/EPSS, compliance, and blast radius.",
            capabilities=_network_read_capabilities(destinations=("osv.dev", "github_advisory_database", "local_vulnerability_db")),
            failure_mode=ScannerFailureMode.FAIL_CLOSED,
            skip_when=("no_scan_requested", "no_packages_found"),
            telemetry_keys=("packages_scanned", "api_batches", "cache_hits", "warnings", "duration_ms"),
            standards=("OWASP", "NIST", "CIS", "SOC2", "EU_AI_ACT"),
        ),
        _registration(
            "secret-patterns",
            "agent_bom.secret_scanner",
            phase=ScannerPhase.SCANNING,
            run_attr="scan_secrets",
            input_types=("filesystem_path", "source_file", "config_file"),
            output_types=("secret_findings",),
            finding_types=("credential", "pii", "hardcoded-secret"),
            summary="Local file secret and PII pattern scanning using the shared runtime detector pattern library.",
            capabilities=local_read,
            failure_mode=ScannerFailureMode.WARN_AND_CONTINUE,
            skip_when=("no_filesystem_scope", "file_too_large", "excluded_directory"),
            telemetry_keys=("files_scanned", "findings_emitted", "warnings", "duration_ms"),
            standards=("OWASP_LLM02", "CIS_16_4", "SOC2_CC6_1"),
        ),
        _registration(
            "code-native",
            "agent_bom.ast_analyzer",
            phase=ScannerPhase.ANALYSIS,
            run_attr="analyze_project",
            input_types=("code_path",),
            output_types=("ast_analysis",),
            finding_types=("prompt-risk", "guardrail", "tool-signature"),
            summary="Native Python AST analysis composed into the agent-bom code command; no Semgrep execution.",
            capabilities=local_read,
            failure_mode=ScannerFailureMode.FAIL_CLOSED,
            skip_when=("no_code_scope",),
            telemetry_keys=("files_analyzed", "components_found", "duration_ms"),
            standards=("OWASP_LLM", "MITRE_ATLAS"),
        ),
        _registration(
            "ai-component-source",
            "agent_bom.ai_components",
            phase=ScannerPhase.ANALYSIS,
            run_attr="scan_source",
            input_types=("code_path",),
            output_types=("ai_components",),
            finding_types=("ai-component", "shadow-ai", "deprecated-model", "credential-reference"),
            summary="Native multi-language AI SDK, model, and component analysis composed into the agent-bom code command.",
            capabilities=local_read,
            failure_mode=ScannerFailureMode.FAIL_CLOSED,
            skip_when=("no_code_scope",),
            telemetry_keys=("files_scanned", "components_found", "duration_ms"),
            standards=("OWASP_LLM", "MITRE_ATLAS"),
        ),
    ]


def _sast_and_ingest_registrations(local_read: ExtensionCapabilities) -> list[ScannerRegistration]:
    """SAST execution and tool-agnostic evidence import."""
    return [
        _registration(
            "sast-semgrep",
            "agent_bom.sast",
            phase=ScannerPhase.SCANNING,
            run_attr="scan_code",
            input_types=("code_path", "sarif"),
            output_types=("sast_data", "packages", "vulnerabilities"),
            finding_types=("sast", "cwe", "owasp"),
            summary=(
                "Semgrep SAST execution and normalization into the package/vulnerability model; "
                "the legacy .sarif path input imports through the canonical parser without executing Semgrep."
            ),
            capabilities=ExtensionCapabilities(
                scan_modes=("local", "online", "offline_local_rules"),
                required_scopes=("local_project_read", "conditional_network_egress"),
                outbound_destinations=("semgrep_registry",),
                data_boundary="local_source_read_with_operator_selected_rule_source",
                network_access=True,
                guarantees=("read_only", "offline_rejects_remote_rules"),
            ),
            failure_mode=ScannerFailureMode.SKIP_WHEN_UNAVAILABLE,
            skip_when=("semgrep_missing", "no_code_scope", "offline_without_local_rules"),
            telemetry_keys=("files_scanned", "rules_loaded", "findings_emitted", "duration_ms"),
            standards=("CWE", "OWASP", "SARIF"),
        ),
        _registration(
            "external-scan-ingest",
            "agent_bom.parsers.external_scanners",
            phase=ScannerPhase.DISCOVERY,
            run_attr="detect_and_parse",
            input_types=("sarif", "cyclonedx", "spdx", "trivy_json", "grype_json", "syft_json", "prowler_ocsf", "asff"),
            output_types=("packages", "vulnerabilities", "findings"),
            finding_types=("external-finding", "sast", "sca", "sbom-package"),
            summary="Tool-agnostic evidence import through canonical SARIF, SBOM, and scanner-native parsers.",
            capabilities=local_read,
            failure_mode=ScannerFailureMode.FAIL_CLOSED,
            skip_when=("no_external_scan_input",),
            telemetry_keys=("format", "packages_emitted", "findings_emitted", "duration_ms"),
            standards=("SARIF", "CycloneDX", "SPDX"),
        ),
    ]


def _container_and_sbom_registrations(local_read: ExtensionCapabilities) -> list[ScannerRegistration]:
    """Container image and SBOM drivers."""
    return [
        _registration(
            "container-image",
            "agent_bom.image",
            phase=ScannerPhase.DISCOVERY,
            run_attr="scan_image",
            input_types=("image_ref", "image_tar"),
            output_types=("packages", "image_scan_strategy"),
            finding_types=("container-package", "image-vulnerability-input"),
            summary="Container image package extraction via local daemon, registry, or OCI tarball paths.",
            capabilities=ExtensionCapabilities(
                scan_modes=("image", "airgap"),
                required_scopes=("image_read",),
                permissions_used=("docker_socket_read", "registry_pull", "local_tar_read"),
                outbound_destinations=("container_registry",),
                data_boundary="image_metadata_and_layers_read_only",
                network_access=True,
                guarantees=("read_only",),
            ),
            failure_mode=ScannerFailureMode.WARN_AND_CONTINUE,
            skip_when=("no_image_scope", "image_runtime_unavailable"),
            telemetry_keys=("images_scanned", "packages_emitted", "strategy", "warnings", "duration_ms"),
        ),
        _registration(
            "container-sbom-posture",
            "agent_bom.cloud.container_sbom",
            phase=ScannerPhase.ANALYSIS,
            run_attr="scan_container_image",
            input_types=("image_ref",),
            output_types=("container_sbom_posture",),
            finding_types=("unpinned-tag", "missing-sbom", "missing-provenance", "stale-image"),
            summary="Read-only OCI metadata posture check for SBOM/provenance/staleness signals.",
            capabilities=_network_read_capabilities(destinations=("docker_hub_registry_api",), scan_modes=("cloud", "container")),
            failure_mode=ScannerFailureMode.WARN_AND_CONTINUE,
            skip_when=("non_docker_hub_registry_metadata_only", "registry_unavailable"),
            telemetry_keys=("images_checked", "registry_requests", "findings_emitted", "duration_ms"),
            standards=("SLSA", "CycloneDX", "SPDX"),
        ),
        _registration(
            "sbom-ingest",
            "agent_bom.sbom",
            phase=ScannerPhase.DISCOVERY,
            run_attr="load_sbom",
            input_types=("cyclonedx", "spdx", "sbom_json"),
            output_types=("packages", "sbom_metadata"),
            finding_types=("sbom-package",),
            summary="SBOM ingestion for CycloneDX/SPDX documents into the shared package model.",
            capabilities=local_read,
            failure_mode=ScannerFailureMode.FAIL_CLOSED,
            skip_when=("no_sbom_input",),
            telemetry_keys=("packages_emitted", "format", "warnings", "duration_ms"),
            standards=("CycloneDX", "SPDX"),
        ),
    ]


def _infrastructure_registrations(local_read: ExtensionCapabilities) -> list[ScannerRegistration]:
    """IaC and live Kubernetes posture drivers."""
    return [
        _registration(
            "iac-terraform",
            "agent_bom.terraform",
            phase=ScannerPhase.DISCOVERY,
            run_attr="scan_terraform_dir",
            input_types=("terraform_dir",),
            output_types=("agents", "iac_findings"),
            finding_types=("iac", "misconfiguration", "ai-infra"),
            summary="Terraform AI infrastructure discovery and misconfiguration evidence.",
            capabilities=local_read,
            failure_mode=ScannerFailureMode.WARN_AND_CONTINUE,
            skip_when=("no_terraform_scope",),
            telemetry_keys=("files_scanned", "findings_emitted", "warnings", "duration_ms"),
            standards=("MITRE_ATLAS", "CIS", "NIST"),
        ),
        _registration(
            "iac-dbt",
            "agent_bom.iac.dbt_security",
            phase=ScannerPhase.DISCOVERY,
            run_attr="scan_dbt_file",
            input_types=("dbt_project", "dbt_profiles", "dbt_packages", "dbt_models", "dbt_macros", "dbt_ci"),
            output_types=("iac_findings",),
            finding_types=("dbt-security", "credential-exposure", "supply-chain", "sql-injection", "ci-hygiene"),
            summary="dbt project, profile, package, model, macro, seed, and CI/CD security checks.",
            capabilities=local_read,
            failure_mode=ScannerFailureMode.WARN_AND_CONTINUE,
            skip_when=("no_dbt_project_scope",),
            telemetry_keys=("files_scanned", "findings_emitted", "warnings", "duration_ms"),
            standards=("SLSA", "NIST", "SOC2"),
        ),
        _registration(
            "k8s-live-cluster",
            "agent_bom.k8s",
            phase=ScannerPhase.DISCOVERY,
            run_attr="scan_live_cluster_posture",
            input_types=("kubeconfig_context", "kubectl"),
            output_types=("iac_findings",),
            finding_types=(
                "kubernetes-live",
                "pod-security",
                "rbac-wildcard",
                "cluster-admin-binding",
                "kubelet-cis",
                "network-policy-gap",
            ),
            summary=(
                "Read-only live Kubernetes cluster audit via kubectl: PodSecurity on running "
                "workloads, RBAC/namespace over-broad grants, and node/kubelet CIS configuration."
            ),
            capabilities=ExtensionCapabilities(
                scan_modes=("cluster", "online"),
                required_scopes=("kubernetes_cluster_read",),
                permissions_used=("kubectl_get", "kubelet_configz_read"),
                outbound_destinations=("kubernetes_api_server",),
                data_boundary="cluster_state_read_only",
                network_access=True,
                guarantees=("read_only", "no_cluster_mutation"),
            ),
            failure_mode=ScannerFailureMode.SKIP_WHEN_UNAVAILABLE,
            skip_when=("kubectl_missing", "cluster_unreachable", "no_cluster_scope"),
            telemetry_keys=("pods_scanned", "nodes_scanned", "findings_emitted", "duration_ms"),
            standards=("CIS", "NIST"),
        ),
    ]


def _pipeline_and_dataset_registrations(local_read: ExtensionCapabilities) -> list[ScannerRegistration]:
    """CI/CD workflow and dataset drivers."""
    return [
        _registration(
            "cicd-github-actions",
            "agent_bom.github_actions",
            phase=ScannerPhase.DISCOVERY,
            run_attr="scan_github_actions",
            input_types=("github_actions_path",),
            output_types=("agents", "workflow_findings"),
            finding_types=("workflow-permissions", "unpinned-action", "secret-exposure", "fork-pr-risk"),
            summary="GitHub Actions workflow inventory and CI/CD posture checks.",
            capabilities=local_read,
            failure_mode=ScannerFailureMode.WARN_AND_CONTINUE,
            skip_when=("no_github_actions_scope",),
            telemetry_keys=("workflows_scanned", "findings_emitted", "warnings", "duration_ms"),
            standards=("SLSA", "CIS", "NIST"),
        ),
        _registration(
            "dataset-card",
            "agent_bom.parsers.dataset_cards",
            phase=ScannerPhase.DISCOVERY,
            run_attr="scan_dataset_directory",
            input_types=("dataset_directory", "dataset_card"),
            output_types=("dataset_cards",),
            finding_types=("unlicensed-dataset", "missing-card", "unversioned-data", "remote-source"),
            summary="Dataset-card provenance, license, and lineage scanner.",
            capabilities=local_read,
            failure_mode=ScannerFailureMode.WARN_AND_CONTINUE,
            skip_when=("no_dataset_scope",),
            telemetry_keys=("datasets_scanned", "flagged_count", "warnings", "duration_ms"),
            standards=("EU_AI_ACT", "NIST_AI_RMF"),
        ),
        _registration(
            "dataset-pii",
            "agent_bom.parsers.dataset_pii_scanner",
            phase=ScannerPhase.SCANNING,
            run_attr="scan_directory_for_pii",
            input_types=("csv", "json", "jsonl", "dataset_directory"),
            output_types=("dataset_pii_findings",),
            finding_types=("pii", "phi", "drivers_license", "email", "ssn"),
            summary="Dataset row sampling scanner for PII/PHI exposure.",
            capabilities=local_read,
            failure_mode=ScannerFailureMode.WARN_AND_CONTINUE,
            skip_when=("no_dataset_scope", "unsupported_file_type", "row_limit_reached"),
            telemetry_keys=("files_scanned", "rows_scanned", "findings_emitted", "duration_ms"),
            standards=("HIPAA", "EU_AI_ACT", "NIST_PRIVACY"),
        ),
    ]


def _content_and_policy_registrations(local_read: ExtensionCapabilities) -> list[ScannerRegistration]:
    """Prompt, skill and license policy drivers."""
    return [
        _registration(
            "prompt-injection",
            "agent_bom.parsers.prompt_scanner",
            phase=ScannerPhase.SCANNING,
            run_attr="scan_prompt_file",
            input_types=("prompt_file", "instruction_file"),
            output_types=("prompt_findings",),
            finding_types=("prompt-injection", "hidden-instruction", "tool-exfiltration"),
            summary="Prompt/instruction file scanning for injection and agentic abuse patterns.",
            capabilities=local_read,
            failure_mode=ScannerFailureMode.WARN_AND_CONTINUE,
            skip_when=("no_prompt_scope", "unsupported_file_type"),
            telemetry_keys=("files_scanned", "findings_emitted", "duration_ms"),
            standards=("OWASP_LLM", "OWASP_AGENTIC"),
        ),
        _registration(
            "skill-audit",
            "agent_bom.parsers.skill_audit",
            phase=ScannerPhase.SCANNING,
            run_attr="audit_skill_result",
            input_types=("skill_file", "instruction_file"),
            output_types=("skill_findings", "skill_audit"),
            finding_types=("skill-risk", "mcp-blocklist", "typosquat", "shell-access", "unverified-server"),
            summary=(
                "Skill/instruction file audit: registry typosquat, MCP blocklist on extracted "
                "servers, shell access, and behavioral regex/AST risks."
            ),
            capabilities=local_read,
            failure_mode=ScannerFailureMode.WARN_AND_CONTINUE,
            skip_when=("no_skill_scope", "unsupported_file_type"),
            telemetry_keys=("files_scanned", "packages_checked", "servers_checked", "findings_emitted", "duration_ms"),
            standards=("OWASP_LLM", "OWASP_AGENTIC", "OWASP_MCP"),
        ),
        _registration(
            "license-policy",
            "agent_bom.license_policy",
            phase=ScannerPhase.ANALYSIS,
            run_attr="evaluate_license_policy",
            input_types=("agents", "packages", "license_policy"),
            output_types=("license_report",),
            finding_types=("license-block", "license-warning", "unknown-license"),
            summary="SPDX license policy evaluation across discovered packages.",
            capabilities=_local_read_capabilities(scan_modes=("analysis",)),
            failure_mode=ScannerFailureMode.WARN_AND_CONTINUE,
            skip_when=("no_packages_found", "license_policy_disabled"),
            telemetry_keys=("packages_evaluated", "findings_emitted", "duration_ms"),
            standards=("SPDX", "OpenChain"),
        ),
    ]


def _advisory_and_runtime_registrations(local_read: ExtensionCapabilities) -> list[ScannerRegistration]:
    """Firmware/model advisory and runtime detector drivers."""
    return [
        _registration(
            "firmware-advisory",
            "agent_bom.scanners.firmware_advisory",
            phase=ScannerPhase.SCANNING,
            run_attr="scan_firmware_advisories",
            input_types=("gpu_inventory", "firmware_inventory"),
            output_types=("firmware_findings",),
            finding_types=("firmware-cve", "bmc-cve", "driver-cve"),
            summary="GPU firmware/BMC/driver advisory scanner for AI infrastructure.",
            capabilities=_network_read_capabilities(destinations=("bundled_firmware_advisory_feed",), scan_modes=("infra", "gpu")),
            failure_mode=ScannerFailureMode.WARN_AND_CONTINUE,
            skip_when=("no_gpu_inventory", "advisory_feed_unavailable"),
            telemetry_keys=("devices_scanned", "advisories_matched", "duration_ms"),
            standards=("NVIDIA_CSAF", "CVE"),
        ),
        _registration(
            "model-advisory",
            "agent_bom.model_advisories",
            phase=ScannerPhase.SCANNING,
            run_attr="match_model_advisories",
            input_types=("model_card", "model_inventory"),
            output_types=("model_advisories",),
            finding_types=("unsafe-model-format", "model-card-risk", "model-advisory"),
            summary="Model-specific advisory and model-card risk matching.",
            capabilities=_local_read_capabilities(scan_modes=("model",)),
            failure_mode=ScannerFailureMode.WARN_AND_CONTINUE,
            skip_when=("no_model_inventory", "feed_missing"),
            telemetry_keys=("models_scanned", "advisories_matched", "duration_ms"),
            standards=("NIST_AI_RMF", "EU_AI_ACT"),
        ),
        _registration(
            "runtime-detectors",
            "agent_bom.runtime.detectors",
            phase=ScannerPhase.SCANNING,
            run_attr="detector_pipeline",
            input_types=("tool_call", "tool_response", "runtime_event"),
            output_types=("runtime_findings", "policy_decisions"),
            finding_types=("prompt-injection", "credential-leak", "rate-limit", "tool-drift", "vector-db-injection"),
            summary="Runtime proxy detector family for agent/tool call enforcement.",
            capabilities=ExtensionCapabilities(
                scan_modes=("runtime", "proxy"),
                required_scopes=("runtime_event_read",),
                permissions_used=("tool_call_observe",),
                outbound_destinations=(),
                data_boundary="runtime_event_inline_redacted",
                network_access=False,
                guarantees=("redacted_evidence", "policy_enforced"),
            ),
            failure_mode=ScannerFailureMode.FAIL_CLOSED,
            skip_when=("runtime_proxy_disabled",),
            telemetry_keys=("events_scanned", "findings_emitted", "policy_blocks", "duration_ms"),
            standards=("OWASP_LLM", "OWASP_MCP", "SOC2"),
        ),
    ]


def _heuristic_registrations(local_read: ExtensionCapabilities) -> list[ScannerRegistration]:
    """Signature and heuristic drivers."""
    return [
        _registration(
            "yara-signature",
            "agent_bom.scanners.yara",
            phase=ScannerPhase.SCANNING,
            run_attr="scan_with_yara",
            input_types=("file", "directory", "model_file", "artifact"),
            output_types=("signature_findings",),
            finding_types=("malware-signature", "unsafe-artifact", "model-file-indicator"),
            summary="Reserved scanner-driver slot for local YARA-style artifact signatures; not executable in this release.",
            capabilities=_local_read_capabilities(scan_modes=("signature",)),
            failure_mode=ScannerFailureMode.SKIP_WHEN_UNAVAILABLE,
            execution_state=ScannerExecutionState.PLANNED,
            enabled_by_default=False,
            skip_when=("driver_not_implemented", "ruleset_missing"),
            telemetry_keys=("files_scanned", "rules_loaded", "matches", "duration_ms"),
            standards=("YARA",),
        ),
        _registration(
            "zero-day-heuristics",
            "agent_bom.scanners.zero_day",
            phase=ScannerPhase.ANALYSIS,
            run_attr="score_zero_day_residual_risk",
            input_types=("packages", "runtime_context", "exploit_signals", "graph_context"),
            output_types=("residual_risk_scores", "prioritized_findings"),
            finding_types=("residual-risk", "zero-day-susceptibility", "high-blast-radius-unfixed"),
            summary="Reserved scanner-driver slot for residual/zero-day risk scoring across SCA, runtime, and graph context.",
            capabilities=_local_read_capabilities(scan_modes=("analysis",)),
            failure_mode=ScannerFailureMode.SKIP_WHEN_UNAVAILABLE,
            execution_state=ScannerExecutionState.PLANNED,
            enabled_by_default=False,
            skip_when=("driver_not_implemented", "insufficient_context"),
            telemetry_keys=("packages_scored", "contexts_used", "scores_emitted", "duration_ms"),
            standards=("EPSS", "KEV", "NIST_AI_RMF"),
        ),
    ]


def builtin_scanner_registrations() -> list[ScannerRegistration]:
    """Return built-in scanner registrations with capability metadata."""

    local_read = _local_read_capabilities()
    return [
        *_code_registrations(local_read),
        *_sast_and_ingest_registrations(local_read),
        *_container_and_sbom_registrations(local_read),
        *_infrastructure_registrations(local_read),
        *_pipeline_and_dataset_registrations(local_read),
        *_content_and_policy_registrations(local_read),
        *_advisory_and_runtime_registrations(local_read),
        *_heuristic_registrations(local_read),
    ]
