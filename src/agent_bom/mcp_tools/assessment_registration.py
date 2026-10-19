"""Assessment MCP tool registration."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field


def _register_policy_check(
    mcp: Any,
    *,
    read_only: Any,
    _execute_tool_async: Any,
    _execute_tool_sync_async: Any,
    _get_registry_data: Any,
    _run_scan_pipeline: Any,
    _truncate_response: Any,
    _validate_ecosystem: Any,
) -> None:
    from agent_bom.mcp_tools.compliance import policy_check_impl

    @mcp.tool(annotations=read_only, title="Policy Evaluation")
    async def policy_check(
        policy_json: Annotated[
            str,
            Field(
                description=(
                    "JSON string containing policy rules,"
                    ' e.g. {"rules": [{"id": "no-critical", "severity_gte": "critical", "action": "fail"}]}.'
                )
            ),
        ],
    ) -> str:
        """Evaluate a security policy against current scan results.

        Runs a scan, then evaluates the provided policy rules against the
        findings. Policies can gate on severity thresholds, CISA KEV status,
        AI risk flags, credential exposure, and denied packages.

        Args:
            policy_json: JSON string containing policy rules. Example:
                {"rules": [{"id": "no-critical", "severity_gte": "critical",
                "action": "fail"}, {"id": "no-kev", "kev": true, "action": "fail"}]}

        Returns:
            JSON with passed (bool), violations list, failure_count, and
            warning_count.
        """
        return await _execute_tool_async(
            "policy_check",
            policy_check_impl,
            policy_json=policy_json,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )


def _register_registry_lookup(
    mcp: Any,
    *,
    read_only: Any,
    _execute_tool_async: Any,
    _execute_tool_sync_async: Any,
    _get_registry_data: Any,
    _run_scan_pipeline: Any,
    _truncate_response: Any,
    _validate_ecosystem: Any,
) -> None:
    from agent_bom.mcp_tools.registry import registry_lookup_impl

    @mcp.tool(annotations=read_only, title="Registry Lookup")
    async def registry_lookup(
        server_name: Annotated[
            str | None, Field(description="MCP server name to look up, e.g. 'filesystem', '@modelcontextprotocol/server-github'.")
        ] = None,
        package_name: Annotated[
            str | None,
            Field(
                description="Package name to search for, e.g. 'mcp-server-sqlite'. At least one of server_name or package_name is required."
            ),
        ] = None,
    ) -> str:
        """Query the agent-bom MCP server threat intelligence registry.

        Look up risk level, known tools, credential requirements, and
        verification status for known MCP servers. The registry contains
        109+ servers with security metadata.

        Args:
            server_name: MCP server name to look up (e.g. "filesystem",
                         "@modelcontextprotocol/server-github").
            package_name: Package name to search for (e.g. "mcp-server-sqlite").
                          At least one of server_name or package_name is required.

        Returns:
            JSON with registry entry: risk_level, verified, tools,
            credential_env_vars, risk_justification. Returns found=false
            if not found.
        """
        return await _execute_tool_sync_async(
            "registry_lookup",
            registry_lookup_impl,
            server_name=server_name,
            package_name=package_name,
            _get_registry_data=_get_registry_data,
        )


def _register_generate_sbom(
    mcp: Any,
    *,
    read_only: Any,
    _execute_tool_async: Any,
    _execute_tool_sync_async: Any,
    _get_registry_data: Any,
    _run_scan_pipeline: Any,
    _truncate_response: Any,
    _validate_ecosystem: Any,
) -> None:
    from agent_bom.mcp_tools.sbom import generate_sbom_impl

    @mcp.tool(annotations=read_only, title="Generate SBOM")
    async def generate_sbom(
        format: Annotated[str, Field(description="SBOM format: 'cyclonedx' (CycloneDX 1.7) or 'spdx' (SPDX 3.0).")] = "cyclonedx",
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
    ) -> str:
        """Generate a Software Bill of Materials (SBOM) for your AI agent setup.

        Discovers AI agents and MCP servers, extracts all package dependencies,
        and generates a standards-compliant SBOM.

        Args:
            format: SBOM format — "cyclonedx" (CycloneDX 1.7) or "spdx" (SPDX 3.0).
            config_path: Path to a specific MCP config directory.
                         If not provided, auto-discovers all local agent configs.

        Returns:
            JSON string containing the SBOM in the requested format.
        """
        return await _execute_tool_async(
            "generate_sbom",
            generate_sbom_impl,
            format=format,
            config_path=config_path,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )


def _register_compliance(
    mcp: Any,
    *,
    read_only: Any,
    _execute_tool_async: Any,
    _execute_tool_sync_async: Any,
    _get_registry_data: Any,
    _run_scan_pipeline: Any,
    _truncate_response: Any,
    _validate_ecosystem: Any,
) -> None:
    from agent_bom.mcp_tools.compliance_persisted import compliance_tool_impl

    @mcp.tool(annotations=read_only, title="Compliance Posture")
    async def compliance(
        config_path: Annotated[
            str | None, Field(description="Local scan only: MCP client config directory. Auto-discovers if omitted.")
        ] = None,
        image: Annotated[str | None, Field(description="Local scan only: Docker image to scan, e.g. 'nginx:1.25'.")] = None,
        tenant_id: Annotated[str, Field(description="Tenant scope for persisted compliance. Defaults to 'default'.")] = "default",
        source: Annotated[
            Literal["auto", "persisted", "local_scan"],
            Field(
                description="auto: persisted tenant evidence when it exists, else a labelled local scan. persisted / local_scan force one."
            ),
        ] = "auto",
        framework: Annotated[
            str | None, Field(max_length=64, description="Persisted only: add one framework's controls, e.g. 'soc2'.")
        ] = None,
        control: Annotated[
            str | None, Field(max_length=64, description="Persisted only: page the finding ids driving this control.")
        ] = None,
        limit: Annotated[int, Field(ge=1, le=500, description="Driving finding ids per page.")] = 50,
        cursor: Annotated[str | None, Field(max_length=512, description="driving_findings.next_cursor from the previous page.")] = None,
    ) -> str:
        """Return compliance posture with its source: the tenant's persisted evidence, or a labelled local scan.

        With completed scans in the control plane, ``summary`` is exactly
        ``/v1/compliance/summary``; ``framework`` adds ``/v1/compliance/{framework}``
        and ``control`` pages the driving finding ids from
        ``/v1/findings?framework=&control=``. Otherwise (or with
        source='local_scan') it scans local MCP configurations and labels that scope.
        """
        return await _execute_tool_async(
            "compliance",
            compliance_tool_impl,
            config_path=config_path,
            image=image,
            tenant_id=tenant_id,
            source=source,
            framework=framework,
            control=control,
            limit=limit,
            cursor=cursor,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )


def _register_remediate(
    mcp: Any,
    *,
    read_only: Any,
    _execute_tool_async: Any,
    _execute_tool_sync_async: Any,
    _get_registry_data: Any,
    _run_scan_pipeline: Any,
    _truncate_response: Any,
    _validate_ecosystem: Any,
) -> None:
    from agent_bom.mcp_tools.sbom import remediate_impl

    @mcp.tool(annotations=read_only, title="Remediation Plan")
    async def remediate(
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
        image: Annotated[str | None, Field(description="Docker image to scan, e.g. 'nginx:1.25'.")] = None,
    ) -> str:
        """Generate a remediation plan for vulnerabilities in your AI agent setup.

        Scans for vulnerabilities, then generates actionable fix commands for
        each affected package (npm install, pip install), credential scope
        reduction guidance, and reports on unfixable vulnerabilities.

        Args:
            config_path: Path to a specific MCP config directory.
                         If not provided, auto-discovers all local agent configs.
            image: Docker image reference to scan (e.g. "nginx:1.25").

        Returns:
            JSON with package_fixes (upgrade commands by ecosystem),
            credential_fixes (scope reduction steps), and unfixable items.
        """
        return await _execute_tool_async(
            "remediate",
            remediate_impl,
            config_path=config_path,
            image=image,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
        )


def _register_verify(
    mcp: Any,
    *,
    read_only: Any,
    _execute_tool_async: Any,
    _execute_tool_sync_async: Any,
    _get_registry_data: Any,
    _run_scan_pipeline: Any,
    _truncate_response: Any,
    _validate_ecosystem: Any,
) -> None:
    from agent_bom.mcp_tools.runtime import verify_impl

    @mcp.tool(annotations=read_only, title="Package Integrity Verify")
    async def verify(
        package: Annotated[str, Field(description="Package name with optional version, e.g. 'express@4.18.2' or 'requests==2.31.0'.")],
        ecosystem: Annotated[str, Field(description="Package ecosystem: 'npm' or 'pypi'.")] = "npm",
    ) -> str:
        """Verify package integrity and SLSA provenance against registries.

        Checks SHA-256/SRI hashes against npm/PyPI registries and looks up
        SLSA build provenance attestations to confirm the package was built
        from its claimed source repository.

        Returns:
            JSON with integrity verification (hash match, expected vs actual)
            and provenance status (SLSA level, source repo, build trigger).
        """
        return await _execute_tool_async(
            "verify",
            verify_impl,
            package=package,
            ecosystem=ecosystem,
            _validate_ecosystem=_validate_ecosystem,
            _truncate_response=_truncate_response,
        )


def register_assessment_tools(mcp: Any, **context: Any) -> None:
    """Register assessment tools with shared execution callbacks."""
    _register_policy_check(mcp, **context)
    _register_registry_lookup(mcp, **context)
    _register_generate_sbom(mcp, **context)
    _register_compliance(mcp, **context)
    _register_remediate(mcp, **context)
    _register_verify(mcp, **context)
