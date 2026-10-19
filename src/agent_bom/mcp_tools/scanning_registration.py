"""Scanning MCP tool registration."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from mcp_types import CallToolResult
from pydantic import Field

ScanRepoUrl = Annotated[
    str | None,
    Field(
        description=(
            "Public git repository URL to clone and scan, e.g. "
            "'https://github.com/org/repo'. Maps the repo's dependencies, project "
            "structure, secrets, IaC, and AI/MCP usage into an AI-BOM. Static and "
            "read-only: the repository is shallow-cloned into a temporary directory, "
            "scanned without ever executing its code, then deleted. The fastest way "
            "to point this tool at a target — no local checkout required."
        )
    ),
]

ScanConfigPath = Annotated[
    str | None,
    Field(
        description=(
            "Local directory to scan — a project root or an MCP client config "
            "directory. Auto-discovers installed MCP clients if omitted unless "
            "no_discover=true. "
            "Mutually exclusive with repo_url."
        )
    ),
]

ScanNoDiscover = Annotated[
    bool,
    Field(
        description=(
            "Disable ambient host MCP-client discovery. Explicit repo/config, image, "
            "SBOM, and package targets are still scanned; use this for deterministic CI."
        )
    ),
]

ScanImage = Annotated[str | None, Field(description="Docker image to scan (e.g. 'nginx:1.25', 'ghcr.io/org/app:v1').")]

ScanSbomPath = Annotated[str | None, Field(description="Path to existing CycloneDX or SPDX JSON SBOM file to ingest.")]

ScanPackage = Annotated[
    str | None,
    Field(
        description=(
            "Direct package or MCP launch command to scan, e.g. "
            "'npx @modelcontextprotocol/server-filesystem@2025.1.14' or '@modelcontextprotocol/server-filesystem'. "
            "A bare 'name@version' spec is assumed to be npm — pass ``ecosystem`` for anything else."
        )
    ),
]

ScanEcosystem = Annotated[
    str | None,
    Field(
        description=(
            "Ecosystem of ``package`` when the spec does not name a launcher: 'npm', "
            "'pypi', 'go', 'cargo', 'maven', 'nuget', 'rubygems', 'composer', 'swift', "
            "'pub', 'hex', 'conda', 'deb', 'apk', or 'rpm'. Omitted, the ecosystem is "
            "inferred from the spec (PEP 440 specifiers such as 'flask==0.12.2' are "
            "PyPI) and any assumption is reported in the result warnings."
        )
    ),
]

ScanEnrich = Annotated[bool, Field(description="Enable NVD CVSS, EPSS probability, and CISA KEV enrichment.")]

ScanOffline = Annotated[
    bool | None,
    Field(
        description=(
            "true: use the local vulnerability DB only and skip registry, OSV, GHSA, and NVIDIA "
            "network lookups (requires a populated DB from `agent-bom db update`). false: query "
            "those sources online. Omitted: online unless the server operator set "
            "AGENT_BOM_OFFLINE or AGENT_BOM_VULN_DB_OFFLINE."
        )
    ),
]

ScanScorecard = Annotated[bool, Field(description="Enrich packages with OpenSSF Scorecard scores (requires resolvable GitHub repos).")]

ScanTransitive = Annotated[bool, Field(description="Resolve transitive dependencies for npx/uvx packages.")]

ScanVerifyIntegrity = Annotated[bool, Field(description="Verify package SHA-256/SRI hashes and SLSA provenance against registries.")]

ScanFailSeverity = Annotated[
    str | None, Field(description="Return failure status if vulns at this severity or higher: critical, high, medium, low.")
]

ScanWarnSeverity = Annotated[
    str | None,
    Field(
        description=(
            "Return warning status (gate_status=warn, exit 0) when vulns at this severity or higher exist. "
            "Use with fail_severity for two-tier CI gates, e.g. warn_severity='medium', fail_severity='critical'."
        )
    ),
]

ScanAutoUpdateDb = Annotated[
    bool,
    Field(description="Explicitly refresh the local vuln DB when older than the daily freshness target before scanning."),
]

ScanDbSources = Annotated[
    str | None,
    Field(description="Comma-separated DB sources to sync before scanning (e.g. 'nvd,ghsa,osv,epss,kev')."),
]

ScanOutputFormat = Annotated[
    str,
    Field(description="Output format: 'json' (default), 'sarif', 'cyclonedx', 'spdx', 'junit', 'csv', or 'markdown'."),
]

ScanPolicy = Annotated[
    dict | None,
    Field(
        description=(
            "Policy object to evaluate alongside scan results,"
            ' e.g. {"rules": [{"id": "no-critical", "severity_gte": "critical", "action": "fail"}]}.'
        )
    ),
]

ScanDetail = Annotated[
    Literal["summary", "full"],
    Field(
        description=(
            "JSON output only. 'summary' (default): counts, top findings, affected paths, and a "
            "result_id for paged follow-ups. 'full': the whole AI-BOM document, shortened "
            "structurally (still valid JSON, with _truncation metadata) if it exceeds the response budget."
        )
    ),
]

ScanResultId = Annotated[
    str | None,
    Field(
        description=(
            "result_id from a previous scan response. With it, no new scan runs: returns that result's summary, or one page of `section`."
        )
    ),
]

ScanSection = Annotated[
    str | None,
    Field(description="Section of a stored result to page, e.g. 'findings', 'blast_radius', 'packages', 'exposure_paths'."),
]

ScanOffset = Annotated[int, Field(ge=0, description="Zero-based item offset into `section`.")]

ScanLimit = Annotated[int, Field(ge=1, le=200, description="Maximum items per page of `section` (1-200).")]


_SCAN_DESCRIPTION = """Run a full AI supply chain security scan and return an AI-BOM.

Point it at a target with one of:
  • repo_url     — a public git repo URL (cloned + scanned, no checkout)
  • config_path  — a local project / MCP-config directory
  • image        — a Docker image
  • sbom_path    — an existing CycloneDX/SPDX SBOM
  • package      — a single package or MCP launch command (pair it with
                   ``ecosystem`` when the spec names no launcher)
With none of these, it auto-discovers local MCP clients (Claude Desktop,
Cursor, Windsurf, VS Code Copilot, OpenClaw, etc.).

It extracts package dependencies, looks up CVEs (online via OSV.dev and
advisory sources unless offline mode is requested or configured),
assesses config security (credential exposure, tool access), computes
blast radius, and returns structured results. Scanning is fully static
and read-only — repository and image contents are parsed, never executed.

Returns:
    JSON. By default a bounded summary: counts (packages, agents,
    findings by severity/category), top findings, affected paths, and a
    result_id. Page any full-fidelity section with
    scan(result_id=..., section='findings', offset=0, limit=25).
    An incomplete scan (e.g. vulnerability source unavailable) is
    returned as an error result whose body is still JSON.
"""


def _register_scan(
    mcp: Any,
    *,
    read_only: Any,
    max_response_chars: Any,
    _execute_tool_async: Any,
    _json_tool_result: Any,
    _mcp_request_ctx: Any,
    _run_scan_pipeline: Any,
    _scan_result_owner: Any,
    _truncate_response: Any,
    **_unused: Any,
) -> None:
    from agent_bom.mcp_tools.scanning import scan_impl

    @mcp.tool(annotations=read_only, title="Security Scan", description=_SCAN_DESCRIPTION)
    async def scan(
        repo_url: ScanRepoUrl = None,
        config_path: ScanConfigPath = None,
        no_discover: ScanNoDiscover = False,
        image: ScanImage = None,
        sbom_path: ScanSbomPath = None,
        package: ScanPackage = None,
        ecosystem: ScanEcosystem = None,
        enrich: ScanEnrich = False,
        offline: ScanOffline = None,
        scorecard: ScanScorecard = False,
        transitive: ScanTransitive = False,
        verify_integrity: ScanVerifyIntegrity = False,
        fail_severity: ScanFailSeverity = None,
        warn_severity: ScanWarnSeverity = None,
        auto_update_db: ScanAutoUpdateDb = False,
        db_sources: ScanDbSources = None,
        output_format: ScanOutputFormat = "json",
        policy: ScanPolicy = None,
        detail: ScanDetail = "summary",
        result_id: ScanResultId = None,
        section: ScanSection = None,
        offset: ScanOffset = 0,
        limit: ScanLimit = 25,
    ) -> Annotated[CallToolResult, str]:
        text = await _execute_tool_async(
            "scan",
            scan_impl,
            config_path=config_path,
            no_discover=no_discover,
            repo_url=repo_url,
            image=image,
            sbom_path=sbom_path,
            package=package,
            ecosystem=ecosystem,
            enrich=enrich,
            offline=offline,
            scorecard=scorecard,
            transitive=transitive,
            verify_integrity=verify_integrity,
            fail_severity=fail_severity,
            warn_severity=warn_severity,
            auto_update_db=auto_update_db,
            db_sources=db_sources,
            output_format=output_format,
            policy=policy,
            detail=detail,
            result_id=result_id,
            section=section,
            offset=offset,
            limit=limit,
            _run_scan_pipeline=_run_scan_pipeline,
            _truncate_response=_truncate_response,
            _result_owner=_scan_result_owner(_mcp_request_ctx.get),
            _max_response_chars=max_response_chars,
        )
        return _json_tool_result(text)


def _register_check(
    mcp: Any, *, read_only: Any, _execute_tool_async: Any, _truncate_response: Any, _validate_ecosystem: Any, **_unused: Any
) -> None:
    from agent_bom.mcp_tools.scanning import check_impl

    @mcp.tool(annotations=read_only, title="Package CVE Check")
    async def check(
        package: Annotated[
            str,
            Field(
                description=(
                    "Package name with optional version, e.g. 'express@4.18.2',"
                    " '@modelcontextprotocol/server-filesystem@2025.1.14', or 'requests' (resolves @latest)."
                )
            ),
        ],
        ecosystem: Annotated[
            str,
            Field(
                description=(
                    "Package ecosystem: 'npm', 'pypi', 'go', 'cargo', 'maven', 'nuget', "
                    "'rubygems', 'composer', 'swift', 'pub', 'hex', 'conda', 'deb', 'apk', or 'rpm'."
                )
            ),
        ] = "npm",
        version: Annotated[
            str | None,
            Field(
                description=(
                    "Optional package version when omitted from ``package`` "
                    "(e.g. package='flask', version='0.12.2'). Prefer embedding "
                    "in ``package`` as 'flask@0.12.2' or 'flask==0.12.2' when possible."
                ),
            ),
        ] = None,
        offline: Annotated[
            bool,
            Field(
                description=(
                    "Use only the local advisory database. An explicit version is required; "
                    "registry resolution and publication checks are disabled."
                )
            ),
        ] = False,
    ) -> str:
        """Check a specific package for known CVEs before installing.

        Queries OSV.dev for vulnerabilities in the given package. Use this
        before installing an MCP server or dependency to verify it is safe.

        Args:
            package: Package name with optional version, e.g. "express@4.18.2",
                     "@modelcontextprotocol/server-filesystem@2025.1.14",
                     or just "requests" (resolves @latest).
            ecosystem: Package ecosystem — "npm", "pypi", "go", "cargo",
                       "maven", "nuget", "rubygems", "composer", "swift",
                       "pub", "hex", "conda", "deb", "apk", or "rpm".
                       Defaults to "npm".

        Returns:
            JSON with package, version, ecosystem, vulnerability count,
            and vulnerability details (id, severity, cvss, fix version, summary).
        """
        return await _execute_tool_async(
            "check",
            check_impl,
            package=package,
            ecosystem=ecosystem,
            version=version,
            offline=offline,
            _validate_ecosystem=_validate_ecosystem,
            _truncate_response=_truncate_response,
        )


def register_scanning_tools(mcp: Any, **context: Any) -> None:
    """Register scanning tools with shared execution callbacks."""
    _register_scan(mcp, **context)
    _register_check(mcp, **context)
