"""Registration of the ``blast_radius`` analysis tool."""

from __future__ import annotations

from typing import Annotated, Any, Callable

from pydantic import Field

from agent_bom.mcp_tools.analysis import blast_radius_impl


def register_blast_radius_tool(
    mcp: Any,
    *,
    read_only: Any,
    execute_tool_async: Callable[..., Any],
    validate_cve_id: Callable[[str], str],
    run_scan_pipeline: Callable[..., Any],
    get_persisted_evidence: Callable[..., dict[str, Any]],
    truncate_response: Callable[[str], str],
    result_owner: Callable[[], str],
) -> None:
    """Tool 3: blast_radius. ``result_owner`` is resolved per call for the session scan result."""

    @mcp.tool(annotations=read_only, title="Blast Radius Analysis")
    async def blast_radius(
        cve_id: Annotated[str, Field(description="CVE identifier to look up, e.g. 'CVE-2024-1234' or 'GHSA-xxxx'.")],
        tenant_id: Annotated[str, Field(description="Tenant scope for persisted findings. Defaults to 'default'.")] = "default",
        scan_id: Annotated[str | None, Field(description="Optional persisted scan scope.")] = None,
        result_id: Annotated[
            str | None,
            Field(
                max_length=128,
                description=(
                    "result_id from a scan response in this session. Answers from that scan result; omitted, the caller's "
                    "newest scan result is consulted before persisted findings and a host configuration scan."
                ),
            ),
        ] = None,
    ) -> str:
        """Look up the blast radius of a specific CVE across your AI agent setup.

        Evidence order: the session's scan result (``result_id``, else the
        caller's newest, labelled ``session_scan_result``), then the tenant's
        persisted control-plane findings, then a local MCP configuration scan.
        Every answer names its ``source``.

        Args:
            cve_id: The CVE identifier (e.g. "CVE-2024-1234" or "GHSA-xxxx").

        Returns:
            JSON with blast radius details including risk_score,
            affected_servers, affected_agents, exposed_credentials, and
            exposed_tools. Returns found=false if CVE not found.
        """
        return await execute_tool_async(
            "blast_radius",
            blast_radius_impl,
            cve_id=cve_id,
            tenant_id=tenant_id,
            scan_id=scan_id,
            result_id=result_id,
            _validate_cve_id=validate_cve_id,
            _run_scan_pipeline=run_scan_pipeline,
            _get_persisted_evidence=get_persisted_evidence,
            _truncate_response=truncate_response,
            _result_owner=result_owner(),
        )
