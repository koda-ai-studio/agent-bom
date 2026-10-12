"""Register the existing MCP risk tool with explicit audit scope controls."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from agent_bom.mcp_tools.audit import tool_risk_assessment_impl


def register_audit_tool(mcp, *, runtime_introspection, execute_tool_sync_async, safe_path, truncate_response) -> None:
    @mcp.tool(annotations=runtime_introspection, title="Tool Capability Risk")
    async def tool_risk_assessment(
        config_path: Annotated[str | None, Field(description="Path to MCP client config directory. Auto-discovers all if omitted.")] = None,
        live: Annotated[
            bool, Field(description="Connect for live descriptors; false audits discovered configuration without connections.")
        ] = True,
        expected_capabilities: Annotated[
            list[Literal["read", "write", "delete", "execute", "network", "auth", "admin"]] | None,
            Field(description="Operator-defined expected capabilities; omitted uses agent-type heuristics, empty allows none."),
        ] = None,
        timeout: Annotated[float, Field(ge=0.1, le=60.0, description="Per-server introspection timeout in seconds.")] = 10.0,
        allow_command_execution: Annotated[
            bool,
            Field(description="Explicitly allow launching unblocked stdio server commands. False only connects to HTTP/SSE servers."),
        ] = False,
    ) -> str:
        """Audit MCP descriptors, permission scope and authentication configuration.

        Returns descriptor coverage and heuristic findings; does not test auth
        bypass, general resource bodies or rendered prompts. Set live=false
        for passive discovery; live mode retains its stdio execution gate.

        Discovers configured MCP clients, connects to their servers, calls
        ``tools/list``, and classifies every exposed tool by capability
        (filesystem, network, code execution, credential access) to produce a
        per-tool and per-server risk score from what the servers actually
        advertise at runtime.

        Args:
            config_path: MCP client config directory to read; auto-discovers all
                supported clients when omitted.
            timeout: Per-server introspection timeout in seconds.
            allow_command_execution: Explicit opt-in required before launching
                discovered stdio server commands.

        Returns:
            JSON with per-server tool inventories, per-tool capability classes
            and risk levels, and an aggregate server risk rating.

        Use this to assess the blast radius of MCP servers an agent can reach
        before granting or trusting their tools.
        """
        return await execute_tool_sync_async(
            "tool_risk_assessment",
            tool_risk_assessment_impl,
            config_path=config_path,
            timeout=timeout,
            live=live,
            expected_capabilities=expected_capabilities,
            allow_command_execution=allow_command_execution,
            _safe_path=safe_path,
            _truncate_response=truncate_response,
            destructive=allow_command_execution,
        )
