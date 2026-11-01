"""Runtime risk for an introspected MCP server, including poisoned tool descriptors.

A descriptor that instructs the model (hidden tags, "do not tell the user",
credential paths, exfiltration) makes the tool high risk whatever it can do,
so the description findings are folded into the per-tool and server risk the
``mcp introspect`` output reports.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.models import MCPServer, MCPTool
from agent_bom.risk_analyzer import score_server_risk, score_tool_risk

if TYPE_CHECKING:
    from agent_bom.mcp_introspect import ServerIntrospection


def descriptor_findings(server_name: str, tools: list[MCPTool]) -> list[dict]:
    """Hidden/unsafe-instruction findings on live tool descriptors, as plain rows."""
    from agent_bom.enforcement import scan_tool_descriptions

    rows = scan_tool_descriptions(MCPServer(name=server_name, tools=list(tools)))
    return [{"tool_name": row.tool_name, "category": row.category, "severity": row.severity, "reason": row.reason} for row in rows]


def _tool_profile(tool: MCPTool, hits: list[str]) -> dict:
    profile = score_tool_risk(tool).to_dict()
    profile["description_findings"] = hits
    if hits and profile["risk_level"] in {"low", "medium"}:
        profile["risk_level"] = "high"
        profile["justification"] = f"{profile['justification']} Descriptor carries {len(hits)} hidden/unsafe instruction(s)."
    return profile


def apply_runtime_risk(server: MCPServer, result: ServerIntrospection) -> None:
    """Fill the introspection result's risk fields from its live tools and their descriptors."""
    findings = descriptor_findings(server.name, result.runtime_tools)
    result.description_findings = findings
    profiles = [_tool_profile(tool, [row["reason"] for row in findings if row["tool_name"] == tool.name]) for tool in result.runtime_tools]
    profiles.sort(key=lambda item: (item["risk_score"], item["tool_name"]), reverse=True)
    result.tool_risk_profiles = profiles

    server_profile = score_server_risk(result.runtime_tools, credentials=server.credential_names)
    result.capability_risk_score = round(server_profile.risk_score, 2)
    result.capability_risk_level = server_profile.risk_level
    result.capability_counts = server_profile.capabilities
    result.capability_tools = server_profile.capability_tools
    result.dangerous_combinations = server_profile.dangerous_combinations
    result.risk_justification = server_profile.justification
    poisoned_tools = sorted({str(row["tool_name"] or "") for row in findings})
    if poisoned_tools:
        if result.capability_risk_level in {"low", "medium"}:
            result.capability_risk_level = "high"
        result.risk_justification = (
            f"{result.risk_justification} {len(findings)} tool-description finding(s) on {', '.join(poisoned_tools)}: "
            "hidden or unsafe instructions in live descriptors (OWASP MCP03)."
        ).strip()


__all__ = ["apply_runtime_risk", "descriptor_findings"]
