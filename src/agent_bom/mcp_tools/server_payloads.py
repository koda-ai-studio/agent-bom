"""Root and health payloads the MCP server's HTTP metadata routes return."""

from __future__ import annotations

from typing import Any


def build_root_metadata(*, auth_required: bool) -> dict[str, Any]:
    from agent_bom import __version__

    return {
        "name": "agent-bom",
        "version": __version__,
        "description": ("Security scanner and graph for AI supply chain and infrastructure — agents, MCP, runtime, and blast radius."),
        "homepage": "https://github.com/msaad00/agent-bom",
        "source": "https://github.com/msaad00/agent-bom",
        "license": "Apache-2.0",
        "pypi": "https://pypi.org/project/agent-bom/",
        "documentation": "https://github.com/msaad00/agent-bom#readme",
        "server_card": "/.well-known/mcp/server-card.json",
        "auth_required": auth_required,
    }


def build_health_payload(*, auth_required: bool, tool_metrics_summary: dict[str, Any]) -> dict[str, Any]:
    from agent_bom import __version__

    return {
        "status": "healthy",
        "name": "agent-bom",
        "version": __version__,
        "auth_required": auth_required,
        "tool_count": tool_metrics_summary["tool_count"],
        "mcp_metrics": tool_metrics_summary,
    }
