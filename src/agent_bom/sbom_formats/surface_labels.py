"""One label for MCP servers vs dependency wrappers across SBOM emitters."""

from __future__ import annotations

from typing import Any


def server_surface_description(server: Any) -> str:
    """``MCP Server (...)`` only for real MCP servers; package manifests and other wrappers say so."""
    if server.counts_as_mcp_server:
        return f"MCP Server ({server.transport.value})"
    return f"Dependency surface ({server.surface.value})"
