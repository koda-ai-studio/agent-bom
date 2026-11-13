"""Find project manifest groups that re-bind an MCP server's own packages.

``scan DIR`` groups every manifest directory under the project into a
``project`` server, and an MCP server whose script lives in one of those
directories extracts the same manifests. Both bindings are true evidence, but
summing them reported each package and vulnerability twice. The project group
is linked to the MCP server it duplicates so report totals count it once.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.models import Agent, MCPServer, Package, ServerSurface
from agent_bom.parsers import find_server_directory


def _key(package: Package) -> tuple[str, str, str]:
    return (str(package.ecosystem or "").lower(), str(package.name).lower(), str(package.version or ""))


def _resolved(path: str | Path) -> Path | None:
    try:
        return Path(path).expanduser().resolve()
    except (OSError, RuntimeError, ValueError):
        return None


def _mcp_servers_by_directory(agents: list[Agent]) -> dict[Path, list[MCPServer]]:
    by_directory: dict[Path, list[MCPServer]] = {}
    for agent in agents:
        for server in agent.mcp_servers:
            if server.surface != ServerSurface.MCP or not server.packages:
                continue
            directory = find_server_directory(server)
            resolved = _resolved(directory) if directory is not None else None
            if resolved is not None:
                by_directory.setdefault(resolved, []).append(server)
    return by_directory


def _is_manifest_group(server: MCPServer) -> bool:
    return server.command == "project" and server.surface == ServerSurface.OTHER and bool(server.args) and bool(server.packages)


def mark_manifest_bindings(agents: list[Agent]) -> int:
    """Link each duplicating manifest group to its MCP server; return how many were linked.

    A group is a duplicate only when it is the same directory and every one of
    its packages is already bound to that MCP server, so a manifest carrying
    packages the server does not is still counted in full.
    """
    by_directory = _mcp_servers_by_directory(agents)
    linked = 0
    for agent in agents:
        for server in agent.mcp_servers:
            if not _is_manifest_group(server):
                continue
            directory = _resolved(server.args[0])
            keys = {_key(package) for package in server.packages}
            for owner in by_directory.get(directory, []) if directory is not None else []:
                if keys <= {_key(package) for package in owner.packages}:
                    server.package_binding_of = owner.canonical_id
                    linked += 1
                    break
    return linked
