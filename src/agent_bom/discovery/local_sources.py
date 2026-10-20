"""Local sources."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

import yaml

from agent_bom.discovery.config_parsers import (
    _parse_docker_mcp_catalog,
    parse_codex_config,
    parse_mcp_config,
)
from agent_bom.discovery.platform_config import CONFIG_LOCATIONS, _read_json_config_no_symlink
from agent_bom.models import Agent, AgentStatus, AgentType, MCPServer, TransportType
from agent_bom.security import sanitize_log_label

logger = logging.getLogger(__name__)


def discover_docker_mcp() -> Optional[Agent]:
    """Discover Docker Desktop MCP Toolkit servers.

    Reads ``~/.docker/mcp/registry.yaml`` for enabled servers, then
    cross-references with ``~/.docker/mcp/catalogs/docker-mcp.yaml``
    for image refs, tools, secrets, and metadata.
    """
    mcp_dir = Path(os.path.expanduser("~/.docker/mcp"))
    registry_path = mcp_dir / "registry.yaml"

    if not registry_path.exists():
        return None

    try:
        registry_data = yaml.safe_load(registry_path.read_text())
    except (OSError, ValueError):
        return None

    if not registry_data or not isinstance(registry_data, dict):
        return None

    registry_section = registry_data.get("registry", {})
    if not isinstance(registry_section, dict):
        return None

    enabled_names = set(registry_section.keys())
    if not enabled_names:
        return Agent(
            name="docker-mcp",
            agent_type=AgentType.DOCKER_MCP,
            config_path=str(registry_path),
            status=AgentStatus.INSTALLED_NOT_CONFIGURED,
        )

    # Cross-reference with catalog for full metadata
    catalog_path = mcp_dir / "catalogs" / "docker-mcp.yaml"
    servers: list[MCPServer] = []

    if catalog_path.exists():
        servers = _parse_docker_mcp_catalog(enabled_names, catalog_path)

    # For enabled servers not found in catalog, create minimal entries
    found_names = {s.name for s in servers}
    for name in enabled_names - found_names:
        servers.append(
            MCPServer(
                name=name,
                command="docker",
                args=[],
                transport=TransportType.STDIO,
                config_path=str(registry_path),
            )
        )

    return Agent(
        name="docker-mcp",
        agent_type=AgentType.DOCKER_MCP,
        config_path=str(registry_path),
        mcp_servers=servers,
        status=AgentStatus.CONFIGURED if servers else AgentStatus.INSTALLED_NOT_CONFIGURED,
    )


def discover_filesystem_mcps(root: Path) -> list[Agent]:
    """Discover MCP configs inside a mounted filesystem (VM snapshot, container).

    Searches for known MCP client config files relative to every home
    directory found under *root* (e.g. ``/mnt/snapshot/home/user/.cursor/mcp.json``).

    This enables agent → server → package → CVE chain mapping for VM
    disk snapshots without requiring the VM to be running.

    Security: only reads JSON/TOML config files — no execution, no symlink
    traversal outside the root, no environment variable expansion.
    """
    agents: list[Agent] = []
    root = root.resolve()
    if not root.is_dir():
        return agents

    # Collect all home-like directories inside the root
    # Patterns: /home/*/  /root/  /Users/*/  (Linux, macOS layouts)
    home_dirs: list[Path] = []
    for pattern in ["home/*", "root", "Users/*"]:
        home_dirs.extend(p for p in root.glob(pattern) if p.is_dir())
    # Also check root itself (if someone mounted just a home dir)
    home_dirs.append(root)

    # Extract the relative portion of each CONFIG_LOCATIONS path (strip ~/  prefix)
    # and search for them under each home dir
    for agent_type, locations in CONFIG_LOCATIONS.items():
        # Check all platform paths (VM might be a different OS)
        all_paths: set[str] = set()
        for plat_paths in locations.values():
            for p in plat_paths:
                # Strip ~/ prefix to get relative path
                rel = p.lstrip("~").lstrip("/")
                all_paths.add(rel)

        for home in home_dirs:
            for rel_path in all_paths:
                config_path = home / rel_path
                # Security: ensure resolved path stays inside root
                try:
                    resolved = config_path.resolve()
                    if not resolved.is_relative_to(root):
                        logger.warning("Skipping path outside root: %s", sanitize_log_label(config_path))
                        continue
                except (OSError, ValueError):
                    continue

                if not config_path.exists() or not config_path.is_file():
                    continue

                try:
                    servers: list[MCPServer] = []
                    if config_path.suffix == ".json":
                        config_data = _read_json_config_no_symlink(config_path)
                        servers = parse_mcp_config(config_data, str(config_path))
                    elif config_path.suffix == ".toml" and agent_type == AgentType.CODEX_CLI:
                        servers = parse_codex_config(str(config_path))

                    if servers:
                        agent = Agent(
                            name=f"{agent_type.value}@{home.name}",
                            agent_type=agent_type,
                            config_path=str(config_path),
                            mcp_servers=servers,
                            status=AgentStatus.CONFIGURED,
                        )
                        agents.append(agent)
                        logger.info(
                            "Discovered %s with %d server(s) in filesystem: %s",
                            sanitize_log_label(agent_type.value),
                            len(servers),
                            sanitize_log_label(config_path),
                        )
                except Exception:
                    logger.debug("Failed to parse %s", sanitize_log_label(config_path), exc_info=True)

    return agents
