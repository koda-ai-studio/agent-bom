"""Platform config."""

from __future__ import annotations

import json
import os
import platform
import shutil
from pathlib import Path
from typing import Optional

from agent_bom.discovery.config_parsers import (
    parse_codex_config,
    parse_mcp_config,
)
from agent_bom.models import Agent, AgentStatus, AgentType, MCPServer


def _read_text_no_symlink(path: Path, *, encoding: str = "utf-8") -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        with os.fdopen(fd, "rb") as fh:
            fd = -1
            return fh.read().decode(encoding, errors="replace")
    finally:
        if fd >= 0:
            os.close(fd)


def _read_json_config_no_symlink(path: Path) -> dict:
    return json.loads(_read_text_no_symlink(path))


CONFIG_LOCATIONS: dict[AgentType, dict[str, list[str]]] = {
    AgentType.CLAUDE_DESKTOP: {
        "Darwin": ["~/Library/Application Support/Claude/claude_desktop_config.json"],
        "Linux": ["~/.config/Claude/claude_desktop_config.json"],
        "Windows": ["~/AppData/Roaming/Claude/claude_desktop_config.json"],
    },
    AgentType.CLAUDE_CODE: {
        "Darwin": ["~/.claude/settings.json", "~/.claude.json"],
        "Linux": ["~/.claude/settings.json", "~/.claude.json"],
        "Windows": ["~/.claude/settings.json", "~/.claude.json"],
    },
    AgentType.CURSOR: {
        "Darwin": ["~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json", "~/.cursor/mcp.json"],
        "Linux": ["~/.config/Cursor/User/globalStorage/cursor.mcp/mcp.json", "~/.cursor/mcp.json"],
        "Windows": ["~/AppData/Roaming/Cursor/User/globalStorage/cursor.mcp/mcp.json", "~/.cursor/mcp.json"],
    },
    AgentType.WINDSURF: {
        "Darwin": ["~/.windsurf/mcp.json", "~/Library/Application Support/Windsurf/User/globalStorage/windsurf.mcp/mcp.json"],
        "Linux": ["~/.windsurf/mcp.json"],
        "Windows": ["~/.windsurf/mcp.json"],
    },
    AgentType.CLINE: {
        "Darwin": ["~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"],
        "Linux": ["~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"],
        "Windows": ["~/AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json"],
    },
    AgentType.VSCODE_COPILOT: {
        # VS Code Copilot Agent mode global MCP config (in addition to workspace .vscode/mcp.json)
        "Darwin": ["~/Library/Application Support/Code/User/mcp.json"],
        "Linux": ["~/.config/Code/User/mcp.json"],
        "Windows": ["~/AppData/Roaming/Code/User/mcp.json"],
    },
    AgentType.CORTEX_CODE: {
        # Snowflake Cortex Code CLI (CoCo) — MCP servers, permissions, hooks, settings
        "Darwin": [
            "~/.snowflake/cortex/mcp.json",
            "~/.snowflake/cortex/settings.json",
            "~/.snowflake/cortex/permissions.json",
            "~/.snowflake/cortex/hooks.json",
        ],
        "Linux": [
            "~/.snowflake/cortex/mcp.json",
            "~/.snowflake/cortex/settings.json",
            "~/.snowflake/cortex/permissions.json",
            "~/.snowflake/cortex/hooks.json",
        ],
        "Windows": [
            "~/.snowflake/cortex/mcp.json",
            "~/.snowflake/cortex/settings.json",
            "~/.snowflake/cortex/permissions.json",
            "~/.snowflake/cortex/hooks.json",
        ],
    },
    AgentType.CODEX_CLI: {
        # OpenAI Codex CLI — TOML config with [mcp_servers.*] tables
        "Darwin": ["~/.codex/config.toml"],
        "Linux": ["~/.codex/config.toml"],
        "Windows": ["~/.codex/config.toml"],
    },
    AgentType.GEMINI_CLI: {
        # Google Gemini CLI — standard mcpServers JSON format
        "Darwin": ["~/.gemini/settings.json"],
        "Linux": ["~/.gemini/settings.json"],
        "Windows": ["~/.gemini/settings.json"],
    },
    AgentType.GOOSE: {
        # Block Goose — YAML config with extensions section
        "Darwin": ["~/.config/goose/config.yaml"],
        "Linux": ["~/.config/goose/config.yaml"],
        "Windows": ["~/AppData/Roaming/Block/goose/config/config.yaml"],
    },
    AgentType.SNOWFLAKE_CLI: {
        # Snowflake CLI (snow) — TOML connection profiles
        "Darwin": ["~/.snowflake/connections.toml", "~/.snowflake/config.toml"],
        "Linux": ["~/.snowflake/connections.toml", "~/.snowflake/config.toml"],
        "Windows": ["~/.snowflake/connections.toml", "~/.snowflake/config.toml"],
    },
    AgentType.CONTINUE: {
        # Continue.dev VS Code extension
        "Darwin": ["~/.continue/config.json", "~/Library/Application Support/Code/User/globalStorage/continue.continue/config.json"],
        "Linux": ["~/.continue/config.json", "~/.config/Code/User/globalStorage/continue.continue/config.json"],
        "Windows": ["~/.continue/config.json", "~/AppData/Roaming/Code/User/globalStorage/continue.continue/config.json"],
    },
    AgentType.ZED: {
        # Zed editor MCP config
        "Darwin": ["~/.config/zed/settings.json"],
        "Linux": ["~/.config/zed/settings.json"],
        "Windows": ["~/AppData/Roaming/Zed/settings.json"],
    },
    AgentType.OPENCLAW: {
        # OpenClaw AI agent — https://github.com/openclaw/openclaw
        # Config dir: ~/.openclaw/ on all platforms (resolveConfigDir in src/utils.ts)
        # Override via OPENCLAW_STATE_DIR env var
        "Darwin": ["~/.openclaw/openclaw.json"],
        "Linux": ["~/.openclaw/openclaw.json"],
        "Windows": ["~/.openclaw/openclaw.json"],
    },
    AgentType.ROO_CODE: {
        # Roo Code VS Code extension (formerly Roo Cline)
        "Darwin": ["~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"],
        "Linux": ["~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"],
        "Windows": ["~/AppData/Roaming/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/cline_mcp_settings.json"],
    },
    AgentType.AMAZON_Q: {
        # Amazon Q Developer VS Code extension
        "Darwin": ["~/Library/Application Support/Code/User/globalStorage/amazonwebservices.amazon-q-vscode/mcp.json"],
        "Linux": ["~/.config/Code/User/globalStorage/amazonwebservices.amazon-q-vscode/mcp.json"],
        "Windows": ["~/AppData/Roaming/Code/User/globalStorage/amazonwebservices.amazon-q-vscode/mcp.json"],
    },
    AgentType.DOCKER_MCP: {
        # Docker Desktop MCP Toolkit — discovery via registry.yaml + catalog
        "Darwin": [],
        "Linux": [],
        "Windows": [],
    },
    AgentType.JETBRAINS_AI: {
        # JetBrains AI Assistant MCP — global config across all JetBrains IDEs
        # Paths contain version-specific dirs (IntelliJIdea2025.2, PyCharm2025.2, etc.)
        # Also supports ~/.config/github-copilot/intellij/mcp.json for Copilot in JetBrains
        "Darwin": [
            "~/Library/Application Support/JetBrains/*/mcp.json",
            "~/.config/github-copilot/intellij/mcp.json",
        ],
        "Linux": [
            "~/.config/JetBrains/*/mcp.json",
            "~/.config/github-copilot/intellij/mcp.json",
        ],
        "Windows": [
            "~/AppData/Roaming/JetBrains/*/mcp.json",
            "~/.config/github-copilot/intellij/mcp.json",
        ],
    },
    AgentType.JUNIE: {
        # JetBrains Junie coding agent — clean, stable paths
        "Darwin": ["~/.junie/mcp/mcp.json"],
        "Linux": ["~/.junie/mcp/mcp.json"],
        "Windows": ["~/.junie/mcp/mcp.json"],
    },
    AgentType.COPILOT_CLI: {
        # GitHub Copilot CLI (standalone) — ~/.copilot/mcp-config.json
        "Darwin": ["~/.copilot/mcp-config.json"],
        "Linux": ["~/.copilot/mcp-config.json"],
        "Windows": ["~/.copilot/mcp-config.json"],
    },
    AgentType.TABNINE: {
        # Tabnine AI assistant — ~/.tabnine/mcp_servers.json (global)
        "Darwin": ["~/.tabnine/mcp_servers.json"],
        "Linux": ["~/.tabnine/mcp_servers.json"],
        "Windows": ["~/.tabnine/mcp_servers.json"],
    },
    AgentType.SOURCEGRAPH_CODY: {
        # Sourcegraph Cody — VS Code extension + standalone config
        "Darwin": [
            "~/Library/Application Support/Code/User/globalStorage/sourcegraph.cody-ai/mcp.json",
            "~/.cody/mcp.json",
        ],
        "Linux": [
            "~/.config/Code/User/globalStorage/sourcegraph.cody-ai/mcp.json",
            "~/.cody/mcp.json",
        ],
        "Windows": [
            "~/AppData/Roaming/Code/User/globalStorage/sourcegraph.cody-ai/mcp.json",
            "~/.cody/mcp.json",
        ],
    },
    AgentType.AIDER: {
        # Aider AI pair programming — YAML config with mcpServers
        "Darwin": ["~/.aider/mcp.json", "~/.aider.conf.yml"],
        "Linux": ["~/.aider/mcp.json", "~/.aider.conf.yml"],
        "Windows": ["~/.aider/mcp.json", "~/.aider.conf.yml"],
    },
    AgentType.REPLIT_AGENT: {
        # Replit Agent — .replit config or MCP config in workspace
        "Darwin": [],
        "Linux": [],
        "Windows": [],
    },
    AgentType.VOID_EDITOR: {
        # Void editor (open-source Cursor alternative) — uses VS Code-style config
        "Darwin": ["~/.void/mcp.json", "~/Library/Application Support/Void/User/globalStorage/void.mcp/mcp.json"],
        "Linux": ["~/.void/mcp.json", "~/.config/Void/User/globalStorage/void.mcp/mcp.json"],
        "Windows": ["~/.void/mcp.json", "~/AppData/Roaming/Void/User/globalStorage/void.mcp/mcp.json"],
    },
    AgentType.AIDE: {
        # Aide AI IDE (VS Code fork) — standard mcpServers format
        "Darwin": ["~/.aide/mcp.json", "~/Library/Application Support/Aide/User/mcp.json"],
        "Linux": ["~/.aide/mcp.json", "~/.config/Aide/User/mcp.json"],
        "Windows": ["~/.aide/mcp.json", "~/AppData/Roaming/Aide/User/mcp.json"],
    },
    AgentType.TRAE: {
        # Trae AI IDE (ByteDance) — standard mcpServers format
        "Darwin": ["~/.trae/mcp.json", "~/Library/Application Support/Trae/User/mcp.json"],
        "Linux": ["~/.trae/mcp.json", "~/.config/Trae/User/mcp.json"],
        "Windows": ["~/.trae/mcp.json", "~/AppData/Roaming/Trae/User/mcp.json"],
    },
    AgentType.PIECES: {
        # Pieces for Developers — desktop app + VS Code extension
        "Darwin": ["~/Library/Application Support/com.pieces.os/mcp.json", "~/.pieces/mcp.json"],
        "Linux": ["~/.pieces/mcp.json"],
        "Windows": ["~/AppData/Roaming/Pieces/mcp.json", "~/.pieces/mcp.json"],
    },
    AgentType.MCP_CLI: {
        # mcp-cli standalone tool — config in ~/.mcp/
        "Darwin": ["~/.mcp/config.json"],
        "Linux": ["~/.mcp/config.json"],
        "Windows": ["~/.mcp/config.json"],
    },
}

AGENT_BINARIES: dict[AgentType, str] = {
    AgentType.CLAUDE_CODE: "claude",
    AgentType.OPENCLAW: "openclaw",
    AgentType.ZED: "zed",
    AgentType.CURSOR: "cursor",
    AgentType.WINDSURF: "windsurf",
    AgentType.CORTEX_CODE: "cortex",
    AgentType.CODEX_CLI: "codex",
    AgentType.GEMINI_CLI: "gemini",
    AgentType.GOOSE: "goose",
    AgentType.SNOWFLAKE_CLI: "snow",
    AgentType.JUNIE: "junie",
    AgentType.AIDER: "aider",
    AgentType.VOID_EDITOR: "void",
    AgentType.AIDE: "aide",
    AgentType.TRAE: "trae",
    AgentType.MCP_CLI: "mcp",
}

PROJECT_CONFIG_FILES = [
    ".mcp.json",
    "mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".windsurf/mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".openclaw/openclaw.json",
    ".codex/config.toml",
    ".gemini/settings.json",
    ".junie/mcp/mcp.json",
]


def get_platform() -> str:
    return platform.system()


def expand_path(path_str: str) -> Path:
    return Path(os.path.expanduser(path_str)).resolve()


def _project_scope_path(project_dir: Optional[str]) -> Path:
    """Return the configured project scope path, preserving file inputs."""
    return Path(project_dir).expanduser().resolve() if project_dir else Path.cwd()


def _project_search_dir(project_dir: Optional[str]) -> Path:
    """Return the directory used for project-adjacent discovery."""
    path = _project_scope_path(project_dir)
    return path.parent if path.is_file() else path


def _project_config_candidates(project_dir: Optional[str]) -> list[Path]:
    """Return explicit project config files to parse."""
    path = _project_scope_path(project_dir)
    if path.is_file():
        return [path]
    return [path / config_name for config_name in PROJECT_CONFIG_FILES]


def _parse_project_config_file(config_path: Path) -> list[MCPServer]:
    """Parse one project-level MCP config file."""
    if config_path.suffix == ".toml":
        return parse_codex_config(str(config_path))
    config_data = _read_json_config_no_symlink(config_path)
    return parse_mcp_config(config_data, str(config_path))


def get_all_discovery_paths(plat: Optional[str] = None) -> list[tuple[str, str]]:
    """Return all config paths that would be checked during discovery.

    Returns a list of (client_name, path_string) tuples for the given platform.
    Used by --dry-run and ``agent-bom paths`` for full transparency.
    """
    plat = plat or get_platform()
    paths: list[tuple[str, str]] = []
    for agent_type, platforms in CONFIG_LOCATIONS.items():
        for p in platforms.get(plat, []):
            paths.append((agent_type.value, p))
    # Docker MCP Toolkit paths (not in CONFIG_LOCATIONS)
    paths.append(("Docker MCP Toolkit", "~/.docker/mcp/registry.yaml"))
    paths.append(("Docker MCP Toolkit", "~/.docker/mcp/catalogs/docker-mcp.yaml"))
    # Project-level configs (relative to CWD)
    for pf in PROJECT_CONFIG_FILES:
        paths.append(("Project config", pf))
    # Docker Compose files (relative to CWD)
    for cf in COMPOSE_FILE_NAMES:
        paths.append(("Docker Compose", cf))
    return paths


_CUSTOM_PARSERS: dict[AgentType, str] = {
    AgentType.CODEX_CLI: "toml",
    AgentType.GOOSE: "yaml",
    AgentType.SNOWFLAKE_CLI: "toml",
}


def _find_binary(binary_name: str) -> str | None:
    """Find a binary on PATH or in common install locations."""
    found = shutil.which(binary_name)
    if found:
        return found
    # Check common locations not always in PATH
    for extra_dir in ("~/.local/bin", "/usr/local/bin", "~/.cargo/bin"):
        candidate = Path(extra_dir).expanduser() / binary_name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


_INSTALL_SIGNALS: dict[AgentType, list[str]] = {
    AgentType.CORTEX_CODE: ["~/.snowflake/cortex/logs/coco.log"],
}


def detect_installed_agents(discovered_types: set[AgentType]) -> list[Agent]:
    """Detect agent CLIs on PATH that weren't found via config files.

    Returns agents with status=INSTALLED_NOT_CONFIGURED for visibility.
    """
    installed: list[Agent] = []
    for agent_type, binary_name in AGENT_BINARIES.items():
        if agent_type in discovered_types:
            continue
        found = _find_binary(binary_name)
        if not found:
            # Check install signal files (e.g. log files that prove installation)
            for signal in _INSTALL_SIGNALS.get(agent_type, []):
                if Path(signal).expanduser().exists():
                    found = signal
                    break
        if found:
            installed.append(
                Agent(
                    name=agent_type.value,
                    agent_type=agent_type,
                    config_path=f"{binary_name} ({found})",
                    status=AgentStatus.INSTALLED_NOT_CONFIGURED,
                )
            )
    return installed


COMPOSE_FILE_NAMES = [
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
]
