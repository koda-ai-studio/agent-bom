"""Continue project-level MCP configs are discovered in every documented shape.

Continue documents ``mcpServers`` in ``config.yaml`` and standalone
``.continue/mcpServers/*.yaml`` blocks; the deprecated ``config.json`` nests
servers under ``experimental.modelContextProtocolServers[].transport``.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.discovery import PROJECT_CONFIG_FILES, discover_project_configs
from agent_bom.discovery.config_parsers import parse_mcp_config
from agent_bom.models import TransportType

LEGACY_JSON = {
    "models": [{"title": "Local", "provider": "ollama", "model": "llama3:8b"}],
    "experimental": {
        "modelContextProtocolServers": [
            {"transport": {"type": "stdio", "command": "npx", "args": ["-y", "mcp-remote@0.1.15", "https://remote.example.com/sse"]}},
            {"name": "docs", "transport": {"type": "sse", "url": "https://mcp.example.com/sse"}},
        ]
    },
}


def test_continue_paths_are_project_candidates() -> None:
    assert ".continue/config.json" in PROJECT_CONFIG_FILES
    assert ".continue/config.yaml" in PROJECT_CONFIG_FILES


def test_legacy_experimental_transport_shape_is_parsed() -> None:
    servers = parse_mcp_config(LEGACY_JSON, "~/.continue/config.json")
    assert [(s.name, s.command, s.args, s.transport, s.url) for s in servers] == [
        ("continue-mcp-1", "npx", ["-y", "mcp-remote@0.1.15", "https://remote.example.com/sse"], TransportType.STDIO, None),
        ("docs", "", [], TransportType.SSE, "https://mcp.example.com/sse"),
    ]


def test_project_continue_config_json_is_discovered(tmp_path: Path) -> None:
    (tmp_path / ".continue").mkdir()
    (tmp_path / ".continue" / "config.json").write_text(json.dumps(LEGACY_JSON))

    agents = discover_project_configs(str(tmp_path))

    assert len(agents) == 1
    assert agents[0].config_path.endswith(".continue/config.json")
    assert [s.command for s in agents[0].mcp_servers][0] == "npx"
    assert "mcp-remote@0.1.15" in agents[0].mcp_servers[0].args


def test_project_continue_config_yaml_and_block_files_are_discovered(tmp_path: Path) -> None:
    (tmp_path / ".continue" / "mcpServers").mkdir(parents=True)
    (tmp_path / ".continue" / "config.yaml").write_text(
        "name: Local Assistant\nversion: 1.0.0\nschema: v1\nmcpServers:\n"
        "  - name: sqlite\n    command: uvx\n    args:\n      - mcp-server-sqlite\n"
        "  - name: remote\n    type: streamable-http\n    url: https://mcp.example.com/mcp\n"
    )
    (tmp_path / ".continue" / "mcpServers" / "playwright-mcp.yaml").write_text(
        "name: Playwright mcpServer\nversion: 0.0.1\nschema: v1\nmcpServers:\n"
        '  - name: Browser search\n    command: npx\n    args:\n      - "@playwright/mcp@latest"\n'
    )
    fs_server = {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}}}
    (tmp_path / ".continue" / "mcpServers" / "mcp.json").write_text(json.dumps(fs_server))

    agents = discover_project_configs(str(tmp_path))
    by_path = {Path(a.config_path).name: a for a in agents}

    assert set(by_path) == {"config.yaml", "playwright-mcp.yaml", "mcp.json"}
    yaml_servers = {s.name: s for s in by_path["config.yaml"].mcp_servers}
    assert yaml_servers["sqlite"].command == "uvx"
    assert yaml_servers["remote"].transport == TransportType.STREAMABLE_HTTP
    assert yaml_servers["remote"].url == "https://mcp.example.com/mcp"
    assert [s.args for s in by_path["playwright-mcp.yaml"].mcp_servers] == [["@playwright/mcp@latest"]]
    assert [s.name for s in by_path["mcp.json"].mcp_servers] == ["fs"]


def test_malformed_continue_yaml_does_not_abort_discovery(tmp_path: Path) -> None:
    (tmp_path / ".continue").mkdir()
    (tmp_path / ".continue" / "config.yaml").write_text("mcpServers: [unterminated\n")
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"ok": {"command": "npx", "args": ["x"]}}}))

    agents = discover_project_configs(str(tmp_path))

    assert [Path(a.config_path).name for a in agents] == [".mcp.json"]
