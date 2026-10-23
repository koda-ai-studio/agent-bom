"""The MCP ``scan`` tool and the CLI must see the same project MCP servers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    root.mkdir()
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@0.5.1", "/tmp"]},
                    "remote-open": {"type": "http", "url": "https://mcp.example.invalid/mcp"},
                }
            }
        )
    )
    (root / "requirements.txt").write_text("requests==2.19.1\n")
    return root


def _mcp_servers(agents: list[dict]) -> set[str]:
    return {server["name"] for agent in agents for server in agent["mcp_servers"]}


@pytest.mark.asyncio
async def test_mcp_no_discover_scans_explicit_config_path(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.mcp_server_scan import run_scan_pipeline

    async def _no_vulns(agents, **_kwargs):
        return []

    monkeypatch.setattr("agent_bom.scanners.scan_agents", _no_vulns)
    agents, _b, _w, _s = await run_scan_pipeline(safe_path=lambda v: Path(v), config_path=str(project), no_discover=True, offline=True)
    mcp_names = {s.name for a in agents for s in a.mcp_servers if s.name in {"filesystem", "remote-open"}}
    assert mcp_names == {"filesystem", "remote-open"}
    fs = next(s for a in agents for s in a.mcp_servers if s.name == "filesystem")
    assert [(p.name, p.version) for p in fs.packages] == [("@modelcontextprotocol/server-filesystem", "0.5.1")]

    out = project.parent / "cli.json"
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--no-discover",
            "--config-dir",
            str(project),
            "-p",
            str(project),
            "--offline",
            "--no-scan",
            "--no-auto-update-db",
            "-f",
            "json",
            "-o",
            str(out),
        ],
    )
    assert out.exists(), result.output
    cli_names = _mcp_servers(json.loads(out.read_text())["agents"])
    assert {"filesystem", "remote-open"} <= cli_names
