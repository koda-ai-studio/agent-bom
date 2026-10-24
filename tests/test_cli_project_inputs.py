"""A named ``-p`` project is an explicit input: it is scanned beside every other input."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main

PROJECT_SERVERS = {"root-fs", "vs-memory", "cursor-git"}
PROJECT_PACKAGES = {("requests", "2.19.1"), ("flask", "2.0.0")}
SBOM_PACKAGES = {("lodash", "4.17.20"), ("pyyaml", "5.3")}


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    (root / ".vscode").mkdir(parents=True)
    (root / ".cursor").mkdir()
    (root / "requirements.txt").write_text("requests==2.19.1\nflask==2.0.0\n")
    (root / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"root-fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@0.5.1", "/tmp"]}}})
    )
    (root / ".vscode" / "mcp.json").write_text(
        json.dumps({"servers": {"vs-memory": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory@0.6.0"]}}})
    )
    cursor = {"mcpServers": {"cursor-git": {"command": "uvx", "args": ["mcp-server-git==0.6.2"]}}}
    (root / ".cursor" / "mcp.json").write_text(json.dumps(cursor))
    return root


@pytest.fixture
def sbom(tmp_path: Path) -> Path:
    path = tmp_path / "bom.cdx.json"
    components = [
        {"type": "library", "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20"},
        {"type": "library", "name": "pyyaml", "version": "5.3", "purl": "pkg:pypi/pyyaml@5.3"},
    ]
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, "components": components}))
    return path


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)


def _cli_scan(tmp_path: Path, *args: str) -> dict:
    out = tmp_path / "cli.json"
    result = CliRunner().invoke(main, ["scan", *args, "--offline", "--no-scan", "--no-auto-update-db", "-f", "json", "-o", str(out)])
    assert out.exists(), result.output
    return json.loads(out.read_text())


def _servers(agents: list[dict]) -> set[str]:
    return {server["name"] for agent in agents for server in agent["mcp_servers"]}


def _packages(agents: list[dict]) -> set[tuple[str, str]]:
    return {(pkg["name"], pkg["version"]) for agent in agents for server in agent["mcp_servers"] for pkg in server["packages"]}


@pytest.mark.parametrize("extra", [(), ("--no-discover",)], ids=["default", "no-discover"])
def test_project_scan_discovers_project_mcp_configs(tmp_path: Path, project: Path, extra: tuple[str, ...]) -> None:
    payload = _cli_scan(tmp_path, "-p", str(project), *extra)

    assert PROJECT_SERVERS <= _servers(payload["agents"])
    assert PROJECT_PACKAGES <= _packages(payload["agents"])


def test_project_scan_with_sbom_merges_both_inputs(tmp_path: Path, project: Path, sbom: Path) -> None:
    payload = _cli_scan(tmp_path, "-p", str(project), "--sbom", str(sbom))
    packages = _packages(payload["agents"])

    assert SBOM_PACKAGES <= packages
    assert PROJECT_PACKAGES <= packages
    assert PROJECT_SERVERS <= _servers(payload["agents"])
    assert any(str(agent["name"]).startswith("sbom:") for agent in payload["agents"])


def test_sbom_alone_still_scans_only_the_sbom(tmp_path: Path, project: Path, sbom: Path) -> None:
    payload = _cli_scan(tmp_path, "--sbom", str(sbom))

    assert _packages(payload["agents"]) == SBOM_PACKAGES
    assert not PROJECT_SERVERS & _servers(payload["agents"])


@pytest.mark.asyncio
@pytest.mark.parametrize("with_sbom", [False, True], ids=["project", "project+sbom"])
async def test_cli_and_mcp_scan_the_same_project_inputs(
    tmp_path: Path, project: Path, sbom: Path, monkeypatch: pytest.MonkeyPatch, with_sbom: bool
) -> None:
    from agent_bom.mcp_server_scan import run_scan_pipeline
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json

    async def _no_vulns(agents, **_kwargs):
        return []

    monkeypatch.setattr("agent_bom.scanners.scan_agents", _no_vulns)
    agents, _b, _w, _s = await run_scan_pipeline(
        safe_path=lambda value: Path(value),
        config_path=str(project),
        sbom_path=str(sbom) if with_sbom else None,
        no_discover=True,
        offline=True,
    )
    mcp_agents = to_json(AIBOMReport(agents=agents))["agents"]

    sbom_args = ("--sbom", str(sbom)) if with_sbom else ()
    cli_agents = _cli_scan(tmp_path, "-p", str(project), "--no-discover", *sbom_args)["agents"]

    expected_servers = PROJECT_SERVERS
    expected_packages = PROJECT_PACKAGES | (SBOM_PACKAGES if with_sbom else set())
    assert expected_servers <= _servers(mcp_agents)
    assert _servers(cli_agents) & expected_servers == _servers(mcp_agents) & expected_servers
    assert _packages(cli_agents) & (PROJECT_PACKAGES | SBOM_PACKAGES) == _packages(mcp_agents) & (PROJECT_PACKAGES | SBOM_PACKAGES)
    assert expected_packages <= _packages(cli_agents)
