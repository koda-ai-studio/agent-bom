"""CLI and MCP ``scan`` surface the same malicious-package finding.

A server launching a cataloged malicious package (``mcp-server-todo``) produced a
critical ``MCP_BLOCKLIST`` finding from the CLI, while the MCP ``scan`` tool
extracted and scanned the package and reported only a medium advisory row, with
nothing malicious in ``counts.findings_by_category`` or ``top_findings``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.models import Agent, AgentType, MCPServer, TransportType

_TODO_ARGS = ["-y", "mcp-server-todo@1.0.0"]


def _agents(config_path: str) -> list[Agent]:
    server = MCPServer(name="todo", command="npx", args=list(_TODO_ARGS), transport=TransportType.STDIO, config_path=config_path)
    return [Agent(name="project:p", agent_type=AgentType.CUSTOM, config_path=config_path, mcp_servers=[server])]


def _malicious(findings: list[dict]) -> list[tuple[str, str, str]]:
    return sorted(
        (str(f.get("finding_type")), str(f.get("severity")), str(f.get("title")))
        for f in findings
        if f.get("finding_type") in {"MCP_BLOCKLIST", "MALICIOUS_PACKAGE"}
    )


async def _mcp_payload(tmp_path: Path, detail: str) -> dict:
    from agent_bom.mcp_blocklist import flag_blocklisted_mcp_servers
    from agent_bom.mcp_tools.scanning import scan_impl

    async def _pipeline(*_args, **_kwargs):
        agents = _agents(str(tmp_path / ".mcp.json"))
        flag_blocklisted_mcp_servers(agents)
        return agents, [], [], ["agent_discovery"]

    text = await scan_impl(
        config_path=str(tmp_path),
        offline=True,
        detail=detail,
        _run_scan_pipeline=_pipeline,
        _truncate_response=lambda s: s,
    )
    return json.loads(text)


@pytest.mark.asyncio
async def test_mcp_scan_reports_blocklisted_malicious_server(tmp_path: Path) -> None:
    full = await _mcp_payload(tmp_path, "full")
    malicious = _malicious(full["findings"])
    assert malicious == [("MCP_BLOCKLIST", "critical", "Malicious MCP todo npm package")]

    summary = await _mcp_payload(tmp_path, "summary")
    assert summary["counts"]["findings_by_type"].get("MCP_BLOCKLIST") == 1
    assert summary["counts"]["findings_by_severity"]["critical"] >= 1
    assert sum(summary["counts"]["findings_by_category"].values()) == summary["counts"]["findings"]
    assert any(row.get("finding_type") == "MCP_BLOCKLIST" and row.get("severity") == "critical" for row in summary["top_findings"])


def test_cli_and_mcp_scan_agree_on_malicious_finding(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import asyncio

    from agent_bom.cli import main

    project = tmp_path / "p"
    project.mkdir()
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"todo": {"command": "npx", "args": _TODO_ARGS}}}))
    out = tmp_path / "cli.json"
    monkeypatch.setenv("AGENT_BOM_SKIP_UPDATE_CHECK", "1")
    result = CliRunner().invoke(
        main,
        ["scan", "--no-discover", "--config-dir", str(project), "-p", str(project), "--offline", "-q", "-f", "json", "-o", str(out)],
    )
    assert out.exists(), result.output
    cli_findings = json.loads(out.read_text())["findings"]

    mcp_findings = asyncio.run(_mcp_payload(project, "full"))["findings"]

    assert _malicious(cli_findings) == _malicious(mcp_findings) != []
    cli_ids = {f["id"] for f in cli_findings if f["finding_type"] == "MCP_BLOCKLIST"}
    mcp_ids = {f["id"] for f in mcp_findings if f["finding_type"] == "MCP_BLOCKLIST"}
    assert cli_ids == mcp_ids


@pytest.mark.asyncio
async def test_mcp_pipeline_skips_package_extraction_for_blocked_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The real MCP pipeline stamps the blocklist before extraction, like the CLI."""
    from agent_bom import mcp_server_scan

    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"todo": {"command": "npx", "args": _TODO_ARGS}}}))
    scanned: list[str] = []

    async def _no_vulns(agents, options=None):
        scanned.extend(p.name for a in agents for s in a.mcp_servers for p in s.packages)
        return []

    monkeypatch.setattr("agent_bom.scanners.scan_agents", _no_vulns)
    agents, _brs, _warnings, _sources = await mcp_server_scan.run_scan_pipeline(
        safe_path=lambda value, **_kw: Path(value),
        config_path=str(tmp_path),
        offline=True,
    )
    servers = [s for a in agents for s in a.mcp_servers]
    assert servers and all(s.security_blocked for s in servers)
    assert scanned == []


@pytest.mark.asyncio
async def test_mcp_remediate_lists_blocked_server_first(tmp_path: Path) -> None:
    from agent_bom.mcp_blocklist import flag_blocklisted_mcp_servers
    from agent_bom.mcp_tools.sbom import remediate_impl

    async def _pipeline(*_args, **_kwargs):
        agents = _agents(str(tmp_path / ".mcp.json"))
        flag_blocklisted_mcp_servers(agents)
        return agents, [], [], ["agent_discovery"]

    payload = json.loads(await remediate_impl(_run_scan_pipeline=_pipeline, _truncate_response=lambda s: s))
    blocked = payload["blocked_servers"]
    assert [(row["server"], row["severity"], row["package"]) for row in blocked] == [("todo", "critical", "mcp-server-todo")]
    assert "Remove" in blocked[0]["action"]


def test_cli_remediate_lists_blocked_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cli import main

    project = tmp_path / "p"
    project.mkdir()
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"todo": {"command": "npx", "args": _TODO_ARGS}}}))
    out = tmp_path / "plan.json"
    monkeypatch.setenv("AGENT_BOM_SKIP_UPDATE_CHECK", "1")
    result = CliRunner().invoke(main, ["remediate", "-p", str(project), "--offline", "-q", "-f", "json", "-o", str(out)])
    assert out.exists(), result.output
    plan = json.loads(out.read_text())
    assert [(row["server"], row["severity"]) for row in plan["blocked_servers"]] == [("todo", "critical")]
    assert plan["summary"]["blocked_servers"] == 1
