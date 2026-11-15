"""``-f graph`` names agents with the endpoint scope the saved JSON report and a direct push use."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

from click.testing import CliRunner

from agent_bom.canonical_ids import agent_graph_id_for, mcp_server_graph_id_for
from agent_bom.cli import main
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer
from agent_bom.output.graph import build_graph_elements
from agent_bom.output.report_packing import load_report_document


def _agent() -> Agent:
    server = MCPServer(name="files", command="npx", args=["-y", "@modelcontextprotocol/server-filesystem"])
    return Agent(name="claude-desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/claude.json", mcp_servers=[server])


def _node_ids(elements: list[dict]) -> set[str]:
    return {e["data"]["id"] for e in elements if "source" not in e["data"]}


def test_endpoint_scope_names_agent_and_server_like_the_stamped_json_agent() -> None:
    agent = _agent()
    canonical = agent.canonical_id
    stamped = {
        "name": agent.name,
        "canonical_id": canonical,
        "config_path": agent.config_path,
        "agent_type": agent.agent_type.value,
        "source_id": "host-a",
    }

    scoped = _node_ids(build_graph_elements(AIBOMReport(agents=[agent]), [], endpoint_scope="host-a"))
    unscoped = _node_ids(build_graph_elements(AIBOMReport(agents=[agent]), []))

    assert agent_graph_id_for(stamped) == "agent:host-a:claude-desktop"
    assert {agent_graph_id_for(stamped), mcp_server_graph_id_for(agent.mcp_servers[0], stamped)} <= scoped
    assert agent_graph_id_for(agent) in unscoped and agent_graph_id_for(agent).startswith("agent:cfg-")
    # The scope is a graph-id input only; the agent's canonical identity is untouched.
    assert agent.source_id is None and agent.canonical_id == canonical


def test_an_agent_with_its_own_scope_keeps_it() -> None:
    agent = _agent()
    agent.source_id = "fleet-device-7"
    ids = _node_ids(build_graph_elements(AIBOMReport(agents=[agent]), [], endpoint_scope="host-a"))
    assert "agent:fleet-device-7:claude-desktop" in ids
    assert not any("host-a" in nid for nid in ids)


async def _no_advisories(_packages, **_kwargs) -> int:
    return 0


def _scan(args: list[str]) -> str:
    # Offline CI has no advisory database; an empty pinned lookup keeps the scan complete.
    with (
        mock.patch("agent_bom.db.local_analytics.record_scan_report_best_effort", lambda *_a, **_k: None),
        mock.patch("agent_bom.scanners.scan_packages", _no_advisories),
    ):
        result = CliRunner().invoke(main, ["scan", "--offline", "--no-auto-update-db", "--quiet", *args], catch_exceptions=False)
    assert result.exit_code in (0, 1), result.output
    return result.stdout


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "repo"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.19.0\n")
    return project


def test_stdout_and_graph_html_use_the_saved_json_scope(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_PUSH_SOURCE_ID", "host-a")
    project = _project(tmp_path)
    saved = tmp_path / "report.json"
    _scan(["-p", str(project), "--format", "json", "--output", str(saved)])
    report = load_report_document(json.loads(saved.read_text()))
    assert {agent.get("source_id") for agent in report["agents"]} == {"host-a"}

    stdout = json.loads(_scan(["-p", str(project), "--format", "graph", "--output", "-"]))
    stdout_ids = _node_ids(stdout["elements"])
    assert [nid for nid in stdout_ids if nid.startswith("directory:repository:host-a.cfg-")]
    assert not [nid for nid in stdout_ids if ":cfg-" in nid]

    html = tmp_path / "graph.html"
    _scan(["-p", str(project), "--format", "graph-html", "--output", str(html)])
    text = html.read_text()
    assert "directory:repository:host-a.cfg-" in text and "directory:repository:cfg-" not in text


def test_demo_graph_carries_no_host_scope(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_PUSH_SOURCE_ID", "host-a")
    ids = _node_ids(json.loads(_scan(["--demo", "--format", "graph", "--output", "-"]))["elements"])
    assert ids and not [nid for nid in ids if "host-a" in nid]
