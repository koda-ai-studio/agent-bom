"""Installed-but-unconfigured agent clients are reported, not counted as agents.

An agent CLI found only on PATH has no MCP configuration. Counting it in
``summary.total_agents`` made a machine with two configured clients read as
five agents, and its ``config_path`` ("openclaw (/opt/.../openclaw)") was
redacted to the malformed label ``<path:openclaw)>``.
"""

from __future__ import annotations

import json
import shutil

import pytest

from agent_bom.models import Agent, AgentStatus, AgentType, AIBOMReport, MCPServer, TransportType
from agent_bom.output import to_json


def _estate() -> list[Agent]:
    configured = Agent(
        name="claude-code",
        agent_type=AgentType.CLAUDE_CODE,
        config_path="/home/u/.claude.json",
        mcp_servers=[MCPServer(name="github", command="npx", args=["-y", "x"], transport=TransportType.STDIO)],
    )
    installed = Agent(
        name="openclaw",
        agent_type=AgentType.OPENCLAW,
        config_path="/opt/homebrew/bin/openclaw",
        status=AgentStatus.INSTALLED_NOT_CONFIGURED,
    )
    return [configured, installed]


def test_json_summary_counts_only_configured_agents() -> None:
    summary = to_json(AIBOMReport(agents=_estate()))["summary"]
    assert summary["total_agents"] == 1
    assert summary["installed_unconfigured_agents"] == 1


def test_installed_agent_with_permission_findings_is_still_not_configured() -> None:
    report = AIBOMReport(agents=_estate())
    assert report.total_agents == 1
    assert to_json(report)["summary"]["installed_unconfigured_agents"] == 1


@pytest.mark.asyncio
async def test_mcp_scan_summary_counts_only_configured_agents() -> None:
    from agent_bom.mcp_tools.scanning import scan_impl

    async def _pipeline(*_args, **_kwargs):
        return _estate(), [], [], ["agent_discovery"]

    payload = json.loads(
        await scan_impl(
            config_path="/tmp/estate", offline=True, detail="summary", _run_scan_pipeline=_pipeline, _truncate_response=lambda s: s
        )
    )
    assert payload["counts"]["agents"] == 1
    assert payload["summary"]["installed_unconfigured_agents"] == 1


def test_installed_agent_config_path_is_the_detected_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.discovery import detect_installed_agents
    from agent_bom.security import sanitize_path_label

    monkeypatch.setattr(shutil, "which", lambda cmd: "/opt/homebrew/bin/openclaw" if cmd == "openclaw" else None)
    openclaw = next(a for a in detect_installed_agents(discovered_types=set()) if a.agent_type == AgentType.OPENCLAW)
    assert openclaw.config_path == "/opt/homebrew/bin/openclaw"
    assert sanitize_path_label(openclaw.config_path) == "<path:openclaw>"


def test_path_label_never_keeps_unbalanced_parenthesis() -> None:
    from agent_bom.security import sanitize_path_label

    assert sanitize_path_label("openclaw (/opt/homebrew/bin/openclaw)") == "<path:openclaw>"
