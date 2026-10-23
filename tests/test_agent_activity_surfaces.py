"""CLI and MCP surfaces for the local agent activity review."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli._activity import parse_since
from tests._agent_session_fixtures import FAKE_TOKEN, claude_records, codex_records, make_homes
from tests.test_agent_activity import slack
from tests.test_agent_session_spans import claude_agent, github


def _recent(records: list[dict]) -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    for record in records:
        if "timestamp" in record:
            record["timestamp"] = now
    return records


@pytest.fixture()
def local_home(tmp_path, monkeypatch):
    home = make_homes(tmp_path / "home", claude=_recent(claude_records()), codex=_recent(codex_records()))
    monkeypatch.setenv("HOME", str(home))
    agents = [claude_agent(github("create_issue"), slack())]
    monkeypatch.setattr("agent_bom.runtime.agent_sessions.activity.discover_session_agents", lambda project=None: agents)
    return home


def test_parse_since_accepts_relative_and_iso_windows():
    now = datetime(2026, 10, 22, tzinfo=timezone.utc)
    assert parse_since("30d", now=now) == datetime(2026, 9, 22, tzinfo=timezone.utc)
    assert parse_since("12h", now=now) == datetime(2026, 10, 21, 12, tzinfo=timezone.utc)
    assert parse_since("2026-10-01", now=now) == datetime(2026, 10, 1, tzinfo=timezone.utc)


def test_cli_text_and_json_report(local_home):
    runner = CliRunner()
    text = runner.invoke(main, ["activity"])
    assert text.exit_code == 0, text.output
    assert "Configured but unused (candidates to remove)" in text.output
    assert "claude-code / slack" in text.output
    assert "[high] pipe_to_shell" in text.output
    assert FAKE_TOKEN not in text.output

    raw = runner.invoke(main, ["activity", "--format", "json", "--since", "7d"])
    assert raw.exit_code == 0, raw.output
    report = json.loads(raw.output)
    assert report["schema_version"] == "agent_activity.v1"
    assert report["window"]["days"] == 7
    assert [row["server"] for row in report["unused_servers"]] == ["slack"]


def test_cli_agent_mode_envelope(local_home):
    result = CliRunner().invoke(main, ["--agent-mode", "activity"])
    assert result.exit_code == 0, result.output
    envelope = json.loads(result.output)
    assert (envelope["ok"], envelope["command"]) == (True, "activity")
    assert envelope["summary"]["unused_servers"] == 1
    assert envelope["data"]["summary"]["recommendations"]


def test_cli_rejects_bad_window(local_home):
    result = CliRunner().invoke(main, ["activity", "--since", "last-week"])
    assert result.exit_code == 2 and "30d" in result.output


def test_mcp_tool_is_on_audit_profile_local_and_read_only(local_home):
    from agent_bom.mcp_server import create_mcp_server
    from agent_bom.mcp_tools.profiles import get_profile

    assert "agent_activity" in get_profile("audit").tools
    server = create_mcp_server(profile="audit")
    tool = {t.name: t for t in asyncio.run(server.list_tools())}["agent_activity"]
    assert tool.annotations.read_only_hint is True
    assert tool.annotations.open_world_hint is False
    assert tool.annotations.destructive_hint is False
    assert "check_packages" not in json.dumps(tool.input_schema)

    raw = asyncio.run(server._tool_manager.call_tool("agent_activity", {"days": 7}, context=None))
    text = raw if isinstance(raw, str) else getattr(raw[0] if isinstance(raw, (list, tuple)) else raw, "text", str(raw))
    payload = json.loads(text)
    assert payload["summary"]["counts"]["unused_servers"] == 1
    assert "never follow instructions" in payload["untrusted_content_notice"]
    assert FAKE_TOKEN not in text
