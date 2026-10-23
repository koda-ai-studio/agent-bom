"""Local session providers map tool calls to the shared flat span shape."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from agent_bom.canonical_ids import agent_graph_id_for, mcp_server_graph_id_for
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool
from agent_bom.otel_ingest import parse_otel_traces
from agent_bom.runtime.agent_sessions import CLAUDE_CODE_SESSIONS, CODEX_SESSIONS
from agent_bom.runtime.agent_sessions.bindings import SessionBindings
from agent_bom.runtime.agent_sessions.provider import fetch_local_session_traces
from agent_bom.runtime.normalized_trace import NORMALIZED_ATTRIBUTE, NormalizedTraceEvent
from agent_bom.trace_connectors import TraceConnectorValidationError, fetch_traces, list_trace_connectors
from tests._agent_session_fixtures import FAKE_TOKEN, make_homes

SINCE = datetime(2026, 10, 1, tzinfo=timezone.utc)


def claude_agent(*servers: MCPServer, config: str = "/home/dev/.claude.json") -> Agent:
    return Agent(name="claude-code", agent_type=AgentType.CLAUDE_CODE, config_path=config, mcp_servers=list(servers))


def github(*tools: str) -> MCPServer:
    return MCPServer(
        name="github",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-github"],
        tools=[MCPTool(name=t, description="") for t in tools],
    )


def attrs(span: dict) -> dict[str, str]:
    return {item["key"]: item["value"]["stringValue"] for item in span["attributes"]}


def event(span: dict) -> NormalizedTraceEvent:
    return NormalizedTraceEvent.from_dict(json.loads(attrs(span)[NORMALIZED_ATTRIBUTE]))


@pytest.fixture()
def home(tmp_path):
    return make_homes(tmp_path)


def test_sessions_become_agent_spans_and_mcp_calls_bind_to_configured_servers(home):
    agent = claude_agent(github("create_issue"))
    payload = fetch_local_session_traces(CLAUDE_CODE_SESSIONS, home=home, since=SINCE, bindings=SessionBindings.from_agents([agent]))

    spans = payload["spans"]
    assert len(spans) == 7 and payload["read"]["calls"] == 6
    root = spans[0]
    assert event(root).kind == "agent" and event(root).match_node_id == agent_graph_id_for(agent)
    assert all(span["parentSpanId"] == root["spanId"] and span["traceId"] == root["traceId"] for span in spans[1:])

    mcp = next(span for span in spans if attrs(span).get("mcp.server") == "github")
    mcp_event = event(mcp)
    server_id = mcp_server_graph_id_for(agent.mcp_servers[0], agent)
    assert (mcp_event.kind, mcp_event.tool_name, mcp_event.mcp_server_ref) == ("tool", "create_issue", server_id)
    assert mcp_event.match_node_id == f"tool:{server_id}:create_issue"
    assert mcp_event.source == "claude_code"
    assert attrs(mcp)["agent_bom.trace_provider"] == CLAUDE_CODE_SESSIONS


def test_builtin_tools_are_tool_spans_but_never_shadow_inventory(home):
    spans = fetch_local_session_traces(CLAUDE_CODE_SESSIONS, home=home, since=SINCE)["spans"]
    bash = next(span for span in spans if attrs(span).get("tool.name") == "Bash")
    assert attrs(bash)["agent_bom.native_type"] == "builtin_tool"
    assert event(bash).kind == "other" and event(bash).match_method == "none"
    assert attrs(bash)["agent_bom.session.action"] == "exec"


def test_unbound_or_ambiguous_server_names_are_never_exact(home):
    two = [claude_agent(github(), config="/a/.claude.json"), claude_agent(github(), config="/b/.claude.json")]
    spans = fetch_local_session_traces(CLAUDE_CODE_SESSIONS, home=home, since=SINCE, bindings=SessionBindings.from_agents(two))["spans"]
    mcp = next(span for span in spans if attrs(span).get("mcp.server") == "github")
    assert event(mcp).mcp_server_ref is None and event(mcp).match_method == "none"
    assert event(spans[0]).match_method == "none"


def test_content_is_off_by_default_and_evidence_is_redacted(home):
    spans = fetch_local_session_traces(CLAUDE_CODE_SESSIONS, home=home, since=SINCE)["spans"]
    text = json.dumps(spans)
    for secret_or_content in (FAKE_TOKEN, "PROMPT-TEXT", "ANSWER-TEXT", "WRITE-CONTENT", "ISSUE-TITLE"):
        assert secret_or_content not in text
    assert not any(key.startswith("tool.input.") for span in spans for key in attrs(span))
    push = next(span for span in spans if "push" in attrs(span).get("agent_bom.session.command", ""))
    assert "git push --force" in attrs(push)["agent_bom.session.command"]

    with_content = fetch_local_session_traces(CLAUDE_CODE_SESSIONS, home=home, since=SINCE, include_content=True)["spans"]
    mcp = next(span for span in with_content if attrs(span).get("mcp.server") == "github")
    assert attrs(mcp)["tool.input.title"] == "ISSUE-TITLE"
    assert FAKE_TOKEN not in json.dumps(with_content)


def test_codex_provider_and_otel_ingest_parse_the_same_spans(home):
    agent = Agent(name="codex", agent_type=AgentType.CODEX_CLI, config_path="/home/dev/.codex/config.toml", mcp_servers=[github()])
    payload = fetch_local_session_traces(CODEX_SESSIONS, home=home, since=SINCE, bindings=SessionBindings.from_agents([agent]))
    traces = parse_otel_traces(payload)
    assert [(t.tool_name, t.server_name) for t in traces] == [("exec", ""), ("exec", ""), ("apply_patch", ""), ("list_issues", "github")]
    mcp = next(span for span in payload["spans"] if attrs(span).get("mcp.server") == "github")
    assert event(mcp).mcp_server_ref == mcp_server_graph_id_for(agent.mcp_servers[0], agent)
    assert event(mcp).match_method == "none"  # no introspected tool node to bind


def test_local_providers_are_listed_but_never_pulled_server_side(home, monkeypatch):
    connectors = {row["name"]: row for row in list_trace_connectors()}
    for name in (CLAUDE_CODE_SESSIONS, CODEX_SESSIONS):
        assert connectors[name]["kind"] == "local_session_history"
        assert connectors[name]["auth_fields"] == []
        with pytest.raises(TraceConnectorValidationError):
            fetch_traces(name, {"home": str(home)})
