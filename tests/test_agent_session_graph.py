"""Session MCP calls become runtime-observed agent -> server -> tool graph evidence."""

from __future__ import annotations

import copy
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from agent_bom.api.native_trace_import import TraceImportScope, prepare_trace_page
from agent_bom.canonical_ids import agent_graph_id_for, mcp_server_graph_id_for
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.models import AIBOMReport
from agent_bom.otel_ingest import parse_otel_traces
from agent_bom.output.json_fmt import to_json
from agent_bom.runtime.agent_sessions import CLAUDE_CODE_SESSIONS
from agent_bom.runtime.agent_sessions.bindings import SessionBindings
from agent_bom.runtime.agent_sessions.projection import project_session_spans
from agent_bom.runtime.agent_sessions.provider import fetch_local_session_traces
from agent_bom.runtime_correlation import correlate_spans_to_attack_paths
from tests._agent_session_fixtures import make_homes
from tests.test_agent_session_spans import claude_agent, github

SINCE = datetime(2026, 10, 1, tzinfo=timezone.utc)


def _runtime_edges(graph) -> dict[tuple[str, str, str], dict]:
    return {
        (edge.source, edge.relationship.value, edge.target): edge.evidence
        for edge in graph.edges
        if edge.evidence.get("source") == "runtime-trace"
    }


@pytest.fixture()
def estate(tmp_path):
    agent = claude_agent(github("create_issue"))
    report = to_json(AIBOMReport(agents=[agent]))
    report["scan_timestamp"] = "2026-10-21T00:00:00+00:00"
    spans = fetch_local_session_traces(
        CLAUDE_CODE_SESSIONS, home=make_homes(tmp_path), since=SINCE, bindings=SessionBindings.from_agents([agent])
    )
    server_id = mcp_server_graph_id_for(agent.mcp_servers[0], agent)
    return report, spans, agent_graph_id_for(agent), server_id


def test_control_plane_importer_refuses_self_asserted_local_history(estate):
    _, spans, _, _ = estate
    scope = TraceImportScope(
        tenant_id="tenant-a", provider=CLAUDE_CODE_SESSIONS, connection_id="local", endpoint="local", project_id="local"
    )
    with pytest.raises(ValueError):
        prepare_trace_page({"spans": spans["spans"]}, scope=scope, collected_at="2026-10-20T12:00:00+00:00")


def test_session_mcp_calls_reach_runtime_correlation_as_candidates(estate):
    _, spans, _, _ = estate
    vulnerability = SimpleNamespace(id="CVE-2026-0001", severity="high", cvss_score=8.1, epss_score=0.1, is_kev=False)
    radius = SimpleNamespace(
        package=SimpleNamespace(name="server-github"),
        vulnerability=vulnerability,
        exposed_tools=[],
        affected_servers=["github"],
        affected_agents=["claude-code"],
        exposed_credentials=["GITHUB_TOKEN"],
        risk_score=7.5,
    )
    paths = correlate_spans_to_attack_paths(parse_otel_traces(spans), [radius])
    assert [(path.tool_name, path.server_name, path.match_basis) for path in paths] == [("create_issue", "github", "server")]
    assert paths[0].to_dict()["execution_proven"] is False


def test_local_projection_marks_used_servers_on_the_discovery_graph(estate):
    report, spans, agent_id, server_id = estate
    graph = build_unified_graph_from_report(copy.deepcopy(report), tenant_id="local")
    result = project_session_spans(graph, spans["spans"], window_start=SINCE, window_end=datetime(2026, 10, 22, tzinfo=timezone.utc))

    edges = _runtime_edges(graph)
    assert {(agent_id, "called", server_id), (agent_id, "invoked", f"tool:{server_id}:create_issue")} <= set(edges)
    called = edges[(agent_id, "called", server_id)]
    assert (called["tier"], called["basis"], called["trace_sources"]) == ("runtime_observed", "exact_inventory_id", ["claude_code"])
    assert result.shadow == []  # built-in shell/file calls never become shadow tools
    assert graph.get_node(server_id).attributes["runtime_trace_use"]["count"] == 1
    assert result.observed["exact_bound"] >= 2
