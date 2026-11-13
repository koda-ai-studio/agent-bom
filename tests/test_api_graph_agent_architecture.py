"""``/v1/graph/agent-architecture`` and the ``agent_architecture`` MCP tool: one answer, tenant-scoped, cursor contract."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from agent_bom.ai_components.framework_agents import scan_framework_agents
from agent_bom.api.read_models import STRICT_CONTRACT
from agent_bom.api.read_models.graph_agent_architecture import GraphAgentArchitectureResponse
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.mcp_tools.agent_architecture import agent_architecture_impl
from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401

_FIXTURES = Path(__file__).parent / "fixtures" / "agent_frameworks"
_ROUTE = "/v1/graph/agent-architecture"
_SCAN = "harness-scan"


def _report(*fixtures: str) -> dict:
    agents = [agent.to_dict() for name in fixtures for agent in scan_framework_agents(_FIXTURES / name)]
    return {"agents": [], "ai_inventory": {"framework_agents": agents}}


def _graph(tenant: str, *fixtures: str) -> UnifiedGraph:
    return build_unified_graph_from_report(_report(*fixtures), scan_id=_SCAN, tenant_id=tenant)


def _with_finding(graph: UnifiedGraph, agent_label: str) -> str:
    agent = next(n for n in graph.nodes_by_type(EntityType.AGENT) if n.label == agent_label and n.attributes.get("model_refs"))
    finding = UnifiedNode(id="vuln:CVE-2026-0001", entity_type=EntityType.VULNERABILITY, label="CVE-2026-0001", severity="high")
    graph.add_node(finding)
    graph.add_edge(UnifiedEdge(source=agent.id, target=finding.id, relationship=RelationshipType.VULNERABLE_TO))
    return agent.id


def _get(client, headers, **params):
    return client.get(_ROUTE, params={"scan_id": _SCAN, **params}, headers=headers)


def _harness(body: dict, label: str) -> dict:
    return next(h for h in body["harnesses"] if h["label"] == label)


def test_langgraph_supervisor_architecture_layers_edges_and_unresolved_routes(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_graph("tenant-a", "langgraph_supervisor"))
    response = _get(client, headers["tenant-a"])
    assert response.status_code == 200, response.text
    body = response.json()
    GraphAgentArchitectureResponse.model_validate(body, context={STRICT_CONTRACT: True})

    assert body["summary"]["harnesses"] == 1
    harness = _harness(body, "builder")
    assert harness["harness_kind"] == "StateGraph" and harness["framework"] == "langgraph"
    roles = {(row["label"], row["layer"]): row["role"] for layer in harness["layers"] for row in layer["agents"]}
    assert roles[("builder", 0)] == "harness"
    assert roles[("supervisor", 1)] == "orchestrator"
    assert roles[("research_builder", 2)] == "subgraph"
    assert {roles[("search", 3)], roles[("summarize", 3)], roles[("writer", 1)], roles[("review", 1)]} == {"sub_agent"}
    assert [layer["layer"] for layer in harness["layers"]] == [0, 1, 2, 3]
    labels = {row["id"]: row["label"] for layer in harness["layers"] for row in layer["agents"]}
    assert {labels[agent_id] for agent_id in harness["orchestrator_ids"]} == {"supervisor"}
    assert {labels[agent_id] for agent_id in harness["entry_agent_ids"]} == {"supervisor", "search"}

    kinds = {(labels[e["source"]], labels[e["target"]], e["kind"]) for e in harness["flow_edges"]}
    assert ("builder", "supervisor", "entry") in kinds
    assert ("supervisor", "research", "conditional") in kinds
    assert ("supervisor", "writer", "conditional") in kinds
    assert ("research", "research_builder", "subgraph") in kinds
    assert ("search", "summarize", "sequential") in kinds
    assert ("review", "writer", "handoff") in kinds
    assert ("writer", "builder", "finish") in kinds
    assert {e["provenance"] for e in harness["flow_edges"]} == {"declared"}

    assert harness["unresolved_route_count"] == 1
    [route] = harness["unresolved_routes"]
    assert labels[route["agent_id"]] == "review"
    assert route == {**route, "status": "unresolved", "reason": "no path map; targets decided at runtime", "line_number": 57}
    # No literal model in this fixture: none is invented.
    assert harness["models"] == []


def test_tool_team_and_crew_models_only_when_literal_and_overlay_findings(api):  # noqa: F811
    client, store, headers = api
    graph = _graph("tenant-a", "langgraph_tool_team", "crewai_hierarchical")
    vulnerable = _with_finding(graph, "triage_agent")
    store.save_graph(graph)
    body = _get(client, headers["tenant-a"]).json()

    assert body["summary"]["harnesses"] == 2
    team = _harness(body, "builder")
    assert team["models"] == ["openai:gpt-4o-mini"]
    workers = [row for row in team["layers"][2]["agents"]]
    assert {row["role"] for row in workers} == {"subgraph"}
    assert all(row["model_refs"] == ["openai:gpt-4o-mini"] for row in workers)
    assert {tuple(row["tools"]) for row in workers} == {("lookup_ticket",), ("draft_reply",)}
    assert all(row["credential_refs"] == ["OPENAI_API_KEY"] for row in workers)
    nodes = [row for row in team["layers"][1]["agents"]]
    assert all(row["model_refs"] == [] for row in nodes)
    flagged = next(row for row in workers if row["id"] == vulnerable)
    assert flagged["security"]["findings"] == 1 and flagged["security"]["max_finding_severity"] == "high"
    assert team["security"]["agents_with_findings"] == 1 and team["security"]["max_severity"] == "high"

    crew = _harness(body, "crew")
    assert crew["harness_kind"] == "Crew" and crew["framework"] == "crewai"
    members = {row["label"]: row for row in crew["layers"][1]["agents"]}
    assert set(members) == {"Evidence Reader", "Report Writer"}
    assert {row["role"] for row in members.values()} == {"sub_agent"}
    assert {e["kind"] for e in crew["flow_edges"]} == {"member", "peer"}
    assert crew["models"] == []
    assert "CrewAI manager_agent" in " ".join(body["coverage"]["gaps"])


def test_empty_and_no_framework_estates_return_an_honest_empty_answer(api):  # noqa: F811
    client, store, headers = api
    # tenant-b has a graph with no framework agents at all (the fixture's path graph).
    body = client.get(_ROUTE, headers=headers["tenant-b"]).json()
    assert body["harnesses"] == [] and body["summary"]["harnesses"] == 0
    assert body["pagination"]["total"] == 0 and body["pagination"]["has_more"] is False
    GraphAgentArchitectureResponse.model_validate(body, context={STRICT_CONTRACT: True})
    missing = client.get(_ROUTE, params={"scan_id": "no-such-scan"}, headers=headers["tenant-b"])
    assert missing.status_code in {200, 404}, missing.text
    if missing.status_code == 200:
        assert missing.json()["harnesses"] == []


def test_tenant_b_cannot_read_tenant_a_architecture(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_graph("tenant-a", "langgraph_supervisor"))
    leaked = _get(client, headers["tenant-b"])
    if leaked.status_code == 200:
        assert leaked.json()["harnesses"] == []
        assert leaked.json()["tenant_id"] == "tenant-b"
    else:
        assert leaked.status_code == 404, leaked.text


def test_cursor_contract_pages_bounds_stale_and_malformed(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_graph("tenant-a", "langgraph_tool_team", "crewai_hierarchical"))
    first = _get(client, headers["tenant-a"], limit=1)
    assert first.status_code == 200, first.text
    page = first.json()
    assert page["pagination"]["total"] == 2 and page["pagination"]["has_more"] is True
    cursor = page["pagination"]["next_cursor"]
    second = _get(client, headers["tenant-a"], cursor=cursor, limit=1).json()
    assert second["pagination"]["offset"] == 1 and second["pagination"]["has_more"] is False
    assert {h["harness_id"] for h in page["harnesses"]}.isdisjoint({h["harness_id"] for h in second["harnesses"]})

    assert _get(client, headers["tenant-a"], cursor=cursor, snapshot_generation="stale").status_code == 409
    assert _get(client, headers["tenant-a"], cursor="not-a-cursor").status_code == 422
    assert _get(client, headers["tenant-a"], cursor=cursor, offset=1).status_code == 400
    assert _get(client, headers["tenant-a"], offset=1).status_code == 422  # continuation without a generation
    assert _get(client, headers["tenant-a"], limit=0).status_code == 422
    assert _get(client, headers["tenant-a"], limit=51).status_code == 422
    assert _get(client, headers["tenant-a"], unknown="1").status_code in {400, 422}
    # A cursor minted for tenant-a is not valid for tenant-b's query.
    assert _get(client, headers["tenant-b"], cursor=cursor).status_code == 404  # tenant-b has no such snapshot
    assert client.get(_ROUTE, params={"cursor": cursor}, headers=headers["tenant-b"]).status_code == 422

    store.save_graph(_graph("tenant-a", "langgraph_tool_team"))
    assert _get(client, headers["tenant-a"], cursor=cursor, limit=1).status_code == 409


def _mcp(tenant: str, monkeypatch: pytest.MonkeyPatch, requested: str | None = None, **kwargs) -> dict:
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", tenant)
    return json.loads(asyncio.run(agent_architecture_impl(tenant_id=requested or tenant, scan_id=_SCAN, **kwargs)))


def test_mcp_tool_returns_the_rest_answer(api, monkeypatch):  # noqa: F811
    client, store, headers = api
    store.save_graph(_graph("tenant-a", "langgraph_tool_team", "crewai_hierarchical"))
    rest = _get(client, headers["tenant-a"], limit=1).json()
    mcp = _mcp("tenant-a", monkeypatch, limit=1)
    assert mcp["tool"] == "agent_architecture"
    shared = {key: value for key, value in mcp.items() if key not in {"tool", "source"}}
    assert shared == rest

    rest_next = _get(client, headers["tenant-a"], cursor=rest["pagination"]["next_cursor"], limit=1).json()
    mcp_next = _mcp("tenant-a", monkeypatch, cursor=mcp["pagination"]["next_cursor"], limit=1)
    assert {k: v for k, v in mcp_next.items() if k not in {"tool", "source"}} == rest_next


def test_mcp_tool_is_tenant_scoped_and_validates(api, monkeypatch):  # noqa: F811
    _, store, _ = api
    store.save_graph(_graph("tenant-a", "langgraph_supervisor"))
    other = _mcp("tenant-b", monkeypatch)
    assert other.get("harnesses", []) == []
    # A tool argument naming another tenant is not authentication: the server-bound tenant wins.
    asked = _mcp("tenant-b", monkeypatch, requested="tenant-a")
    assert asked.get("harnesses", []) == [] and asked.get("tenant_id", "tenant-b") == "tenant-b"
    assert "error" in _mcp("tenant-a", monkeypatch, limit=0)
    assert "error" in _mcp("tenant-a", monkeypatch, cursor="not-a-cursor")
    stale = _mcp("tenant-a", monkeypatch, snapshot_generation="stale")
    assert "error" in stale


def test_bounded_reads_say_the_answer_is_incomplete(api, monkeypatch):  # noqa: F811
    from agent_bom.api import graph_agent_architecture as reads

    client, store, headers = api
    store.save_graph(_graph("tenant-a", "langgraph_tool_team"))
    assert _get(client, headers["tenant-a"]).json()["coverage"]["complete"] is True
    monkeypatch.setattr(reads, "MAX_OVERLAY_EDGES", 1)
    assert _get(client, headers["tenant-a"]).json()["coverage"]["complete"] is False
    monkeypatch.setattr(reads, "MAX_OVERLAY_EDGES", 20_000)
    monkeypatch.setattr(reads, "FRAMEWORK_AGENT_CAP", 2)
    capped = _get(client, headers["tenant-a"]).json()
    assert capped["coverage"]["complete"] is False and capped["summary"]["framework_agents"] == 2
