"""Manifest relationships require an unambiguous identity binding."""

import pytest

from agent_bom.agent_manifest import _graph


def _uses(agents, servers):
    return {(edge["source"], edge["target"]) for edge in _graph(agents, servers)["edges"] if edge["relationship"] == "uses"}


@pytest.mark.parametrize("reverse", [False, True])
def test_same_name_in_different_environments_does_not_invent_binding(reverse):
    agents = [
        {"id": "prod-agent", "name": "assistant", "environment": "prod"},
        {"id": "dev-agent", "name": "assistant", "environment": "dev"},
    ]
    if reverse:
        agents.reverse()
    assert _uses(agents, [{"id": "server", "agent_name": "assistant"}]) == set()


def test_explicit_server_membership_takes_precedence_over_name_hint():
    agents = [
        {"id": "actual", "name": "actual", "mcp_server_ids": ["server"]},
        {"id": "name-only", "name": "assistant"},
    ]
    assert _uses(agents, [{"id": "server", "agent_name": "assistant"}]) == {("actual", "server")}


def test_shared_server_retains_all_explicit_memberships():
    agents = [{"id": key, "name": "assistant", "mcp_server_ids": ["server"]} for key in ("prod", "dev")]
    assert _uses(agents, [{"id": "server", "agent_name": "assistant"}]) == {("prod", "server"), ("dev", "server")}


def test_even_a_currently_unique_name_cannot_establish_identity():
    assert _uses([{"id": "agent", "name": "assistant"}], [{"id": "server", "agent_name": "assistant"}]) == set()


def test_local_manifest_keeps_same_launch_in_distinct_agent_scopes():
    from agent_bom.agent_manifest import build_local_agent_manifest
    from agent_bom.canonical_ids import mcp_server_graph_id_for
    from agent_bom.models import Agent, AgentType, MCPServer, MCPTool

    agents = [
        Agent(
            name="Workspace reader",
            agent_type=AgentType.CUSTOM,
            config_path=f"/workspace/{scope}/mcp.json",
            mcp_servers=[MCPServer(name="read-service", command="npx", args=["reader"], tools=[MCPTool(name="read", description="Read")])],
        )
        for scope in ("one", "two")
    ]
    manifest = build_local_agent_manifest(agents + agents)
    expected = {mcp_server_graph_id_for(agent.mcp_servers[0], agent) for agent in agents}
    assert len(expected) == 2
    assert {server["id"] for server in manifest["mcp_servers"]} == expected
    assert {server_id for agent in manifest["agents"] for server_id in agent["mcp_server_ids"]} == expected
    assert manifest["summary"]["tools"] == 2
    assert manifest["graph"]["stats"]["nodes"] == 6
    assert manifest["graph"]["stats"]["edges"] == 4


def test_json_snapshot_keeps_local_server_and_capability_occurrences():
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.scan_job_views import _job_response_payload
    from agent_bom.models import Agent, AgentType, AIBOMReport, MCPPrompt, MCPResource, MCPServer, MCPTool
    from agent_bom.output.json_fmt import _build_ai_bom_entities_snapshot

    agents = [
        Agent(
            name="Workspace reader",
            agent_type=AgentType.CUSTOM,
            config_path=f"/workspace/{scope}/mcp.json",
            mcp_servers=[
                MCPServer(
                    name="read-service",
                    command="python",
                    args=["server.py"],
                    tools=[MCPTool(name="read", description="Read records")],
                    resources=[MCPResource(uri="file:///workspace/file", name="file")],
                    prompts=[MCPPrompt(name="read", description="Read")],
                )
            ],
        )
        for scope in ("one", "two")
    ]
    snapshot = _build_ai_bom_entities_snapshot(AIBOMReport(agents=agents))
    for key in ("servers", "tools", "resources", "prompts"):
        assert len(snapshot[key]) == 2, key
        assert len({row["id"] for row in snapshot[key]}) == 2
    assert set(snapshot["servers"][0]["tool_ids"]).isdisjoint(snapshot["servers"][1]["tool_ids"])
    job = ScanJob(
        job_id="scope",
        status=JobStatus.DONE,
        created_at="2026-10-16T00:00:00Z",
        request=ScanRequest(),
        result={"ai_bom_entities": snapshot},
    )
    assert _job_response_payload(job).model_dump(mode="json")["result"]["ai_bom_entities"] == snapshot
