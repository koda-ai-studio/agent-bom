"""HTTP, MCP, Python client and CLI preserve one serialized assessment."""

import asyncio
import json
from datetime import datetime

import httpx
from click.testing import CliRunner

from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401


def test_http_mcp_client_cli_semantics_agree(api, monkeypatch):  # noqa: F811
    from agent_bom.api import graph_consequence
    from agent_bom.cli import main
    from agent_bom.client import AgentBomClient
    from agent_bom.mcp_tools.consequence import consequence_assessment_impl
    from tests.graph.test_consequence import AT, bound_graph
    from tests.test_cli_graph_paths import FakeGraphClient, _install

    client, store, headers = api
    graph = bound_graph()
    graph.scan_id = "shared-scan"
    graph.tenant_id = "tenant-a"
    graph.edges[1].evidence["session_binding"].update(scan_id=graph.scan_id, tenant_id=graph.tenant_id)
    store.save_graph(graph)

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return AT

    monkeypatch.setattr(graph_consequence, "datetime", Clock)
    request = {"root_node_id": "agent:a", "mode": "assumed_compromise", "assume_control": True}
    expected = client.post("/v1/graph/consequences", json={**request, "scan_id": graph.scan_id}, headers=headers["tenant-a"]).json()
    assert expected["counts"]["supported"] == 1
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")
    mcp = json.loads(
        asyncio.run(
            consequence_assessment_impl(request=request, scan_id=graph.scan_id, tenant_id="tenant-b", _get_graph_store=lambda: store)
        )
    )
    assert mcp == expected

    def handler(req):
        response = client.post(req.url.path, json=json.loads(req.content), headers=headers["tenant-a"])
        return httpx.Response(response.status_code, json=response.json())

    with AgentBomClient(base_url="https://example.test", bearer_token="fixture", transport=httpx.MockTransport(handler)) as sdk:
        assert sdk.consequence_assessment(request=request, scan_id=graph.scan_id) == expected
    _install(monkeypatch)
    monkeypatch.setattr(FakeGraphClient, "consequence_assessment", lambda self, **kwargs: expected, raising=False)
    result = CliRunner().invoke(
        main,
        [
            "graph-paths",
            "consequences",
            "--scan-id",
            graph.scan_id,
            "--node",
            "agent:a",
            "--mode",
            "assumed_compromise",
            "--assume-control",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == expected


def test_mcp_consequence_strict_nested_input_and_safe_errors():
    from agent_bom.mcp_server import create_mcp_server
    from agent_bom.mcp_tools.consequence import consequence_assessment_impl

    server = create_mcp_server(profile="graph")
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    assert tools["consequence_assessment"].annotations.read_only_hint
    assert tools["consequence_assessment"].input_schema["additionalProperties"] is False

    def unavailable():
        raise RuntimeError("private://secret-host/password")

    invalid = asyncio.run(
        consequence_assessment_impl(
            request={"root_node_id": "agent:a", "mode": "assumed_compromise", "assume_control": 1},
            scan_id="s",
            _get_graph_store=unavailable,
        )
    )
    assert "VALIDATION_INVALID_ARGUMENT" in invalid and "private" not in invalid
    failure = asyncio.run(
        consequence_assessment_impl(
            request={"root_node_id": "agent:a", "mode": "assumed_compromise", "assume_control": True},
            scan_id="s",
            _get_graph_store=unavailable,
        )
    )
    assert "UPSTREAM_UNAVAILABLE" in failure and "secret-host" not in failure


def test_cli_consequence_requires_explicit_assumption():
    from agent_bom.cli import main

    result = CliRunner().invoke(
        main, ["graph-paths", "consequences", "--scan-id", "s", "--node", "agent:a", "--mode", "assumed_compromise"]
    )
    assert result.exit_code != 0 and "--assume-control" in result.output
