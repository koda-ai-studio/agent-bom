"""Inventory, the graph and the Agents page count one agent and server population.

The fixture is a real offline scan of four projects: one with MCP servers only,
one mixing MCP servers with a Maven manifest and an AI SDK import, one holding
only ``pom.xml``, and one holding only an AI SDK import. The manifest and SDK
records are inventory, so none of them may add an agent or an MCP server on any
surface, and the per-row server counts must sum to the KPI total.
"""

from __future__ import annotations

import json
import shutil
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from click.testing import CliRunner
from fastapi.testclient import TestClient

import agent_bom.api.routes.discovery as discovery
from agent_bom.api import stores as api_stores
from agent_bom.api.agents_listing import agent_metrics
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.cli import main
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.node_roles import node_role
from agent_bom.graph.types import EntityType
from agent_bom.output.report_packing import load_report_document
from tests._clock_helpers import recent
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

TENANT = "agent-counts-cross-surface"
_MCP = {
    "mcpServers": {
        "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.1.14", "/tmp"]},
        "gh": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github@2025.1.1"]},
    }
}
_POM = (
    '<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
    "<groupId>x</groupId><artifactId>y</artifactId><version>1</version><dependencies><dependency>"
    "<groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version>"
    "</dependency></dependencies></project>"
)


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def _project(root: Path, name: str, *, mcp: bool = False, pom: bool = False, sdk: bool = False) -> Path:
    path = root / name
    path.mkdir()
    if mcp:
        (path / ".mcp.json").write_text(json.dumps(_MCP), encoding="utf-8")
    if pom:
        (path / "pom.xml").write_text(_POM, encoding="utf-8")
    if sdk:
        (path / "requirements.txt").write_text("anthropic==0.40.0\n", encoding="utf-8")
        (path / "agent.py").write_text("import anthropic\n", encoding="utf-8")
    return path


def _estate_report(tmp_path: Path) -> dict:
    projects = [
        _project(tmp_path, "projA", mcp=True),
        _project(tmp_path, "projM", mcp=True, pom=True, sdk=True),
        _project(tmp_path, "projB", pom=True),
        _project(tmp_path, "projC", sdk=True),
    ]
    out = tmp_path / "report.json"
    args = ["scan", "--offline", "--no-scan", "--no-discover", "--exit-zero", "-q", "-f", "json", "-o", str(out)]
    for project in projects:
        args += ["-p", str(project)]
    result = CliRunner().invoke(main, args)
    assert out.is_file(), result.output
    return load_report_document(json.loads(out.read_text()))


@pytest.fixture()
def scanned_estate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    monkeypatch.delenv("AGENT_BOM_API_HOST_DISCOVERY_TENANT", raising=False)
    report = _estate_report(tmp_path)
    job_id = str(uuid.uuid4())
    report["scan_id"] = job_id
    completed_at = recent("2026-11-01T00:01:00Z")
    jobs = InMemoryJobStore()
    jobs.put(
        ScanJob(
            job_id=job_id,
            tenant_id=TENANT,
            status=JobStatus.DONE,
            created_at=recent("2026-11-01T00:00:00Z"),
            completed_at=completed_at,
            request=ScanRequest(offline=True),
            result=report,
        )
    )
    graphs = SQLiteGraphStore(tmp_path / "graph.db")
    graph = build_unified_graph_from_report(report, scan_id=job_id, tenant_id=TENANT)
    graph.created_at = completed_at
    graphs.save_graph(graph)
    monkeypatch.setattr(api_stores, "_store", jobs)
    monkeypatch.setattr(api_stores, "_graph_store", graphs)
    discovery._clear_agents_response_cache_for_tests()
    yield report
    discovery._clear_agents_response_cache_for_tests()


def _settled_summary(client: TestClient, headers: dict) -> dict:
    deadline = time.monotonic() + 30
    while True:
        graph = client.get("/v1/graph?limit=1", headers=headers)
        if graph.status_code == 200 and graph.json().get("collection_coverage", {}).get("freshness") != "previous_generation":
            summary = client.get("/v1/inventory/summary", headers=headers).json()
            if summary["by_type"]:
                return summary
        assert time.monotonic() < deadline, graph.text
        time.sleep(0.1)


def test_inventory_graph_and_agents_page_agree(scanned_estate: dict) -> None:
    names = {str(agent.get("name")) for agent in scanned_estate["agents"]}
    assert {"project:projA", "project:projM", "project:projB", "project:projC"} <= names, names

    client = TestClient(app)
    headers = proxy_headers(role="analyst", tenant=TENANT)
    summary = _settled_summary(client, headers)
    agents = client.get("/v1/agents?limit=50", headers=headers).json()
    posture = client.get("/v1/posture/counts", headers=headers).json()["agents"]
    graph = build_unified_graph_from_report(scanned_estate, scan_id="cross-surface")
    graph_agents = sorted(node.label for node in graph.nodes.values() if node.entity_type == EntityType.AGENT)
    graph_servers = sum(1 for node in graph.nodes.values() if node.entity_type == EntityType.SERVER)

    # Agents: the pom-only and SDK-only projects are inventory on every surface.
    assert graph_agents == ["project:projA", "project:projM"]
    assert sorted(agent["name"] for agent in agents["agents"]) == graph_agents
    assert summary["by_type"].get("agent") == agents["count"] == agents["summary"]["agents"] == posture["total"] == 2

    # MCP servers: one rule for the KPI, each row, and the graph.
    row_servers = [agent_metrics(agent)["servers"] for agent in agents["agents"]]
    assert row_servers == [2, 2]
    assert summary["by_type"].get("server") == graph_servers == agents["summary"]["mcp_servers"] == sum(row_servers) == 4


def _cli_report(tmp_path: Path, *projects: Path) -> dict:
    out = tmp_path / f"report-{uuid.uuid4().hex}.json"
    args = ["scan", "--offline", "--no-scan", "--no-discover", "--exit-zero", "-q", "-f", "json", "-o", str(out)]
    for project in projects:
        args += ["-p", str(project)]
    result = CliRunner().invoke(main, args)
    assert out.is_file(), result.output
    return json.loads(out.read_text())


def _framework_project(root: Path, name: str) -> Path:
    path = root / name
    path.mkdir()
    (path / "requirements.txt").write_text("langchain==0.2.0\n", encoding="utf-8")
    return path


@pytest.fixture()
def push_estate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    monkeypatch.delenv("AGENT_BOM_API_HOST_DISCOVERY_TENANT", raising=False)
    monkeypatch.setenv("AGENT_BOM_PUSH_SOURCE_ID", "host-under-test")
    monkeypatch.setattr(api_stores, "_store", InMemoryJobStore())
    monkeypatch.setattr(api_stores, "_graph_store", SQLiteGraphStore(tmp_path / "push-graph.db"))
    discovery._clear_agents_response_cache_for_tests()
    with TestClient(app) as client:
        client.headers.update(proxy_headers(role="analyst", tenant=TENANT))
        yield client
    discovery._clear_agents_response_cache_for_tests()


def _surface_counts(client: TestClient) -> dict[str, int]:
    """Headline agent and MCP server counts on each surface, plus the other labelled groups."""
    discovery._clear_agents_response_cache_for_tests()
    summary = _settled_summary(client, {})
    agents = client.get("/v1/agents?limit=200").json()
    nodes = client.get("/v1/graph?limit=1000").json()["nodes"]
    clusters = {c["cluster_key"]: c["member_count"] for c in client.get("/v1/graph/cluster-map").json()["clusters"]}
    roles = summary["by_role"]

    def graph_count(entity_type: str, role: str) -> int:
        typed = [node for node in nodes if node["entity_type"] == entity_type]
        return sum(1 for node in typed if node_role(entity_type, node.get("dimensions") or {}) == role)

    return {
        "inventory_agents": roles.get("agent", 0),
        "inventory_servers": roles.get("mcp_server", 0),
        "inventory_framework_agents": roles.get("framework_agent", 0),
        "inventory_other_servers": roles.get("other_server", 0),
        "inventory_agent_nodes": summary["by_type"].get("agent", 0),
        "inventory_server_nodes": summary["by_type"].get("server", 0),
        "graph_agents": graph_count("agent", "agent"),
        "graph_servers": graph_count("server", "mcp_server"),
        "graph_framework_agents": graph_count("agent", "framework_agent"),
        "graph_other_servers": graph_count("server", "other_server"),
        "map_agents": clusters.get("type:agent", 0),
        "map_servers": clusters.get("type:server", 0),
        "map_framework_agents": clusters.get("agent:framework", 0),
        "map_other_servers": clusters.get("server:other", 0),
        "agents_page": agents["count"],
        "agents_page_servers": agents["summary"]["mcp_servers"],
    }


def _post(client: TestClient, report: dict) -> None:
    response = client.post("/v1/results/push", json=report)
    assert response.status_code == 201, response.text


def test_saved_report_push_lands_on_the_direct_push_agent_node(tmp_path: Path, push_estate: TestClient) -> None:
    """``--push-url`` and ``-o -f json`` + POST from one host describe one agent, not two."""
    from agent_bom.push import sanitize_results

    proj_a = _project(tmp_path, "projA", mcp=True)
    proj_b = _project(tmp_path, "projB", mcp=True)
    _post(push_estate, sanitize_results(_cli_report(tmp_path, proj_a, proj_b)))
    before = _surface_counts(push_estate)

    partial = _cli_report(tmp_path, proj_a)
    partial["scan_run"] = {**(partial.get("scan_run") or {}), "outcome": "partial"}
    _post(push_estate, partial)
    after = _surface_counts(push_estate)

    assert after == before
    assert after["graph_agents"] == after["inventory_agents"] == after["agents_page"] == 2
    assert after["graph_servers"] == after["inventory_servers"] == after["agents_page_servers"] == 4


def test_framework_project_servers_count_the_same_on_every_surface(tmp_path: Path, push_estate: TestClient) -> None:
    """A framework project's entry is not an MCP server on any surface."""
    from agent_bom.push import sanitize_results

    mcp_only, mixed = _project(tmp_path, "projA", mcp=True), _project(tmp_path, "projM", mcp=True, sdk=True)
    report = _cli_report(tmp_path, mcp_only, mixed, _framework_project(tmp_path, "projL"))
    framework = next(agent for agent in report["agents"] if agent["name"] == "project:projL")
    assert any(server["name"] == "langchain:LangChain project" for server in framework["mcp_servers"]), framework["mcp_servers"]
    _post(push_estate, sanitize_results(report))

    counts = _surface_counts(push_estate)
    assert counts["graph_agents"] == counts["inventory_agents"] == counts["map_agents"] == counts["agents_page"] == 3
    assert counts["graph_servers"] == counts["inventory_servers"] == counts["map_servers"] == counts["agents_page_servers"] == 4
    # The framework entry stays visible on every surface, labelled as what it is.
    assert counts["graph_other_servers"] == counts["inventory_other_servers"] == counts["map_other_servers"] == 1
    assert counts["inventory_server_nodes"] == 5


def test_framework_agent_definition_counts_the_same_on_every_surface(tmp_path: Path, push_estate: TestClient) -> None:
    """A framework agent defined in project code is its own labelled group, not an extra AI agent."""
    from agent_bom.push import sanitize_results

    framework = _framework_project(tmp_path, "projL")
    (framework / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\nagent = AgentExecutor(agent=None, tools=[])\n", encoding="utf-8"
    )
    report = _cli_report(tmp_path, _project(tmp_path, "projA", mcp=True), _project(tmp_path, "projM", mcp=True, sdk=True), framework)
    _post(push_estate, sanitize_results(report))

    counts = _surface_counts(push_estate)
    assert counts["graph_agents"] == counts["inventory_agents"] == counts["map_agents"] == counts["agents_page"] == 3
    assert counts["graph_servers"] == counts["inventory_servers"] == counts["map_servers"] == counts["agents_page_servers"] == 4
    assert counts["graph_framework_agents"] == counts["inventory_framework_agents"] == counts["map_framework_agents"] == 1
    assert counts["graph_other_servers"] == counts["inventory_other_servers"] == counts["map_other_servers"] == 1
    assert counts["inventory_agent_nodes"] == 4 and counts["inventory_server_nodes"] == 5

    # Each inventory row names its role, so a row is never labelled as something it is not.
    rows = push_estate.get("/v1/inventory/assets?type=agent,server&limit=50").json()["assets"]
    roles = sorted((row["type"], row["role"]) for row in rows)
    assert roles.count(("agent", "framework_agent")) == 1 and roles.count(("agent", "agent")) == 3
    assert roles.count(("server", "other_server")) == 1 and roles.count(("server", "mcp_server")) == 4


def _eval_fixture_project(root: Path, fixture: str) -> Path:
    path = root / fixture
    shutil.copytree(Path(__file__).resolve().parents[1] / "fixtures" / "eval_suites" / fixture, path)
    for staged in path.rglob("*.fixture"):
        staged.rename(staged.with_suffix(""))
    return path


def test_same_named_agents_from_two_projects_keep_their_own_graph_nodes(tmp_path: Path, push_estate: TestClient) -> None:
    """Two projects pushed from one host never fold same-named agents into one node."""
    from agent_bom.push import sanitize_results

    uncovered = _eval_fixture_project(tmp_path, "uncovered_agent")
    covered = _eval_fixture_project(tmp_path, "deepeval_safety")
    for project in (uncovered, covered):
        _post(push_estate, sanitize_results(_cli_report(tmp_path, project)))

    discovery._clear_agents_response_cache_for_tests()
    _settled_summary(push_estate, {})
    listed = push_estate.get("/v1/agents?limit=50").json()["agents"]
    graph = push_estate.get("/v1/graph?limit=1000").json()
    agent_nodes = sorted(node["id"] for node in graph["nodes"] if node["entity_type"] == "agent")
    canonical = {agent.get("canonical_id") or agent.get("stable_id") for agent in listed}
    assert len(canonical) == len(listed) == 2, listed
    assert len(agent_nodes) == 2, agent_nodes

    evaluated = {edge["target"] for edge in graph["edges"] if edge["relationship"] == "evaluates"}
    assert len(evaluated) == 1, evaluated


def test_mixed_estate_counts_one_agent_population_on_every_surface(tmp_path: Path, push_estate: TestClient) -> None:
    """MCP, pom-only, SDK-only, framework and eval projects: every surface counts the same agents."""
    from agent_bom.push import sanitize_results

    framework = _framework_project(tmp_path, "projL")
    (framework / "agent.py").write_text(
        "from langchain.agents import AgentExecutor\nagent = AgentExecutor(agent=None, tools=[])\n", encoding="utf-8"
    )
    projects = [
        _project(tmp_path, "projA", mcp=True),
        _project(tmp_path, "projM", mcp=True, pom=True, sdk=True),
        _project(tmp_path, "pom", pom=True),
        _project(tmp_path, "projC", sdk=True),
        framework,
        _eval_fixture_project(tmp_path, "uncovered_agent"),
    ]
    _post(push_estate, sanitize_results(_cli_report(tmp_path, *projects)))

    counts = _surface_counts(push_estate)
    inventory = push_estate.get("/v1/inventory?limit=200").json()
    agents_page = {agent["name"] for agent in push_estate.get("/v1/agents?limit=200").json()["agents"]}
    assert "project:pom" not in agents_page
    assert sorted(agent["name"] for agent in inventory["agents"]) == sorted(agents_page)
    assert inventory["total"] == counts["agents_page"]
    assert counts["graph_agents"] == counts["inventory_agents"] == counts["map_agents"] == counts["agents_page"]
    assert counts["graph_servers"] == counts["inventory_servers"] == counts["map_servers"] == counts["agents_page_servers"]
    assert counts["graph_framework_agents"] == counts["inventory_framework_agents"] == counts["map_framework_agents"]


def test_shared_remote_servers_count_unique_servers_on_every_surface(push_estate: TestClient) -> None:
    """The scale estate's shape: agents share remote endpoints, so configurations outnumber servers."""
    from scripts.generate_graph_benchmark_estate import generate_estate

    report, _ = generate_estate(agents=400, seed=2145, vulnerable_package_rate=0.0)
    configurations = sum(len(agent["mcp_servers"]) for agent in report["agents"])
    _post(push_estate, report)

    counts = _surface_counts(push_estate)
    summary = push_estate.get("/v1/agents?limit=1").json()["summary"]
    # The first graph page is capped, so count the projection the store persisted.
    graph = build_unified_graph_from_report(report, scan_id="shared-servers")
    graph_servers = sum(1 for node in graph.nodes.values() if node_role(node.entity_type, node.dimensions.to_dict()) == "mcp_server")
    assert counts["agents_page"] == counts["inventory_agents"] == counts["map_agents"] == 400
    assert summary["mcp_server_configurations"] == configurations
    assert summary["mcp_servers"] < configurations
    assert summary["mcp_servers"] == graph_servers == counts["inventory_servers"] == counts["map_servers"]
