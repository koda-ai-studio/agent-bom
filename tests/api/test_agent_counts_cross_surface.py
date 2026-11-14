"""Inventory, the graph and the Agents page count one agent and server population.

The fixture is a real offline scan of four projects: one with MCP servers only,
one mixing MCP servers with a Maven manifest and an AI SDK import, one holding
only ``pom.xml``, and one holding only an AI SDK import. The manifest and SDK
records are inventory, so none of them may add an agent or an MCP server on any
surface, and the per-row server counts must sum to the KPI total.
"""

from __future__ import annotations

import json
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
    discovery._clear_agents_response_cache_for_tests()
    summary = _settled_summary(client, {})
    agents = client.get("/v1/agents?limit=200").json()
    nodes = client.get("/v1/graph?limit=1000").json()["nodes"]
    return {
        "inventory_agents": summary["by_type"].get("agent", 0),
        "inventory_servers": summary["by_type"].get("server", 0),
        "graph_agents": sum(1 for node in nodes if node["entity_type"] == "agent"),
        "graph_servers": sum(1 for node in nodes if node["entity_type"] == "server"),
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


@pytest.mark.xfail(
    strict=True,
    reason=(
        "A framework entry (surface 'other', command 'python') is a graph server node, so Inventory and the grouped "
        "map count it under MCP servers while /v1/agents applies the MCP rule; fixing that needs the server surface "
        "in the store-native inventory and cluster reads."
    ),
)
def test_framework_project_servers_count_the_same_on_every_surface(tmp_path: Path, push_estate: TestClient) -> None:
    """A framework project's entry is not an MCP server on any surface."""
    from agent_bom.push import sanitize_results

    mcp_only, mixed = _project(tmp_path, "projA", mcp=True), _project(tmp_path, "projM", mcp=True, sdk=True)
    report = _cli_report(tmp_path, mcp_only, mixed, _framework_project(tmp_path, "projL"))
    framework = next(agent for agent in report["agents"] if agent["name"] == "project:projL")
    assert any(server["name"] == "langchain:LangChain project" for server in framework["mcp_servers"]), framework["mcp_servers"]
    _post(push_estate, sanitize_results(report))

    counts = _surface_counts(push_estate)
    assert counts["graph_agents"] == counts["inventory_agents"] == counts["agents_page"] == 3
    assert counts["graph_servers"] == counts["inventory_servers"] == counts["agents_page_servers"] == 4
