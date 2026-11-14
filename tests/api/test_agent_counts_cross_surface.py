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
