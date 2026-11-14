"""The Agents list counts the agents the graph does, not the scan's inventory wrappers.

A scanned repository is recorded as one ``project:<name>`` agent so the report
keeps one asset shape, but the graph types it as a directory. On the quickstart
sample the Agents page said 3 while Asset inventory said 2 for the same scan.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from click.testing import CliRunner
from fastapi.testclient import TestClient

import agent_bom.api.routes.discovery as discovery
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store
from agent_bom.cli import main
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import EntityType
from agent_bom.output.report_packing import load_report_document
from tests._clock_helpers import recent


def _quickstart_report(tmp_path: Path) -> dict:
    from agent_bom.samples import write_first_run_sample

    sample = tmp_path / "sample"
    write_first_run_sample(sample)
    out = tmp_path / "report.json"
    args = [
        "scan",
        "--offline",
        "-f",
        "json",
        "-q",
        "--no-scan",
        "--exit-zero",
        "--inventory",
        str(sample / "inventory.json"),
        "-p",
        str(sample),
        "--agent-project",
        str(sample),
        "-o",
        str(out),
    ]
    CliRunner().invoke(main, args)
    assert out.is_file()
    return load_report_document(json.loads(out.read_text()))


@pytest.fixture()
def scanned_quickstart(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[dict]:
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    monkeypatch.delenv("AGENT_BOM_API_HOST_DISCOVERY_TENANT", raising=False)
    report = _quickstart_report(tmp_path)
    store = InMemoryJobStore()
    store.put(
        ScanJob(
            job_id=str(uuid.uuid4()),
            tenant_id="default",
            status=JobStatus.DONE,
            created_at=recent("2026-11-01T00:00:00Z"),
            completed_at=recent("2026-11-01T00:01:00Z"),
            request=ScanRequest(offline=True),
            result=report,
        )
    )
    set_job_store(store)
    discovery._clear_agents_response_cache_for_tests()
    yield report
    discovery._clear_agents_response_cache_for_tests()


def test_agents_list_is_the_graph_agent_population(scanned_quickstart: dict) -> None:
    report = scanned_quickstart
    assert any(str(agent.get("name", "")).startswith("project:") for agent in report["agents"]), "sample must include the project wrapper"
    graph = build_unified_graph_from_report(report, scan_id="quickstart")
    graph_agents = sorted(node.label for node in graph.nodes.values() if node.entity_type == EntityType.AGENT)

    body = TestClient(app).get("/v1/agents?limit=50").json()

    assert body["scope"] == "scanned_estate"
    assert sorted(agent["name"] for agent in body["agents"]) == graph_agents
    assert body["count"] == body["total"] == body["summary"]["agents"] == len(graph_agents)
    assert sum(body["count_by_class"].values()) == len(graph_agents)
    unpaged = TestClient(app).get("/v1/agents").json()
    assert unpaged["count"] == len(graph_agents)
