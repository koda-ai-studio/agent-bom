"""Triton serves several versions of one model at once (``version_policy: all``).

The repository index below is the response a live Triton 2.74.0 (26.10-py3)
returned for a two-version Python-backend model on 2026-11-12. Each served
version must stay a separate record through the report and the stored graph.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.graph.builder import build_unified_graph_from_report
from tests._serving_runtime_fixtures import serving_fixture
from tests._serving_scan_helpers import scan_serving_report

LIVE_INDEX = [
    {"name": "abq_identity", "version": "1", "state": "READY"},
    {"name": "abq_identity", "version": "2", "state": "READY"},
]
LIVE_METADATA = {"name": "triton", "version": "2.74.0", "extensions": ["model_repository"]}


def _routes() -> dict:
    return {("GET", "/v2"): (200, LIVE_METADATA, 0.0), ("POST", "/v2/repository/index"): (200, LIVE_INDEX, 0.0)}


def _versions(evidence: list[dict]) -> list[str]:
    return sorted(f"{item['model']['served_name']}@{item['model']['version']}" for item in evidence)


def test_each_served_triton_version_is_its_own_agent_in_the_report(tmp_path: Path) -> None:
    with serving_fixture(_routes()) as url:
        report = scan_serving_report(tmp_path, [f"triton={url}"])
    serving = [agent for agent in report["agents"] if (agent.get("metadata") or {}).get("serving_evidence")]
    assert _versions([agent["metadata"]["serving_evidence"] for agent in serving]) == ["abq_identity@1", "abq_identity@2"]
    assert len({agent["name"] for agent in serving}) == 2


def test_each_served_triton_version_survives_into_the_graph(tmp_path: Path) -> None:
    with serving_fixture(_routes()) as url:
        report = scan_serving_report(tmp_path, [f"triton={url}"])
    graph = build_unified_graph_from_report(report, scan_id="s1", tenant_id="default")
    evidence = [node.attributes["serving_evidence"] for node in graph.nodes.values() if (node.attributes or {}).get("serving_evidence")]
    assert _versions(evidence) == ["abq_identity@1", "abq_identity@2"]
