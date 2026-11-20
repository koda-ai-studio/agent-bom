"""The overview package count is the estate's unique packages, the same identity the graph inventory counts."""

from __future__ import annotations

from typing import Any

from agent_bom.api.routes.overview import _estate_rollup
from agent_bom.api.server import JobStatus, ScanJob, ScanRequest
from agent_bom.graph.builder import build_unified_graph_from_report
from tests._clock_helpers import recent


def _pkg(name: str, version: str, ecosystem: str = "pypi") -> dict[str, Any]:
    return {"name": name, "version": version, "ecosystem": ecosystem}


def _result(agent: str, servers: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    return {
        "agents": [
            {
                "name": agent,
                "agent_type": "claude-desktop",
                "config_path": f"/tmp/{agent}.json",
                "mcp_servers": [{"name": name, "command": "uvx", "args": [name], "packages": pkgs} for name, pkgs in servers.items()],
            }
        ],
        "findings": [{"id": f"f-{agent}", "severity": "low", "title": "t"}],
        "scan_sources": ["agent_discovery"],
    }


def _job(job_id: str, result: dict[str, Any]) -> ScanJob:
    stamp = recent("2026-11-18T00:00:00+00:00")
    return ScanJob(
        job_id=job_id,
        tenant_id="default",
        created_at=stamp,
        completed_at=stamp,
        status=JobStatus.DONE,
        request=ScanRequest(repo_url=f"https://example.test/acme/{job_id}.git"),
        result=result,
    )


def _graph_package_ids(results: list[dict[str, Any]]) -> set[str]:
    ids: set[str] = set()
    for result in results:
        graph = build_unified_graph_from_report(result)
        ids |= {nid for nid, node in graph.nodes.items() if node.entity_type.value == "package"}
    return ids


def test_overview_counts_shared_packages_once_across_scans_and_servers() -> None:
    shared = [_pkg("requests", "2.28.0"), _pkg("PyYAML", "5.3")]
    results = [
        _result("alpha", {"a1": shared, "a2": [*shared, _pkg("jinja2", "3.0.0")]}),
        _result("beta", {"b1": [_pkg("requests", "2.28.0"), _pkg("pyyaml", "5.3")]}),
        _result("gamma", {"c1": [_pkg("axios", "1.4.0", "npm")], "c2": [_pkg("requests", "2.31.0")]}),
    ]
    estate = _estate_rollup([_job(f"scan-{i}", r) for i, r in enumerate(results)])
    graph_ids = _graph_package_ids(results)
    assert len(graph_ids) == 5
    assert estate["unique_packages"] == len(graph_ids)


def test_overview_package_count_is_zero_without_packages() -> None:
    estate = _estate_rollup([_job("empty", _result("alpha", {"a1": []}))])
    assert estate["unique_packages"] == 0
