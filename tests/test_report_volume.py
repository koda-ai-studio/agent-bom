"""The JSON report does not carry the same large object twice."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime
from typing import Any

from agent_bom.models import Agent, AgentStatus, AgentType, AIBOMReport, BlastRadius, MCPServer, MCPTool, Package, Severity, Vulnerability
from agent_bom.output import to_json
from agent_bom.output.exposure_path import blast_radius_exposure_path


def _report() -> AIBOMReport:
    tool = MCPTool(name="deploy", description="Deploy workloads")
    servers = [
        MCPServer(name=f"mcp-{i}", command="npx", args=[f"mcp-{i}"], tools=[tool], env={"API_TOKEN": "x"}, packages=[]) for i in range(2)
    ]
    agent = Agent(
        name="assistant", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/a.json", mcp_servers=servers, status=AgentStatus.CONFIGURED
    )
    radii = []
    for index in range(6):
        pkg = Package(name=f"lib{index}", version="1.0.0", ecosystem="npm")
        vuln = Vulnerability(id=f"CVE-2024-{index:04d}", severity=Severity.HIGH, summary="test", cvss_score=8.1, cwe_ids=["CWE-94"])
        br = BlastRadius(
            package=pkg,
            vulnerability=vuln,
            affected_agents=[agent],
            affected_servers=servers,
            exposed_credentials=["API_TOKEN"],
            exposed_tools=[tool],
        )
        br.risk_score = 8.0
        radii.append(br)
    return AIBOMReport(agents=[agent], blast_radii=radii, generated_at=datetime(2026, 1, 1), tool_version="0.0.0")


def _duplicated_subtrees(document: dict[str, Any], min_bytes: int = 1500) -> dict[str, list[str]]:
    seen: dict[str, list[str]] = defaultdict(list)

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict | list):
            encoded = json.dumps(value, sort_keys=True)
            if len(encoded) >= min_bytes:
                seen[encoded].append(path)
        children = value.items() if isinstance(value, dict) else enumerate(value) if isinstance(value, list) else ()
        for key, child in children:
            walk(child, f"{path}.{key}" if isinstance(value, dict) else f"{path}[]")

    walk(document, "$")
    return {paths[0]: paths for paths in seen.values() if len(paths) > 1 and len({p.split(".")[1].split("[")[0] for p in paths}) > 1}


def test_blast_radius_rows_reference_exposure_paths_instead_of_copying_them() -> None:
    payload = to_json(_report())
    paths = payload["exposure_paths"]["paths"]
    assert len(paths) == len(payload["blast_radius"]) == 6
    for rank, row in enumerate(payload["blast_radius"], start=1):
        assert row["schema_version"] == "2"
        assert "exposure_path" not in row
        assert row["exposure_path_rank"] == rank
        assert blast_radius_exposure_path(payload, row) == paths[rank - 1]
        assert paths[rank - 1]["id"] == row["exposure_path_id"]
    duplicated = {path: where for path, where in _duplicated_subtrees(payload).items() if "blast_radius" in " ".join(where)}
    assert not duplicated, duplicated


def test_resolver_reads_schema_v1_rows_with_an_inline_path() -> None:
    inline = {"id": "blast:cve-1:npm:lib:1.0.0", "label": "lib@1.0.0 -> CVE-1"}
    assert blast_radius_exposure_path({}, {"schema_version": "1", "exposure_path": inline}) == inline


def test_resolver_uses_rank_when_ids_repeat_and_refuses_mismatches() -> None:
    first = {"id": "blast:same", "rank": 1, "affectedServers": ["a"]}
    second = {"id": "blast:same", "rank": 2, "affectedServers": ["b"]}
    report = {"exposure_paths": {"paths": [first, second]}}
    assert blast_radius_exposure_path(report, {"exposure_path_id": "blast:same", "exposure_path_rank": 2}) is second
    assert blast_radius_exposure_path(report, {"exposure_path_id": "blast:other", "exposure_path_rank": 2}) is None
    assert blast_radius_exposure_path(report, {"exposure_path_id": "blast:same", "exposure_path_rank": 9}) is None
