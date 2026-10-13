"""Snapshot-materialized attack paths: derive once at persist, read many times."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.path_derivation import _derived_attack_paths
from agent_bom.graph.snapshot_paths import (
    DERIVATION_VERSION,
    PATHS_ANALYSIS_KEY,
    resolve_snapshot_attack_paths,
    stored_paths_current,
)


def shared_server_estate(*, agents: int, group_size: int, scan_id: str = "synthetic-shared") -> dict[str, Any]:
    """Agents in groups that share one vulnerable, credentialed MCP server."""
    report_agents: list[dict[str, Any]] = []
    blast_radius: list[dict[str, Any]] = []
    for group in range(max(1, agents // group_size)):
        server = f"shared-mcp-{group:04d}"
        members = [f"agent-{group:04d}-{idx:03d}" for idx in range(group_size)]
        packages = [{"name": f"pkg-{group}-{idx}", "version": "1.0.0", "ecosystem": "pypi", "is_direct": True} for idx in range(3)]
        for idx, package in enumerate(packages[:2]):
            blast_radius.append(
                {
                    "vulnerability_id": f"CVE-2026-{group:04d}{idx}",
                    "severity": ("critical", "high")[idx],
                    "package": package["name"],
                    "package_name": package["name"],
                    "package_version": package["version"],
                    "fixed_version": "1.0.1",
                    "affected_agents": members,
                    "affected_servers": [{"name": server}],
                    "exposed_tools": [f"{server}-tool-0"],
                    "exposed_credentials": [f"SHARED_{group}_TOKEN"],
                }
            )
        for name in members:
            report_agents.append(
                {
                    "name": name,
                    "type": "claude-desktop",
                    "status": "configured",
                    "mcp_servers": [
                        {
                            "name": server,
                            "transport": "stdio",
                            "credential_env_vars": [f"SHARED_{group}_TOKEN"],
                            "packages": packages,
                            "tools": [{"name": f"{server}-tool-{t}"} for t in range(2)],
                        }
                    ],
                }
            )
    return {"scan_id": scan_id, "generated_at": "2026-10-13T00:00:00Z", "agents": report_agents, "blast_radius": blast_radius}


def _demo_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """The ``scan --demo --offline`` document pinned by the scan characterization goldens."""
    from click.testing import CliRunner

    from agent_bom.cli import main

    monkeypatch.setattr("agent_bom.db.local_analytics.record_scan_report_best_effort", lambda *_a, **_k: None)
    out = tmp_path / "demo.json"
    result = CliRunner().invoke(
        main,
        ["scan", "--offline", "--no-auto-update-db", "--quiet", "--demo", "--format", "json", "--exit-zero", "--output", str(out)],
        catch_exceptions=False,
    )
    assert out.exists(), result.output
    return {**json.loads(out.read_text()), "scan_id": "demo-characterization"}


def _quickstart_offline_report(tmp_path: Path) -> dict[str, Any]:
    from click.testing import CliRunner

    from agent_bom.cli import main
    from agent_bom.samples import write_first_run_sample

    sample = tmp_path / "sample"
    write_first_run_sample(sample)
    report_path = sample / "agent-bom-report.json"
    result = CliRunner().invoke(
        main,
        [
            "agents",
            "--inventory",
            str(sample / "inventory.json"),
            "-p",
            str(sample),
            "--offline",
            "--no-scan",
            "--exit-zero",
            "-f",
            "json",
            "-o",
            str(report_path),
            "--scan-prompts",
            "--agent-project",
            str(sample),
            "--ai-inventory",
            str(sample),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    return {**json.loads(report_path.read_text()), "scan_id": "quickstart-offline"}


def _dicts(paths: list[AttackPath]) -> list[dict[str, Any]]:
    return [path.to_dict() for path in paths]


@pytest.fixture()
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SQLiteGraphStore:
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "graph.db"))
    return SQLiteGraphStore(tmp_path / "graph.db")


def _assert_equivalent(store: SQLiteGraphStore, report: dict[str, Any], *, tenant: str = "tenant-a") -> list[AttackPath]:
    scan_id = report["scan_id"]
    graph = build_unified_graph_from_report(report, scan_id=scan_id, tenant_id=tenant)
    store.save_graph(graph)

    loaded = store.load_graph(tenant_id=tenant, scan_id=scan_id)
    assert stored_paths_current(loaded.analysis_status)
    stored = store.snapshot_attack_paths(tenant_id=tenant, scan_id=scan_id)
    assert stored is not None
    derived = _derived_attack_paths(store.load_graph(tenant_id=tenant, scan_id=scan_id))
    assert _dicts(stored.paths) == _dicts(derived)
    assert loaded.analysis_status[PATHS_ANALYSIS_KEY].observed == {"version": DERIVATION_VERSION, "count": len(derived)}
    return stored.paths


def test_stored_paths_equal_read_time_derivation_for_demo_fixture(
    store: SQLiteGraphStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = _assert_equivalent(store, _demo_report(tmp_path, monkeypatch))
    assert paths, "demo characterization estate must produce attack paths"


def test_stored_paths_equal_read_time_derivation_for_synthetic_estate(store: SQLiteGraphStore) -> None:
    paths = _assert_equivalent(store, shared_server_estate(agents=40, group_size=10))
    assert len({path.source for path in paths}) >= 40


def test_stored_paths_equal_read_time_derivation_for_quickstart_sample(store: SQLiteGraphStore, tmp_path: Path) -> None:
    _assert_equivalent(store, _quickstart_offline_report(tmp_path))


def _node(node_id: str, entity_type: EntityType, **attrs: Any) -> UnifiedNode:
    return UnifiedNode(id=node_id, entity_type=entity_type, label=node_id, attributes=attrs)


def _two_route_graph(tenant: str, scan_id: str = "two-routes") -> UnifiedGraph:
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant)
    for node in (
        _node("agent:a", EntityType.AGENT),
        _node("server:x", EntityType.SERVER),
        _node("server:y", EntityType.SERVER),
        _node("data:crown", EntityType.DATA_STORE),
    ):
        graph.add_node(node)
    for source, target in (("agent:a", "server:x"), ("agent:a", "server:y")):
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=RelationshipType.USES))
    for source in ("server:x", "server:y"):
        graph.add_edge(UnifiedEdge(source=source, target="data:crown", relationship=RelationshipType.CAN_ACCESS))
    for via, risk in (("server:x", 80.0), ("server:y", 60.0)):
        graph.attack_paths.append(
            AttackPath(
                source="agent:a",
                target="data:crown",
                hops=["agent:a", via, "data:crown"],
                edges=["uses", "can_access"],
                composite_risk=risk,
                summary=f"via {via}",
                reachability="likely",
            )
        )
    return graph


def test_two_distinct_paths_between_same_endpoints_both_persist(store: SQLiteGraphStore) -> None:
    store.save_graph(_two_route_graph("tenant-a"))

    stored = store.snapshot_attack_paths(tenant_id="tenant-a", scan_id="two-routes")
    assert stored is not None
    routes = [path.hops for path in stored.paths if path.source == "agent:a" and path.target == "data:crown"]
    assert ["agent:a", "server:x", "data:crown"] in routes
    assert ["agent:a", "server:y", "data:crown"] in routes


def test_materialization_does_not_mutate_fusion_rows(store: SQLiteGraphStore) -> None:
    graph = _two_route_graph("tenant-a")
    graph.attack_paths[0].reachability = "unknown"
    before = _dicts(graph.attack_paths)
    store.save_graph(graph)
    assert _dicts(graph.attack_paths) == before


def test_cross_tenant_isolation_of_stored_paths(store: SQLiteGraphStore) -> None:
    store.save_graph(_two_route_graph("tenant-a", scan_id="shared-scan"))
    other = UnifiedGraph(scan_id="shared-scan", tenant_id="tenant-b")
    other.add_node(_node("agent:b", EntityType.AGENT))
    store.save_graph(other)

    a_paths = store.snapshot_attack_paths(tenant_id="tenant-a", scan_id="shared-scan")
    b_paths = store.snapshot_attack_paths(tenant_id="tenant-b", scan_id="shared-scan")
    assert a_paths is not None and b_paths is not None
    assert {path.source for path in a_paths.paths} == {"agent:a"}
    assert b_paths.paths == []
    assert store.snapshot_attack_paths(tenant_id="tenant-c", scan_id="shared-scan") is None
    store.delete_snapshot(tenant_id="tenant-a", scan_id="shared-scan")
    assert store.snapshot_attack_paths(tenant_id="tenant-a", scan_id="shared-scan") is None
    assert store.snapshot_attack_paths(tenant_id="tenant-b", scan_id="shared-scan") is not None


def test_source_filter_returns_only_requested_sources_in_rank_order(store: SQLiteGraphStore) -> None:
    store.save_graph(build_unified_graph_from_report(shared_server_estate(agents=20, group_size=10), scan_id="s", tenant_id="t"))
    full = store.snapshot_attack_paths(tenant_id="t", scan_id="s")
    assert full is not None
    wanted = {full.paths[0].source, full.paths[-1].source}
    subset = store.snapshot_attack_paths(tenant_id="t", scan_id="s", source_ids=wanted)
    assert subset is not None
    assert _dicts(subset.paths) == _dicts([path for path in full.paths if path.source in wanted])


def test_version_mismatch_falls_back_to_derive_on_read(store: SQLiteGraphStore, monkeypatch: pytest.MonkeyPatch) -> None:
    graph = build_unified_graph_from_report(shared_server_estate(agents=20, group_size=10), scan_id="s", tenant_id="t")
    store.save_graph(graph)
    loaded = store.load_graph(tenant_id="t", scan_id="s")
    assert stored_paths_current(loaded.analysis_status)

    calls: list[str] = []
    monkeypatch.setattr(
        "agent_bom.graph.snapshot_paths._derive_on_read",
        lambda g: calls.append("derive") or _derived_attack_paths(g),
    )
    stored = resolve_snapshot_attack_paths(loaded, store)
    assert calls == []

    monkeypatch.setattr("agent_bom.graph.snapshot_paths.DERIVATION_VERSION", DERIVATION_VERSION + 1)
    assert not stored_paths_current(loaded.analysis_status)
    fallback = resolve_snapshot_attack_paths(store.load_graph(tenant_id="t", scan_id="s"), store)
    assert calls == ["derive"]
    assert _dicts(fallback) == _dicts(stored)


def test_legacy_snapshot_without_paths_status_derives_on_read(store: SQLiteGraphStore) -> None:
    graph = build_unified_graph_from_report(shared_server_estate(agents=10, group_size=5), scan_id="old", tenant_id="t")
    graph.analysis_status[PATHS_ANALYSIS_KEY] = GraphAnalysisStatus(status=GraphAnalysisState.FAILED)
    store.save_graph_streaming(
        scan_id="old",
        tenant_id="t",
        nodes=graph.nodes.values(),
        edges=graph.edges,
        attack_paths=graph.attack_paths,
        interaction_risks=graph.interaction_risks,
        analysis_status={k: v for k, v in graph.analysis_status.items() if k != PATHS_ANALYSIS_KEY},
    )
    assert store.snapshot_attack_paths(tenant_id="t", scan_id="old") is None
    loaded = store.load_graph(tenant_id="t", scan_id="old")
    assert not stored_paths_current(loaded.analysis_status)
    expected = _derived_attack_paths(store.load_graph(tenant_id="t", scan_id="old"))
    assert _dicts(resolve_snapshot_attack_paths(loaded, store)) == _dicts(expected)


def test_stored_paths_equal_derivation_when_fusion_rows_need_read_adjustment(store: SQLiteGraphStore) -> None:
    graph = _two_route_graph("tenant-a", scan_id="fusion")
    graph.add_node(_node("vuln:CVE-1", EntityType.VULNERABILITY, severity="high"))
    graph.add_edge(UnifiedEdge(source="server:y", target="vuln:CVE-1", relationship=RelationshipType.VULNERABLE_TO))
    graph.attack_paths[1] = AttackPath(
        source="agent:a",
        target="vuln:CVE-1",
        hops=["agent:a", "server:y", "vuln:CVE-1"],
        edges=["uses", "vulnerable_to"],
        composite_risk=90.0,
        summary="fused",
    )
    store.save_graph(graph)
    stored = store.snapshot_attack_paths(tenant_id="tenant-a", scan_id="fusion")
    assert stored is not None
    derived = _derived_attack_paths(store.load_graph(tenant_id="tenant-a", scan_id="fusion"))
    assert _dicts(stored.paths) == _dicts(derived)
    capped = next(path for path in stored.paths if path.target == "vuln:CVE-1" and path.summary.endswith("fused"))
    assert capped.composite_risk == 39.0
    assert store.load_graph(tenant_id="tenant-a", scan_id="fusion").attack_paths[1].composite_risk == 90.0
