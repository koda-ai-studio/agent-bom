"""The current-estate projection keeps every distinct route between the same endpoints."""

from __future__ import annotations

import pytest

from agent_bom.api import stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.store import InMemoryJobStore
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
from agent_bom.graph.container import AttackPath
from tests.api.test_scan_job_sla_history import job


@pytest.fixture
def estate(tmp_path, monkeypatch):
    jobs, graphs = InMemoryJobStore(), SQLiteGraphStore(str(tmp_path / "graph.db"))
    monkeypatch.setattr(stores, "_store", jobs)
    monkeypatch.setattr(stores, "_graph_store", graphs)
    return jobs, graphs


def _record(estate, month: int, target: str, risk: float) -> None:
    jobs, graphs = estate
    scan = job(month, tenant="t", target=target, findings=[])
    scan.result.update(scan_id=scan.job_id, scan_run={"outcome": "complete"})
    graph = UnifiedGraph(scan_id=scan.job_id, tenant_id="t", created_at=scan.completed_at)
    for node_id in ("entry", f"mid-{target}", "jewel"):
        graph.add_node(UnifiedNode(id=node_id, entity_type=EntityType.SERVER, label=node_id))
    graph.attack_paths.append(
        AttackPath(source="entry", target="jewel", hops=["entry", f"mid-{target}", "jewel"], edges=["uses", "uses"], composite_risk=risk)
    )
    graphs.save_graph(graph)
    jobs.put(scan)


def test_current_estate_keeps_both_routes_between_same_endpoints(estate) -> None:
    _record(estate, 8, "repo-a", 90.0)
    _record(estate, 9, "repo-b", 10.0)

    current = stores._get_graph_store().load_graph(tenant_id="t")

    assert [(path.hops, path.composite_risk) for path in current.attack_paths] == [
        (["entry", "mid-repo-a", "jewel"], 90.0),
        (["entry", "mid-repo-b", "jewel"], 10.0),
    ]
