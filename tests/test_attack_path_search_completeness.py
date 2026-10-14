"""Whole-queue searches (deploy gate, filtered exposure paths) must see every stored path.

A snapshot holding more paths than the rank window used to be searched only up
to the window while reporting a complete search, so a candidate ranked beyond it
was "not found" and a low-risk match inside the window could yield ``allow``.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from agent_bom.graph import attack_path_queue
from agent_bom.graph.container import AttackPath
from agent_bom.graph.snapshot_paths import StoredQueuePage
from agent_bom.mcp_tools import exposure_queue
from agent_bom.mcp_tools.graph import deploy_decision_impl, exposure_paths_impl

WINDOW = 5


def _path(index: int, *, target: str | None = None, risk: float = 10.0) -> AttackPath:
    return AttackPath(
        source=f"agent:a{index}",
        target=target or f"server:s{index}",
        hops=[f"agent:a{index}", target or f"server:s{index}"],
        composite_risk=risk,
        reachability="confirmed",
    )


class _IndexedStore:
    """Stored queue index in rank order, paged like the SQLite/Postgres readers."""

    def __init__(self, paths: list[AttackPath], *, indexed: bool = True) -> None:
        self.paths = paths
        self.indexed = indexed
        self.generation = "gen-1"
        self.identity_reads = 0
        self.swap_after: int | None = None

    def snapshot_identity(self, *, tenant_id: str = "", scan_id: str = "", for_paging: bool = False) -> tuple[str, str]:
        self.identity_reads += 1
        if self.swap_after is not None and self.identity_reads > self.swap_after:
            self.generation = "gen-2"
        return "scan-1", self.generation

    def snapshot_queue_page(self, *, tenant_id: str = "", scan_id: str = "", offset: int = 0, limit: int = 100, **_filters: Any):
        if not self.indexed:
            return None
        return StoredQueuePage("scan-1", "2026-10-01T00:00:00Z", self.paths[offset : offset + limit], len(self.paths), len(self.paths))

    def attack_paths(self, *, tenant_id: str = "", scan_id: str = "", offset: int = 0, limit: int = 100):
        ordered = sorted(self.paths, key=lambda path: -path.composite_risk)
        return "scan-1", "2026-10-01T00:00:00Z", ordered[offset : offset + limit], len(self.paths)

    def nodes_by_ids(self, *, tenant_id: str = "", scan_id: str = "", node_ids: set[str]) -> list[Any]:
        return []

    def edges_for_node_ids(self, **_kwargs: Any) -> list[Any]:
        return []

    def snapshot_stats(self, **_kwargs: Any) -> dict[str, Any]:
        return {}


@pytest.fixture(autouse=True)
def _small_window(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(attack_path_queue, "RANK_WINDOW", WINDOW)


def _deploy(store: _IndexedStore, candidate: str) -> dict[str, Any]:
    return json.loads(asyncio.run(deploy_decision_impl(candidate=candidate, _get_graph_store=lambda: store)))


def _exposure(store: _IndexedStore, **filters: Any) -> dict[str, Any]:
    return json.loads(asyncio.run(exposure_paths_impl(_get_graph_store=lambda: store, limit=10, **filters)))


def test_deploy_gate_finds_a_match_ranked_beyond_the_window() -> None:
    paths = [_path(index) for index in range(12)]
    paths[9] = _path(9, target="server:deep")
    payload = _deploy(_IndexedStore(paths), "server:deep")
    assert payload["matchedPathCount"] == 1
    assert payload["searchedPaths"] == payload["total"] == 12
    assert payload["searchComplete"] is True


def test_low_risk_match_in_window_never_hides_a_high_risk_match_beyond_it() -> None:
    paths = [_path(index, target="server:shared" if index in {0, 10} else None) for index in range(12)]
    paths[10] = _path(10, target="server:shared", risk=95.0)
    payload = _deploy(_IndexedStore(paths), "server:shared")
    assert payload["matchedPathCount"] == 2
    assert payload["decision"] == "block"
    assert payload["maxRisk"] == 95.0


def test_unindexed_snapshot_beyond_the_window_is_incomplete_and_never_allows() -> None:
    paths = [_path(index, target="server:low" if index == 0 else None, risk=50.0 - index) for index in range(12)]
    payload = _deploy(_IndexedStore(paths, indexed=False), "server:low")
    assert payload["searchComplete"] is False
    assert payload["evidenceStatus"] == "not_evaluated"
    assert payload["decision"] != "allow"


def test_filtered_exposure_search_reads_past_the_window() -> None:
    paths = [_path(index) for index in range(12)]
    paths[11] = _path(11, target="server:deep")
    payload = _exposure(_IndexedStore(paths), target_id="server:deep")
    assert [path["target"]["id"] for path in payload["paths"]] == ["server:deep"]
    assert payload["total"] == 1
    assert payload["count_metadata"]["total_is_lower_bound"] is False
    assert payload["completeness"]["complete"] is True


def test_filtered_exposure_search_past_the_cap_is_a_lower_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exposure_queue, "SEARCH_PATH_CAP", 8)
    paths = [_path(index) for index in range(12)]
    paths[11] = _path(11, target="server:deep")
    payload = _exposure(_IndexedStore(paths), target_id="server:deep")
    assert payload["total"] == 0
    assert payload["count_metadata"]["total_is_lower_bound"] is True
    assert payload["completeness"]["complete"] is False
    assert payload["completeness"]["reason"] == "search_cap"


def test_deploy_gate_rejects_a_snapshot_that_changed_mid_read() -> None:
    store = _IndexedStore([_path(index, target="server:x" if index == 0 else None) for index in range(3)])
    store.swap_after = 1
    payload = _deploy(store, "server:x")
    error = payload["error"]
    assert error["code"] == "AGENTBOM_MCP_UPSTREAM_UNAVAILABLE"
    assert error["details"] == {"retryable": True, "reason": "snapshot_changed", "evidenceStatus": "not_evaluated"}
    assert "decision" not in payload


def test_rest_attack_paths_report_lower_bound_beyond_the_rank_window() -> None:
    from agent_bom.api.routes.graph_routes.payloads import _serialize_attack_path_queue

    page = attack_path_queue.ranked_persisted_path_page(
        _IndexedStore([_path(index) for index in range(12)], indexed=False),
        scan_id="scan-1",
        tenant_id="default",
        offset=0,
        limit=100,
        filters=attack_path_queue.AttackPathFilters(),
    )
    payload = _serialize_attack_path_queue(
        scan_id="scan-1",
        tenant="default",
        created_at=page.created_at,
        nodes=[],
        path_edges=[],
        paths=page.paths,
        total=page.total,
        offset=0,
        limit=100,
        stats={},
        path_source="persisted_graph_paths",
        materialized_paths=page.snapshot_total,
        derived_paths=0,
        ranked=page,
    )
    assert payload["completeness"]["complete"] is False
    assert payload["completeness"]["reason"] == "rank_window"
    assert payload["count_metadata"]["total_is_lower_bound"] is True
