"""A committed snapshot pre-builds the findings reachability index.

``GET /v1/findings?reachability=`` joins every finding against the snapshot's
evidence-bearing attack paths. The index is built once per snapshot generation
and cached, but the first reader after a commit paid the whole build (23.6 s on
the freshly seeded demo, contending with the other first reads). A commit hook
now builds it in the background, so the first reader is served from cache.
"""

from __future__ import annotations

import pytest

from agent_bom.api import finding_reachability, finding_reachability_prewarm, graph_commit_hooks
from agent_bom.api.finding_reachability import project_persisted_graph_reachability
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph import AttackPath, EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode

pytestmark = pytest.mark.graph_contract("warn")


def _graph() -> UnifiedGraph:
    graph = UnifiedGraph(scan_id="reach-scan", tenant_id="t1", created_at="2026-10-19T00:00:00+00:00")
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="a"))
    graph.add_node(UnifiedNode(id="vuln:CVE-2099-1", entity_type=EntityType.VULNERABILITY, label="CVE-2099-1", severity="high"))
    graph.add_edge(UnifiedEdge(source="agent:a", target="vuln:CVE-2099-1", relationship=RelationshipType.VULNERABLE_TO))
    graph.attack_paths.append(
        AttackPath(
            source="agent:a",
            target="vuln:CVE-2099-1",
            hops=["agent:a", "vuln:CVE-2099-1"],
            edges=["vulnerable_to"],
            composite_risk=50.0,
            vuln_ids=["CVE-2099-1"],
        )
    )
    return graph


@pytest.fixture
def store(tmp_path):
    finding_reachability.clear_reachability_index_cache()
    graph_store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    graph_store.save_graph(_graph())
    yield graph_store
    finding_reachability.clear_reachability_index_cache()


def _count_path_reads(monkeypatch: pytest.MonkeyPatch, graph_store: SQLiteGraphStore) -> list[int]:
    reads: list[int] = []
    original = graph_store.attack_paths

    def counting(**kwargs):  # type: ignore[no-untyped-def]
        reads.append(int(kwargs.get("limit") or 0))
        return original(**kwargs)

    monkeypatch.setattr(graph_store, "attack_paths", counting)
    return reads


def test_prewarm_builds_the_index_the_first_reader_uses(store: SQLiteGraphStore, monkeypatch: pytest.MonkeyPatch) -> None:
    assert finding_reachability_prewarm.prewarm_reachability_index(store, tenant_id="t1") is True
    reads = _count_path_reads(monkeypatch, store)
    projection = project_persisted_graph_reachability(
        [{"vulnerability_id": "CVE-2099-1", "node_id": "vuln:CVE-2099-1"}], graph_store=store, tenant_id="t1", scan_id=None
    )
    assert projection.rows[0]["graph_reachable"] is True
    assert reads == [1], "the first reader re-read the snapshot's paths instead of using the warmed index"


def test_prewarm_is_tenant_scoped(store: SQLiteGraphStore, monkeypatch: pytest.MonkeyPatch) -> None:
    finding_reachability_prewarm.prewarm_reachability_index(store, tenant_id="other")
    reads = _count_path_reads(monkeypatch, store)
    project_persisted_graph_reachability(
        [{"vulnerability_id": "CVE-2099-1", "node_id": "vuln:CVE-2099-1"}], graph_store=store, tenant_id="t1", scan_id=None
    )
    assert len(reads) > 1, "another tenant's warm-up must not serve this tenant"


def test_commit_hook_is_registered_and_opt_out(store: SQLiteGraphStore, monkeypatch: pytest.MonkeyPatch) -> None:
    assert "finding_reachability_prewarm" in graph_commit_hooks._HOOKS
    monkeypatch.setenv("AGENT_BOM_FINDING_REACHABILITY_PREWARM", "0")
    assert finding_reachability_prewarm.schedule_reachability_prewarm(lambda: store, tenant_id="t1") is False


def test_scheduled_warm_up_runs_off_thread_and_never_raises(store: SQLiteGraphStore) -> None:
    def broken():  # type: ignore[no-untyped-def]
        raise RuntimeError("store unavailable")

    assert finding_reachability_prewarm.schedule_reachability_prewarm(broken, tenant_id="t1") is True
    assert finding_reachability_prewarm.schedule_reachability_prewarm(lambda: store, tenant_id="t1") is True
    assert finding_reachability_prewarm.wait_idle(10.0)
