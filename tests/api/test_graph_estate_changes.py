"""What changed in the current estate: each target scope against its own previous snapshot."""

from __future__ import annotations

import asyncio
import json

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.container import AttackPath
from tests.api.test_scan_job_sla_history import job
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

TENANT = "changes-tenant"


@pytest.fixture
def estate(tmp_path, monkeypatch):
    jobs = InMemoryJobStore()
    graph_store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    monkeypatch.setattr(stores, "_store", jobs)
    monkeypatch.setattr(stores, "_graph_store", graph_store)
    enable_trusted_proxy_env()
    yield jobs, graph_store
    disable_trusted_proxy_env()


def record(estate, month, target, nodes, edges=(), *, tenant=TENANT, save_graph=True):
    jobs, graph_store = estate
    scan = job(month, tenant=tenant, target=target, findings=[])
    scan.result.update(scan_id=scan.job_id, scan_run={"outcome": "complete"})
    if save_graph:
        graph = UnifiedGraph(scan_id=scan.job_id, tenant_id=tenant, created_at=scan.completed_at)
        for name in nodes:
            kind = EntityType.SERVER if name.endswith("srv") else EntityType.PACKAGE
            graph.add_node(UnifiedNode(id=name, entity_type=kind, label=name))
        for source, target_id in edges:
            graph.add_edge(UnifiedEdge(source=source, target=target_id, relationship=RelationshipType.DEPENDS_ON))
        graph_store.save_graph(graph)
    jobs.put(scan)
    return scan.job_id


def seed(estate):
    # repo-a: +a3, -a1; one edge added.
    record(estate, 7, "repo-a", ["asrv", "a1"])
    record(estate, 8, "repo-a", ["asrv", "a3"], [("asrv", "a3")])
    # repo-b: +b2 +b3; edge bsrv->b2 added; nothing removed.
    record(estate, 7, "repo-b", ["bsrv"])
    record(estate, 9, "repo-b", ["bsrv", "b2", "b3"], [("bsrv", "b2")])
    # repo-c: single snapshot — a first observation, never an addition.
    record(estate, 10, "repo-c", ["c1", "c2", "c3", "c4"])


def client(tenant=TENANT):
    return TestClient(app, headers=proxy_headers(tenant=tenant))


def by_label(body):
    return {row["label"]: row for row in body["sources"]}


def test_each_scope_diffs_against_its_own_previous_snapshot(estate):
    seed(estate)
    with client() as http:
        response = http.get("/v1/graph/changes")
    assert response.status_code == 200, response.text
    body = response.json()
    rows = by_label(body)
    assert set(rows) == {"repo-a", "repo-b"}
    a, b = rows["repo-a"], rows["repo-b"]
    assert (a["old"]["scan_id"], a["new"]["scan_id"]) == (f"{TENANT}-repo-a-7", f"{TENANT}-repo-a-8")
    assert a["counts"]["nodes"] == {"added": 1, "removed": 1, "changed": 0}
    assert a["counts"]["edges"] == {"added": 1, "removed": 0, "changed": 0}
    assert b["counts"]["nodes"] == {"added": 2, "removed": 0, "changed": 0}
    assert b["counts"]["edges"] == {"added": 1, "removed": 0, "changed": 0}
    assert a["old"]["captured_at"] < a["new"]["captured_at"]
    assert "highlights" in a and "new_critical_findings" in a["highlights"]
    # Scope ids are opaque and never the raw request scope.
    assert a["scope_id"] and "repo-a" not in a["scope_id"]

    assert [row["label"] for row in body["new_sources"]] == ["repo-c"]
    first = body["new_sources"][0]
    assert first["reason"] == "first_observation" and first["new"]["scan_id"] == f"{TENANT}-repo-c-10"
    assert first["node_count"] == 4

    totals = body["totals"]
    # repo-c's four nodes are a first observation, not additions.
    assert totals["nodes"] == {"added": 3, "removed": 1, "changed": 0}
    assert totals["edges"] == {"added": 2, "removed": 0, "changed": 0}
    assert totals["changed_sources"] == 2 and totals["new_sources"] == 1 and totals["unchanged_sources"] == 0
    assert body["evidence_scope"] == "current_estate"
    assert body["completeness"]["complete"] is True
    assert body["pagination"]["has_more"] is False and body["pagination"]["total"] == 3


def test_tenant_wide_latest_pair_would_misreport_sources(estate):
    """The bug this route exists to avoid: the latest-two diff crosses scopes."""
    seed(estate)
    with client() as http:
        naive = http.get("/v1/graph/diff").json()
        estate_changes = http.get("/v1/graph/changes").json()
    assert (naive["old"], naive["new"]) == (f"{TENANT}-repo-b-9", f"{TENANT}-repo-c-10")
    for row in estate_changes["sources"]:
        assert row["old"]["scan_id"].rsplit("-", 1)[0] == row["new"]["scan_id"].rsplit("-", 1)[0]
    assert estate_changes["totals"]["nodes"]["removed"] == 1


def test_previous_snapshot_without_graph_is_skipped_and_disclosed(estate):
    record(estate, 6, "repo-a", ["a0", "a1"])
    record(estate, 7, "repo-a", [], save_graph=False)
    record(estate, 8, "repo-a", ["a1", "a2"])
    with client() as http:
        body = http.get("/v1/graph/changes").json()
    row = body["sources"][0]
    assert row["old"]["scan_id"] == f"{TENANT}-repo-a-6"
    assert row["skipped_snapshots"] == 1
    assert row["counts"]["nodes"] == {"added": 1, "removed": 1, "changed": 0}
    assert "previous_graph_unavailable" in body["completeness_reasons"]


def test_unchanged_scope_reports_zero_changes(estate):
    record(estate, 7, "repo-a", ["a1"])
    record(estate, 8, "repo-a", ["a1"])
    with client() as http:
        body = http.get("/v1/graph/changes").json()
    assert body["totals"]["changed_sources"] == 0 and body["totals"]["unchanged_sources"] == 1
    assert body["sources"][0]["total_changes"] == 0


def test_tenant_isolation(estate):
    seed(estate)
    record(estate, 7, "repo-a", ["x1"], tenant="other-tenant")
    record(estate, 9, "repo-a", ["x1", "x2", "x3"], tenant="other-tenant")
    with client("other-tenant") as http:
        other = http.get("/v1/graph/changes").json()
    assert [row["label"] for row in other["sources"]] == ["repo-a"]
    assert other["sources"][0]["counts"]["nodes"] == {"added": 2, "removed": 0, "changed": 0}
    assert other["new_sources"] == []
    with client("empty-tenant") as http:
        empty = http.get("/v1/graph/changes").json()
    assert empty["sources"] == [] and empty["new_sources"] == [] and empty["totals"]["nodes"]["added"] == 0


def test_scopes_are_capped_with_honest_paging(estate):
    seed(estate)
    seen: list[str] = []
    offset = 0
    with client() as http:
        for _ in range(4):
            page = http.get("/v1/graph/changes", params={"limit": 1, "offset": offset}).json()
            assert page["pagination"]["total"] == 3 and page["pagination"]["returned"] == 1
            seen.extend(row["label"] for row in [*page["sources"], *page["new_sources"]])
            if not page["pagination"]["has_more"]:
                assert page["completeness"]["complete"] is True
                break
            assert page["completeness"]["truncated"] is True and page["completeness"]["reason"] == "source_page_limit"
            offset = page["pagination"]["next_offset"]
        assert http.get("/v1/graph/changes", params={"limit": 0}).status_code == 422
        assert http.get("/v1/graph/changes", params={"limit": 101}).status_code == 422
    assert sorted(seen) == ["repo-a", "repo-b", "repo-c"]


def test_mcp_estate_mode_matches_rest(estate, monkeypatch):
    from agent_bom.mcp_tools.graph_diff import graph_diff_impl

    seed(estate)
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", TENANT)
    with client() as http:
        rest = http.get("/v1/graph/changes").json()
    mcp = json.loads(asyncio.run(graph_diff_impl(tenant_id=TENANT, view="estate")))
    assert mcp["tool"] == "graph_diff" and mcp["source"] == "v1_graph_changes"
    for key in ("sources", "new_sources", "totals", "pagination", "completeness"):
        assert mcp[key] == rest[key]


def save_snapshot(estate, scan_id, created_at, nodes, *, paths=()):
    _jobs, graph_store = estate
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=TENANT, created_at=created_at)
    for name in nodes:
        kind = EntityType.SERVER if name.endswith("srv") else EntityType.PACKAGE
        graph.add_node(UnifiedNode(id=name, entity_type=kind, label=name))
    for hops in paths:
        graph.attack_paths.append(AttackPath(source=hops[0], target=hops[-1], hops=list(hops), composite_risk=7.0))
    graph_store.save_graph(graph)


def test_single_scan_scope_compares_with_declared_snapshot_baseline(estate):
    """A scope seen once is still comparable with the store's earlier same-kind snapshot no other scope owns."""
    save_snapshot(estate, "baseline", "2026-07-01T00:00:00+00:00", ["asrv", "a1"])
    record(estate, 8, "repo-a", ["asrv", "a2", "a3"])
    with client() as http:
        body = http.get("/v1/graph/changes").json()
    assert body["new_sources"] == []
    row = by_label(body)["repo-a"]
    assert row["old"]["scan_id"] == "baseline" and row["old"]["job_id"] == ""
    assert row["baseline"] == "snapshot_continuity"
    assert row["counts"]["nodes"] == {"added": 2, "removed": 1, "changed": 0}
    assert body["totals"]["changed_sources"] == 1 and body["totals"]["new_sources"] == 0
    assert "snapshot_baseline" in body["completeness_reasons"]


def test_scope_history_baseline_is_labelled(estate):
    seed(estate)
    with client() as http:
        body = http.get("/v1/graph/changes").json()
    assert {row["baseline"] for row in body["sources"]} == {"scope_history"}
    assert "snapshot_baseline" not in body["completeness_reasons"]


def test_another_scopes_snapshot_is_never_a_baseline(estate):
    """The tenant-wide predecessor belongs to repo-b's scan, so repo-c stays a first observation."""
    record(estate, 7, "repo-b", ["bsrv"])
    record(estate, 8, "repo-c", ["c1"])
    with client() as http:
        body = http.get("/v1/graph/changes").json()
    assert {row["label"] for row in body["new_sources"]} == {"repo-b", "repo-c"}
    assert body["sources"] == []


def test_source_lists_new_and_removed_attack_paths(estate):
    save_snapshot(estate, "baseline", "2026-07-01T00:00:00+00:00", ["asrv", "a1"], paths=[("asrv", "a1")])
    jobs, graph_store = estate
    scan = job(8, tenant=TENANT, target="repo-a", findings=[])
    scan.result.update(scan_id=scan.job_id, scan_run={"outcome": "complete"})
    graph = UnifiedGraph(scan_id=scan.job_id, tenant_id=TENANT, created_at=scan.completed_at)
    for name, kind in (("asrv", EntityType.SERVER), ("a2", EntityType.PACKAGE)):
        graph.add_node(UnifiedNode(id=name, entity_type=kind, label=name))
    graph.attack_paths.append(AttackPath(source="asrv", target="a2", hops=["asrv", "a2"], composite_risk=9.0))
    graph_store.save_graph(graph)
    jobs.put(scan)
    with client() as http:
        row = by_label(http.get("/v1/graph/changes").json())["repo-a"]
    added = row["highlights"]["new_attack_paths"]
    removed = row["highlights"]["removed_attack_paths"]
    assert added["count"] == 1 and added["top"][0]["hops"] == ["asrv", "a2"]
    assert removed["count"] == 1 and removed["top"][0]["hops"] == ["asrv", "a1"]


def test_highlighted_paths_and_reach_carry_node_display_names(estate):
    """The changes panel names endpoints, never raw ids; each side is named from its own snapshot."""
    jobs, graph_store = estate
    baseline = UnifiedGraph(scan_id="baseline", tenant_id=TENANT, created_at="2026-07-01T00:00:00+00:00")
    baseline.add_node(UnifiedNode(id="asrv", entity_type=EntityType.SERVER, label="Billing server"))
    baseline.add_node(UnifiedNode(id="a1", entity_type=EntityType.PACKAGE, label="Old package"))
    baseline.attack_paths.append(AttackPath(source="asrv", target="a1", hops=["asrv", "a1"], composite_risk=7.0))
    graph_store.save_graph(baseline)
    scan = job(8, tenant=TENANT, target="repo-a", findings=[])
    scan.result.update(scan_id=scan.job_id, scan_run={"outcome": "complete"})
    graph = UnifiedGraph(scan_id=scan.job_id, tenant_id=TENANT, created_at=scan.completed_at)
    graph.add_node(UnifiedNode(id="asrv", entity_type=EntityType.SERVER, label="Billing server"))
    graph.add_node(UnifiedNode(id="cred:k", entity_type=EntityType.CREDENTIAL, label="Stripe key"))
    graph.add_node(UnifiedNode(id="a2", entity_type=EntityType.PACKAGE, label="New package"))
    graph.add_edge(UnifiedEdge(source="asrv", target="cred:k", relationship=RelationshipType.EXPOSES_CRED))
    graph.attack_paths.append(AttackPath(source="asrv", target="a2", hops=["asrv", "a2"], composite_risk=9.0))
    graph_store.save_graph(graph)
    jobs.put(scan)
    with client() as http:
        row = by_label(http.get("/v1/graph/changes").json())["repo-a"]
    added = row["highlights"]["new_attack_paths"]["top"][0]
    removed = row["highlights"]["removed_attack_paths"]["top"][0]
    reach = row["highlights"]["new_credential_reach"]["top"][0]
    assert (added["source_label"], added["target_label"]) == ("Billing server", "New package")
    assert (removed["source_label"], removed["target_label"]) == ("Billing server", "Old package")
    assert (reach["source_label"], reach["target_label"]) == ("Billing server", "Stripe key")
