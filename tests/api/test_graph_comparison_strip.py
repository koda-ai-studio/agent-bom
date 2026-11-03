"""The compact change strip uses comparable scopes and known metrics only."""

import pytest

from agent_bom.api import graph_estate_changes
from agent_bom.graph.container import AttackPath
from tests.api.test_graph_estate_changes import TENANT, client, record
from tests.api.test_graph_estate_changes import estate as estate_fixture

estate = estate_fixture


def test_path_only_change_is_not_reported_as_an_unchanged_scope(estate):
    old = record(estate, 7, "repo-a", ["asrv", "package"], [("asrv", "package")])
    new = record(estate, 8, "repo-a", ["asrv", "package"], [("asrv", "package")])
    graph = estate[1].load_graph(tenant_id=TENANT, scan_id=new)
    graph.attack_paths.append(AttackPath(source="asrv", target="package", hops=["asrv", "package"], composite_risk=7))
    estate[1].save_graph(graph)
    with client() as http:
        body = http.get("/v1/graph/changes").json()
    row = body["sources"][0]
    assert row["old"]["scan_id"] == old
    assert row["counts"]["nodes"] == {"added": 0, "removed": 0, "changed": 0}
    assert row["highlights"]["new_attack_paths"]["count"] == 1
    assert body["totals"]["changed_sources"] == 1
    assert row["comparison"]["status"] == "comparable"


@pytest.mark.parametrize("partial_side", ["old", "new"])
def test_partial_collection_never_supplies_a_comparable_decrease(estate, partial_side):
    ids = {"old": record(estate, 7, "repo-a", ["asrv", "package"]), "new": record(estate, 8, "repo-a", ["asrv"])}
    scan = estate[0].get(ids[partial_side], tenant_id=TENANT)
    scan.result["scan_run"]["outcome"] = "partial"
    estate[0].put(scan)
    with client() as http:
        row = http.get("/v1/graph/changes").json()["sources"][0]
    assert row["comparison"]["status"] == "unavailable"
    assert row["comparison"]["reason"] == "incomplete_collection"
    assert row["kev_change"] is None


def test_changed_collection_scope_is_not_a_comparable_delta(estate):
    record(estate, 7, "repo-a", ["asrv"])
    new = record(estate, 8, "repo-a", ["asrv", "package"])
    scan = estate[0].get(new, tenant_id=TENANT)
    scan.result["scan_sources"] = ["repository", "cloud"]
    estate[0].put(scan)
    with client() as http:
        row = http.get("/v1/graph/changes").json()["sources"][0]
    assert row["comparison"]["reason"] == "different_collection_coverage"


def test_kev_delta_requires_matching_recorded_trend_basis(estate, monkeypatch):
    old = record(estate, 7, "repo-a", ["asrv"])
    new = record(estate, 8, "repo-a", ["asrv"])
    meta = {"scope_id": "scoped", "measurement_version": 1, "collection_coverage": "complete", "coverage_key": "same"}
    recorded = {
        old: {"basis": "issue_groups", "kev_count": 2, "trend_basis": meta},
        new: {"basis": "issue_groups", "kev_count": 0, "trend_basis": meta},
    }
    monkeypatch.setattr(graph_estate_changes, "_recorded_issue_counts", lambda tenant: recorded)
    with client() as http:
        row = http.get("/v1/graph/changes").json()["sources"][0]
        assert row["kev_change"] == {"old": 2, "new": 0, "delta": -2, "basis": "issue_groups"}
        recorded[new]["trend_basis"] = {**meta, "scope_id": "foreign"}
        assert http.get("/v1/graph/changes").json()["sources"][0]["kev_change"] is None
