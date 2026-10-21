"""Default graph reads retain current evidence across independent scan targets."""

import pytest

from agent_bom.api import stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.store import InMemoryJobStore
from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
from tests.api.test_scan_job_sla_history import job


@pytest.fixture
def estate(tmp_path, monkeypatch):
    jobs = InMemoryJobStore()
    graph_store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    monkeypatch.setattr(stores, "_store", jobs)
    monkeypatch.setattr(stores, "_graph_store", graph_store)
    return jobs, graph_store


def record(estate, month, target, *nodes, tenant="history-tenant", partial=False):
    jobs, graph_store = estate
    scan = job(month, tenant=tenant, target=target, findings=[])
    scan.result.update(scan_id=scan.job_id, scan_run={"outcome": "partial" if partial else "complete"})
    graph = UnifiedGraph(scan_id=scan.job_id, tenant_id=tenant, created_at=scan.completed_at)
    for name in nodes:
        graph.add_node(UnifiedNode(id=name, entity_type=EntityType.PACKAGE, label=name))
    graph_store.save_graph(graph)
    jobs.put(scan)
    return scan.job_id


def current(tenant="history-tenant"):
    return stores._get_graph_store().load_graph(tenant_id=tenant)


def test_clean_push_replaces_only_its_own_target_and_preserves_history(estate):
    first = record(estate, 7, "repo-a", "clean-package-a")
    record(estate, 8, "repo-b", "package-b")
    record(estate, 9, "repo-b")
    assert set(current().nodes) == {"clean-package-a"}
    assert current().scan_id.startswith("current-estate:")
    assert set(stores._get_graph_store().load_graph(tenant_id="history-tenant", scan_id=first).nodes) == {"clean-package-a"}
    assert not current("other-tenant").nodes


def test_partial_push_retains_prior_assets_and_older_arrival_does_not_replace(estate):
    record(estate, 8, "repo-a", "package-a")
    record(estate, 9, "repo-a", "package-b", partial=True)
    record(estate, 7, "repo-a", "obsolete-package")
    assert set(current().nodes) == {"package-a", "package-b"}
    generation = current().scan_id
    assert current().scan_id == generation
    record(estate, 10, "repo-a")
    assert not current().nodes
    assert current().scan_id != generation


def test_replay_changes_generation_and_rejects_stale_continuation(estate):
    from starlette.exceptions import HTTPException

    from agent_bom.api.graph_generation import pin_generation

    record(estate, 8, "repo-a", "before")
    store = stores._get_graph_store()
    before = store.snapshot_identity(tenant_id="history-tenant", for_paging=True)
    record(estate, 8, "repo-a", "after")
    assert set(current().nodes) == {"after"}
    with pytest.raises(HTTPException) as exc:
        pin_generation(store, tenant="history-tenant", scan_id=before[0], generation=before[1], offset=1)
    assert exc.value.status_code == 409


def test_warm_reads_do_not_deserialize_historical_reports(estate, monkeypatch):
    record(estate, 8, "repo-a", "package-a")
    current()

    def fail(*args, **kwargs):
        raise AssertionError("warm read reloaded a report")

    monkeypatch.setattr(estate[0], "get", fail)
    assert set(current().nodes) == {"package-a"}


def test_inventory_projects_the_same_current_assets(estate):
    import asyncio

    from agent_bom.api.inventory_service import build_asset_list

    record(estate, 8, "repo-a", "package-a")
    record(estate, 9, "repo-b")
    page = asyncio.run(build_asset_list(store=stores._get_graph_store(), tenant_id="history-tenant"))
    assert {row["id"] for row in page["assets"]} == {"package-a"}
    assert page["evidence_scope"] == "current_estate"


def test_current_projection_does_not_add_to_recorded_scan_history(estate):
    record(estate, 8, "repo-a", "package-a")
    before = estate[1].list_snapshots(tenant_id="history-tenant")
    current()
    assert estate[1].list_snapshots(tenant_id="history-tenant") == before


def test_current_generation_is_stable_across_projection_workers(estate):
    from agent_bom.api.current_graph import CurrentGraphStore

    record(estate, 8, "repo-a", "package-a")
    a = CurrentGraphStore(estate[1], estate[0])
    b = CurrentGraphStore(estate[1], estate[0])
    assert a.snapshot_identity(tenant_id="history-tenant", for_paging=True) == b.snapshot_identity(
        tenant_id="history-tenant", for_paging=True
    )
    assert set(a.load_rollup_graph(tenant_id="history-tenant").nodes) == {"package-a"}


def test_rest_and_mcp_inventory_share_current_and_historical_scope(estate, monkeypatch):
    import asyncio
    import json

    from starlette.testclient import TestClient

    from agent_bom.api.server import app
    from agent_bom.mcp_tools.inventory import inventory_summary_impl
    from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

    old = record(estate, 7, "repo-a", "old")
    record(estate, 8, "repo-a", "current")
    record(estate, 9, "repo-b")
    enable_trusted_proxy_env()
    try:
        with TestClient(app, headers=proxy_headers(tenant="history-tenant")) as client:
            assets = client.get("/v1/inventory/assets").json()
            assert {node["id"] for node in assets["assets"]} == {"current"}
            graph = client.get("/v1/graph", params={"limit": 100})
            assert graph.status_code == 200, graph.text
            assert {node["id"] for node in graph.json()["nodes"]} == {"current"}
            historical = client.get("/v1/inventory/assets", params={"scan_id": old}).json()
            assert {node["id"] for node in historical["assets"]} == {"old"}
        monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "history-tenant")
        mcp = json.loads(asyncio.run(inventory_summary_impl(tenant_id="history-tenant")))
        assert mcp["total_assets"] == 1
        assert mcp["evidence_scope"] == "current_estate"
    finally:
        disable_trusted_proxy_env()


def test_legacy_agent_inventory_retires_only_completed_target(estate):
    from agent_bom.api.estate_agents import scanned_estate_agents

    jobs, _ = estate
    record(estate, 7, "repo-a", "asset-a")
    record(estate, 8, "repo-b", "asset-b")
    for row in jobs.list_all(tenant_id="history-tenant"):
        row.result["agents"] = [{"name": row.target["path"], "canonical_id": row.target["path"]}]
        jobs.put(row)
    record(estate, 9, "repo-b")
    assert [a["name"] for a in scanned_estate_agents(jobs.list_all(tenant_id="history-tenant"))] == ["repo-a"]


def test_partial_current_scope_retains_a_visible_collection_gap(estate):
    import asyncio

    from agent_bom.api.inventory_service import build_summary

    record(estate, 8, "repo-a", "package-a")
    record(estate, 9, "repo-a", partial=True)
    summary = asyncio.run(build_summary(store=stores._get_graph_store(), tenant_id="history-tenant"))
    assert summary["total_assets"] == 1
    assert summary["collection_coverage"]["status"] == "partial"
    assert "scan_partial" in summary["collection_coverage"]["reason_codes"]


def test_inventory_only_observation_keeps_assets_without_erasing_findings(estate):
    record(estate, 8, "repo-a", "package-a")
    latest = record(estate, 9, "repo-a", "unassessed-package")
    row = estate[0].get(latest, tenant_id="history-tenant")
    row.result["no_scan"] = True
    estate[0].put(row)
    assert set(current().nodes) == {"package-a", "unassessed-package"}


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_in_place_authority_change_invalidates_current_projection(estate, tmp_path, backend):
    from agent_bom.api.current_graph import CurrentGraphStore
    from agent_bom.api.store import SQLiteJobStore

    old = record(estate, 8, "repo-a", "package-a")
    latest = record(estate, 9, "repo-a", "unassessed-package")
    jobs = estate[0]
    if backend == "sqlite":
        jobs = SQLiteJobStore(str(tmp_path / "jobs.db"))
        for scan_id in (old, latest):
            jobs.put(estate[0].get(scan_id, tenant_id="history-tenant"))
    store = CurrentGraphStore(estate[1], jobs)
    before = store.load_graph(tenant_id="history-tenant")
    assert set(before.nodes) == {"unassessed-package"}
    row = jobs.get(latest, tenant_id="history-tenant")
    row.result["no_scan"] = True
    jobs.put(row)
    after = store.load_graph(tenant_id="history-tenant")
    assert set(after.nodes) == {"package-a", "unassessed-package"}
    assert before.scan_id != after.scan_id


def test_derived_cache_retires_superseded_generations_but_keeps_observations(estate):
    store = stores._get_graph_store()
    for month in (7, 8, 9):
        record(estate, month, "repo-a", f"asset-{month}")
        assert set(current().nodes) == {f"asset-{month}"}
    assert len(store._projection_store.list_snapshots(tenant_id="history-tenant")) == 1
    assert len(estate[1].list_snapshots(tenant_id="history-tenant")) == 3


def test_current_incident_pages_accept_returned_generation(estate):
    from starlette.testclient import TestClient

    from agent_bom.api.server import app
    from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

    record(estate, 8, "repo-a", "package-a")
    enable_trusted_proxy_env()
    try:
        with TestClient(app, headers=proxy_headers(tenant="history-tenant")) as client:
            first = client.get("/v1/graph/incident-edges", params={"node_id": "package-a"})
            assert first.status_code == 200, first.text
            body = first.json()
            second = client.get(
                "/v1/graph/incident-edges",
                params={"node_id": "package-a", "scan_id": body["scan_id"], "snapshot_generation": body["snapshot_generation"]},
            )
            assert second.status_code == 200, second.text
    finally:
        disable_trusted_proxy_env()


def test_missing_retained_graph_returns_partial_without_substituting_latest(estate):

    record(estate, 8, "repo-a", "retained-a")
    record(estate, 9, "repo-b", "latest-b")
    assert set(current().nodes) == {"retained-a", "latest-b"}
    first = job(8, tenant="history-tenant", target="repo-a", findings=[])
    estate[1].delete_snapshot(tenant_id="history-tenant", scan_id=first.job_id)
    assert set(current().nodes) == {"latest-b"}

    from starlette.testclient import TestClient

    from agent_bom.api.server import app
    from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

    enable_trusted_proxy_env()
    try:
        with TestClient(app) as client:
            for endpoint in ("/v1/inventory/summary", "/v1/inventory/assets", "/v1/graph"):
                response = client.get(endpoint, headers=proxy_headers(tenant="history-tenant"))
                assert response.status_code == 200, response.text
                assert response.json()["collection_coverage"]["status"] == "partial"
                assert "graph_evidence_unavailable" in response.json()["collection_coverage"]["reason_codes"]
    finally:
        disable_trusted_proxy_env()


@pytest.mark.parametrize("same_target", [False, True])
@pytest.mark.parametrize("no_scan", [False, True])
def test_graphless_job_retains_available_evidence_and_late_graph_invalidates_cache(estate, same_target, no_scan):
    import asyncio

    from agent_bom.api.inventory_service import build_summary

    record(estate, 8, "repo-a", "retained-a")
    target = "repo-a" if same_target else "repo-b"
    latest = job(9, tenant="history-tenant", target=target, findings=[])
    latest.result.update(scan_id=latest.job_id, no_scan=no_scan)
    estate[0].put(latest)
    assert set(current().nodes) == {"retained-a"}
    before = current().scan_id
    summary = asyncio.run(build_summary(store=stores._get_graph_store(), tenant_id="history-tenant"))
    assert summary["collection_coverage"]["status"] == "partial"
    assert "graph_evidence_unavailable" in summary["collection_coverage"]["reason_codes"]
    # A graph arriving without a job mutation must still invalidate the cache.
    graph = UnifiedGraph(scan_id=latest.job_id, tenant_id="history-tenant", created_at=latest.completed_at)
    graph.add_node(UnifiedNode(id="late-package", entity_type=EntityType.PACKAGE, label="late"))
    estate[1].save_graph(graph)
    assert set(current().nodes) == ({"late-package"} if same_target and not no_scan else {"retained-a", "late-package"})
    assert current().scan_id != before
    summary = asyncio.run(build_summary(store=stores._get_graph_store(), tenant_id="history-tenant"))
    assert "graph_evidence_unavailable" not in summary["collection_coverage"]["reason_codes"]


def test_only_graphless_job_returns_empty_partial_estate(estate):
    import asyncio

    from agent_bom.api.inventory_service import build_summary

    latest = job(9, tenant="history-tenant", findings=[])
    estate[0].put(latest)
    assert not current().nodes
    summary = asyncio.run(build_summary(store=stores._get_graph_store(), tenant_id="history-tenant"))
    assert summary["total_assets"] == 0
    assert summary["collection_coverage"]["status"] == "partial"


def test_empty_estate_has_a_valid_empty_generation(estate):
    assert not current().nodes
    assert current().scan_id.startswith("current-estate:")


def test_storage_read_failure_is_not_reported_as_empty(estate, monkeypatch):
    record(estate, 8, "repo-a", "retained-a")

    def unavailable(*args, **kwargs):
        raise RuntimeError("storage unavailable")

    monkeypatch.setattr(estate[1], "snapshot_identity", unavailable)
    with pytest.raises(RuntimeError, match="storage unavailable"):
        current()


def test_empty_estate_rest_reads_are_successful_and_coverage_is_unknown(estate):
    from starlette.testclient import TestClient

    from agent_bom.api.server import app
    from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

    enable_trusted_proxy_env()
    try:
        with TestClient(app, headers=proxy_headers(tenant="history-tenant")) as client:
            for endpoint in ("/v1/graph", "/v1/inventory/summary", "/v1/inventory/assets"):
                response = client.get(endpoint)
                assert response.status_code == 200, response.text
                assert response.json()["collection_coverage"]["status"] == "unknown"
    finally:
        disable_trusted_proxy_env()


def _record_path(estate, month, target, risk, status, tenant="path-tenant"):
    from agent_bom.graph.container import AttackPath

    jobs, graph_store = estate
    scan = job(month, tenant=tenant, target=target, findings=[])
    scan.result.update(scan_id=scan.job_id, scan_run={"outcome": "complete"})
    graph = UnifiedGraph(scan_id=scan.job_id, tenant_id=tenant, created_at=scan.completed_at)
    for name in ("entry", "mid-" + target, "jewel"):
        graph.add_node(UnifiedNode(id=name, entity_type=EntityType.SERVER, label=name))
    graph.attack_paths.append(
        AttackPath(source="entry", target="jewel", hops=["entry", "mid-" + target, "jewel"], edges=["uses", "uses"], composite_risk=risk)
    )
    graph.analysis_status["credential_reach"] = status
    graph_store.save_graph(graph)
    jobs.put(scan)
    return scan.job_id


def test_current_estate_keeps_the_worst_source_analysis_status(estate):
    from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus

    _record_path(estate, 8, "repo-a", 90.0, GraphAnalysisStatus(status=GraphAnalysisState.LIMITED, reason_codes=("agent_budget",)))
    _record_path(estate, 9, "repo-b", 10.0, GraphAnalysisStatus(status=GraphAnalysisState.LIMITED, reason_codes=("depth_budget",)))
    _record_path(estate, 10, "repo-c", 20.0, GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE))
    projected = current("path-tenant")
    assert projected.scan_id.startswith("current-estate:")
    status = projected.analysis_status["credential_reach"]
    assert status.status is GraphAnalysisState.LIMITED
    assert status.reason_codes == ("agent_budget", "depth_budget")


def test_current_estate_does_not_inherit_source_stored_path_state(estate):
    from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus

    _, graph_store = estate
    scan_id = _record_path(estate, 8, "repo-a", 90.0, GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE))
    source = graph_store.load_graph(scan_id=scan_id, tenant_id="path-tenant")
    source.analysis_status["paths"] = GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE, observed={"count": 1})
    # Retain an old source receipt without regenerating its index.
    graph_store.save_graph_streaming(
        scan_id=source.scan_id,
        tenant_id=source.tenant_id,
        nodes=source.nodes.values(),
        edges=source.edges,
        attack_paths=source.attack_paths,
        analysis_status=source.analysis_status,
        created_at=source.created_at,
    )
    from agent_bom.graph.snapshot_paths import DERIVATION_VERSION

    projected = current("path-tenant")
    page = stores._get_graph_store().snapshot_attack_paths(tenant_id="path-tenant", scan_id=projected.scan_id)
    assert page is not None
    assert projected.analysis_status["paths"].observed == {"version": DERIVATION_VERSION, "count": len(page.paths)}


def test_merged_analysis_status_ranks_failure_above_limits():
    from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus, merge_analysis_statuses

    complete = GraphAnalysisStatus(status=GraphAnalysisState.COMPLETE, observed={"edges": 2})
    limited = GraphAnalysisStatus(status=GraphAnalysisState.LIMITED, reason_codes=("agent_budget",), observed={"edges": 3})
    failed = GraphAnalysisStatus(status=GraphAnalysisState.FAILED, reason_codes=("error",))
    merged = merge_analysis_statuses([{"x": complete, "y": complete}, {"x": limited}, {"x": failed}])
    assert merged["x"].status is GraphAnalysisState.FAILED
    assert merged["x"].reason_codes == ("agent_budget", "error")
    assert merged["x"].observed == {"edges": 5}
    assert merged["y"] == complete
    assert merge_analysis_statuses([]) == {}


def test_search_and_compliance_accept_the_returned_current_estate_id(estate):
    from starlette.testclient import TestClient

    from agent_bom.api.server import app
    from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

    record(estate, 8, "repo-a", "langchain-package")
    enable_trusted_proxy_env()
    try:
        with TestClient(app, headers=proxy_headers(tenant="history-tenant")) as client:
            current_id = client.get("/v1/graph", params={"limit": 10}).json()["scan_id"]
            assert current_id.startswith("current-estate:")
            found = client.get("/v1/graph/search", params={"q": "langchain", "scan_id": current_id})
            assert found.status_code == 200, found.text
            assert [node["id"] for node in found.json()["results"]] == ["langchain-package"]
            assert found.json()["filters"]["scan_id"] == current_id
            compliance = client.get("/v1/graph/compliance", params={"scan_id": current_id})
            assert compliance.status_code == 200, compliance.text
        with TestClient(app, headers=proxy_headers(tenant="other-tenant")) as other:
            # Another tenant replaying the id reads only its own (empty) estate.
            foreign = other.get("/v1/graph/search", params={"q": "langchain", "scan_id": current_id})
            assert foreign.status_code in {200, 404}, foreign.text
            assert "langchain-package" not in foreign.text
    finally:
        disable_trusted_proxy_env()


@pytest.mark.parametrize("reader", ["snapshot_attack_paths", "snapshot_queue_page", "snapshot_cross_vendor_page"])
@pytest.mark.parametrize("explicit_generation", [False, True])
def test_current_estate_path_indexes_follow_the_resolved_generation(estate, reader, explicit_generation):
    from agent_bom.api.current_graph import CurrentGraphStore
    from tests.test_graph_cross_vendor_queue import _graph

    scan = record(estate, 8, "repo-paths", tenant="history-tenant")
    graph = _graph("history-tenant")
    graph.scan_id = scan
    estate[1].save_graph(graph)
    current_store = CurrentGraphStore(estate[1], estate[0])
    generation = current_store.latest_snapshot_id(tenant_id="history-tenant")
    args = {"tenant_id": "history-tenant", "scan_id": generation if explicit_generation else ""}
    if reader != "snapshot_attack_paths":
        args.update(offset=0, limit=10)
    page = getattr(current_store, reader)(**args)
    assert page is not None, "the index must read the current projection, not the backing scan store"
    assert page.scan_id == generation
    assert len(page.paths) == (2 if reader == "snapshot_cross_vendor_page" else 4)
    historical = getattr(current_store, reader)(**{**args, "scan_id": scan})
    assert historical is not None and historical.scan_id == scan
