"""One attack-path count: the correlation receipt and ``/v1/graph`` agree for the same snapshot."""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as api_stores
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.server import app, configure_api
from agent_bom.api.store import InMemoryJobStore
from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode
from agent_bom.graph.analysis import GraphAnalysisState, GraphAnalysisStatus
from agent_bom.graph.attack_path_counts import attack_paths_summary

DIGEST = "sha256:" + "ab12cd34" * 8


def _graph(scan_id: str) -> UnifiedGraph:
    return UnifiedGraph(scan_id=scan_id, tenant_id="default", created_at=datetime.now(timezone.utc).isoformat())


def _image_scan() -> UnifiedGraph:
    graph = _graph("image-scan")
    graph.add_node(
        UnifiedNode(
            id="image:api",
            entity_type=EntityType.CONTAINER,
            label="api",
            attributes={"image_digest": DIGEST},
            data_sources=["cyclonedx_sbom"],
        )
    )
    graph.add_node(
        UnifiedNode(id="pkg:pillow", entity_type=EntityType.PACKAGE, label="pillow", attributes={"purl": "pkg:pypi/pillow@9.0.0"})
    )
    graph.add_node(
        UnifiedNode(
            id="vuln:cve",
            entity_type=EntityType.VULNERABILITY,
            label="CVE-2023-4863",
            severity="high",
            attributes={"canonical_id": "CVE-2023-4863"},
        )
    )
    for source, target, rel in (
        ("image:api", "pkg:pillow", RelationshipType.CONTAINS),
        ("pkg:pillow", "vuln:cve", RelationshipType.VULNERABLE_TO),
    ):
        graph.add_edge(
            UnifiedEdge(
                source=source,
                target=target,
                relationship=rel,
                source_scan_id="image-scan",
                evidence={"source": "cyclonedx_sbom", "tier": "static_scan"},
            )
        )
    return graph


def _iac_scan() -> UnifiedGraph:
    graph = _graph("iac-scan")
    graph.add_node(
        UnifiedNode(
            id="workload:api",
            entity_type=EntityType.CONTAINER,
            label="api deployment",
            attributes={"image_digest": DIGEST},
            data_sources=["kubernetes_iac"],
        )
    )
    return graph


@pytest.fixture
def client(tmp_path, monkeypatch):
    store = SQLiteGraphStore(tmp_path / "graph.db")
    store.save_graph(_image_scan())
    store.save_graph(_iac_scan())
    monkeypatch.setattr(api_stores, "_graph_store", store)
    monkeypatch.setattr(api_stores, "_store", InMemoryJobStore())
    configure_api(api_key=None, allow_unauthenticated=True)
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        configure_api(api_key=None)


def test_receipt_and_graph_report_the_same_retained_paths(client, monkeypatch) -> None:
    from agent_bom.graph import snapshot_paths

    derive = snapshot_paths.materialize_snapshot_paths
    calls: list[str] = []

    def counted(graph):
        calls.append(graph.scan_id)
        return derive(graph)

    monkeypatch.setattr(snapshot_paths, "materialize_snapshot_paths", counted)
    created = client.post(
        "/v1/graph/correlations",
        headers={"Idempotency-Key": "idem-path-count"},
        json={"name": "count", "scan_ids": ["image-scan", "iac-scan"], "max_age_hours": 168},
    ).json()
    deadline, status = time.monotonic() + 5, created
    while status["status"] not in {"complete", "failed"} and time.monotonic() < deadline:
        time.sleep(0.02)
        status = client.get(f"/v1/graph/correlations/{created['correlation_id']}").json()
    assert status["status"] == "complete", status
    # Paths are derived once per run: the receipt counts the rows the store indexes.
    assert calls == [created["correlation_id"]]

    output = status["result_manifest"]["output"]
    receipt = output["attack_paths"]
    assert receipt["retained_count"] >= 1
    assert output["attack_path_count"] == receipt["retained_count"]
    assert receipt["assessed_count"] >= receipt["retained_count"]

    for params in ({}, {"limit": 5}, {"view": "summary"}):
        response = client.get("/v1/graph", params={"scan": created["correlation_id"], **params})
        assert response.status_code == 200, response.text
        stats = response.json()["stats"]
        assert stats["attack_paths"]["retained_count"] == receipt["retained_count"], params
        assert stats["attack_path_count"] == receipt["retained_count"], params
        assert stats["attack_paths"]["assessed_count"] == receipt["assessed_count"], params


def test_summary_counts_fusion_and_derived_candidates() -> None:
    status = {
        "attack_path_fusion": GraphAnalysisStatus(GraphAnalysisState.COMPLETE, observed={"candidate_path_count": 4}),
        "component_paths": GraphAnalysisStatus(
            GraphAnalysisState.COMPLETE, observed={"paths": 3, "vex_excluded": 1, "unlikely_excluded": 2}
        ),
    }
    assert attack_paths_summary(retained_count=5, basis="derived_graph_paths", analysis_status=status) == {
        "retained_count": 5,
        "assessed_count": 10,
        "basis": "derived_graph_paths",
    }
    # Nothing recorded: assessed is the retained set, never a guess.
    assert attack_paths_summary(retained_count=2, basis="persisted_graph_paths", analysis_status={})["assessed_count"] == 2


def test_client_isolates_completed_jobs_before_startup(tmp_path, monkeypatch):
    """Inherited scan jobs must not start a current-estate derivation in this fixture."""
    from agent_bom.api import current_graph_prewarm
    from tests.api.test_scan_job_sla_history import job

    previous = InMemoryJobStore()
    previous.put(job(8, tenant="default", target="previous-target", findings=[]))
    monkeypatch.setattr(api_stores, "_store", previous)
    entered, release = threading.Event(), threading.Event()
    recent_tenants = current_graph_prewarm._recent_tenants

    def delayed(job_store):
        entered.set()
        assert release.wait(10)
        return recent_tenants(job_store)

    monkeypatch.setattr(current_graph_prewarm, "_recent_tenants", delayed)
    monkeypatch.setenv("AGENT_BOM_CURRENT_GRAPH_PREWARM", "1")
    with contextmanager(client.__wrapped__)(tmp_path, monkeypatch) as api:

        class OrderedClient:
            def post(self, *args, **kwargs):
                # The counter is installed now. Complete startup before posting
                # so any inherited tenant produces the CI failure deterministically.
                release.set()
                for thread in threading.enumerate():
                    if thread.name == "current-graph-prewarm":
                        thread.join(5)
                        assert not thread.is_alive()
                return api.post(*args, **kwargs)

            def get(self, *args, **kwargs):
                return api.get(*args, **kwargs)

        try:
            assert entered.wait(5)
            test_receipt_and_graph_report_the_same_retained_paths(OrderedClient(), monkeypatch)
        finally:
            release.set()


def _ref(schema: dict) -> str:
    options = schema.get("anyOf") or [schema]
    return next(option["$ref"] for option in options if "$ref" in option).rsplit("/", 1)[-1]


def test_openapi_types_the_count_on_both_payloads() -> None:
    schemas = app.openapi()["components"]["schemas"]
    counts = schemas["GraphAttackPathCounts"]
    assert set(counts["required"]) == {"retained_count", "assessed_count", "basis"}
    assert counts["properties"]["retained_count"]["type"] == counts["properties"]["assessed_count"]["type"] == "integer"
    assert counts["properties"]["basis"]["enum"] == ["derived_graph_paths", "persisted_graph_paths", "served_graph_paths"]

    stats = schemas[_ref(schemas["GraphPageResponse"]["properties"]["stats"])]
    assert _ref(stats["properties"]["attack_paths"]) == "GraphAttackPathCounts"
    manifest = schemas[_ref(schemas["GraphCorrelationRunResponse"]["properties"]["result_manifest"])]
    output = schemas[_ref(manifest["properties"]["output"])]
    assert _ref(output["properties"]["attack_paths"]) == "GraphAttackPathCounts"
