"""Demo-estate bootstrap: the seed contract, its idempotence and the catalog.

Every seeded test here boots its own estate (``demo_estate_client``). The
lifecycle, rollover and live-feed suites sit in sibling modules so the shard
planner can spread the per-test seeds across runners.
"""

from __future__ import annotations

import inspect
import os
from datetime import datetime, timedelta

import pytest
from starlette.testclient import TestClient

from agent_bom.demo_estate.showcase_graph import SHOWCASE_BASELINE_SCAN_ID
from tests._demo_estate_fixtures import VIEWER, _wait_for_current_graph


def test_demo_bootstrap_log_does_not_emit_raw_graph_owner_scan_id() -> None:
    """Keep the exact owner in the summary without copying it into logs."""
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate

    source = inspect.getsource(maybe_bootstrap_demo_estate)
    assert "graph_owner_scan_id=%s" not in source
    assert "graph_owner_scan_id_present=%s" in source


def test_demo_estate_bootstrap_seeds_honest_posture_trajectory(
    demo_estate_client: TestClient,
) -> None:
    """Recorded stages move through the live trend path and end at the headline."""
    from agent_bom.demo_estate.showcase_graph import (
        SHOWCASE_BASELINE_CREATED_AT,
        SHOWCASE_CURRENT_CREATED_AT,
        SHOWCASE_SCAN_ID,
    )

    response = demo_estate_client.get("/v1/trends", headers=VIEWER, params={"limit": 30})

    assert response.status_code == 200, response.text
    payload = response.json()
    points = payload["data_points"]
    assert payload["count"] >= 5
    current = points[0]
    assert current["scan_id"] == SHOWCASE_SCAN_ID
    assert current["timestamp"] == SHOWCASE_CURRENT_CREATED_AT
    baseline = next(point for point in points if point["scan_id"] == SHOWCASE_BASELINE_SCAN_ID)
    assert baseline["timestamp"] == SHOWCASE_BASELINE_CREATED_AT
    assert all(point["issues"] and point["issues"]["basis"] == "issue_groups" for point in points)
    # Movement comes from the recorded evidence, not a constant series.
    assert len({(point["issues"]["critical"], point["issues"]["high"]) for point in points}) >= 4
    comparable = [point["comparison"] for point in points if point["comparison"]["status"] == "comparable"]
    assert len(comparable) >= 4
    assert sum(item["new_findings"] for item in comparable) > 0
    assert sum(item["no_longer_detected"] for item in comparable) > 0
    assert current["verified_remediations"] is None
    # The latest point is the headline the posture endpoints serve right now.
    counts = demo_estate_client.get("/v1/posture/counts", headers=VIEWER).json()["issues"]
    for key in ("critical", "high", "medium", "low", "total"):
        assert current["issues"][key] == counts[key], key
    posture = demo_estate_client.get("/v1/posture", headers=VIEWER).json()
    assert (current["posture_grade"], current["posture_score"]) == (posture["grade"], posture["score"])
    findings = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"status": "suppressed", "limit": 1}).json()
    assert findings.get("total", 0) == 0, "suppressed history findings were fixed before the current scan"

    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate

    assert maybe_bootstrap_demo_estate().get("reason") == "demo_jobs_present"
    repeated = demo_estate_client.get("/v1/trends", headers=VIEWER, params={"limit": 30}).json()
    assert repeated["count"] == payload["count"]


def test_demo_estate_bootstrap_validates_versioned_enterprise_contract(
    demo_estate_client: TestClient,
) -> None:
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate
    from agent_bom.demo_estate.enterprise import ENTERPRISE_SCHEMA_VERSION

    summary = maybe_bootstrap_demo_estate()
    contract = summary.get("enterprise_contract") or {}

    assert contract["schema_version"] == ENTERPRISE_SCHEMA_VERSION
    # The demo now boots the narrative estate composed into a generated
    # population, so the id gains its suffix and the floors move from
    # "the story exists" to "the story sits inside an enterprise". The old
    # values (20 assets, 15 observations) passed against an estate too small
    # to demonstrate correlation at all.
    assert contract["estate_id"] == "northstar-health-ai-v1-composed"
    assert contract["assets"] >= 2000
    assert contract["observations"] >= 6000
    assert contract["snapshots"] == 3
    assert contract["partial_sources"] == ["gcp_audit"]
    assert len(contract["content_hash"]) == 64


def test_demo_estate_status_never_presents_a_non_demo_snapshot(
    demo_estate_client: TestClient,
) -> None:
    """A non-showcase snapshot in the demo store blocks the demo instead of being shown as sample data."""
    from agent_bom.api import stores as api_stores
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate
    from agent_bom.demo_estate.showcase_graph import (
        SHOWCASE_CURRENT_CREATED_AT,
        SHOWCASE_TENANT,
    )
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.types import EntityType

    operator_graph = UnifiedGraph(
        scan_id="operator-scan",
        tenant_id=SHOWCASE_TENANT,
        created_at=(datetime.fromisoformat(SHOWCASE_CURRENT_CREATED_AT) + timedelta(days=1)).isoformat(),
    )
    operator_graph.add_node(
        UnifiedNode(
            id="agent:operator",
            entity_type=EntityType.AGENT,
            label="Operator scan",
        )
    )
    api_stores._get_graph_store().save_graph(operator_graph)
    summary = maybe_bootstrap_demo_estate()
    assert summary["seeded"] is False
    assert summary["blocked"] == "non_demo_snapshot_present"

    response = demo_estate_client.get("/v1/demo-estate/status", headers=VIEWER)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["showcase_available"] is True
    assert payload["graph_owner_scan_id"] is None
    assert payload["graph_alignment"] == "blocked"
    assert payload["reason"] == "non_demo_snapshot_present"
    assert "operator-scan" not in response.text


def test_showcase_catalog_needs_no_ephemeral_key_and_is_tenant_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_bom.api.connection_crypto import CONNECTIONS_KEY_ENV
    from agent_bom.api.connection_store import InMemoryConnectionStore
    from agent_bom.api.cost_store import InMemoryCostStore
    from agent_bom.api.source_store import InMemorySourceStore
    from agent_bom.demo_estate import showcase_catalog

    connection_store = InMemoryConnectionStore()
    source_store = InMemorySourceStore()
    cost_store = InMemoryCostStore()
    monkeypatch.delenv(CONNECTIONS_KEY_ENV, raising=False)
    monkeypatch.setattr(showcase_catalog, "get_connection_store", lambda: connection_store)
    monkeypatch.setattr(showcase_catalog, "_get_source_store", lambda: source_store)
    monkeypatch.setattr(showcase_catalog, "get_cost_store", lambda: cost_store)

    first = showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="tenant-a")
    second = showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="tenant-a")
    other = showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="tenant-b")

    assert first == {"seeded": True, "connections": 3, "sources": 2, "cost_samples": 1}
    assert second.get("seeded") is False and second.get("reason") == "catalog_present"
    assert other.get("seeded") is True
    assert CONNECTIONS_KEY_ENV not in os.environ
    tenant_a_connections = connection_store.list_for_tenant("tenant-a")
    tenant_b_connections = connection_store.list_for_tenant("tenant-b")
    assert len(tenant_a_connections) == len(tenant_b_connections) == 3
    assert {row.id for row in tenant_a_connections}.isdisjoint({row.id for row in tenant_b_connections})
    assert all(not row.external_id_encrypted for row in tenant_a_connections)
    assert len(source_store.list_all("tenant-a")) == 2
    assert len(source_store.list_all("tenant-b")) == 2
    assert len(cost_store.list_records("tenant-a")) == 1
    assert len(cost_store.list_records("tenant-b")) == 1


def test_showcase_catalog_retry_heals_partial_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.connection_store import InMemoryConnectionStore
    from agent_bom.api.cost_store import InMemoryCostStore
    from agent_bom.api.source_store import InMemorySourceStore
    from agent_bom.demo_estate import showcase_catalog

    connection_store = InMemoryConnectionStore()
    source_store = InMemorySourceStore()
    cost_store = InMemoryCostStore()
    original_put = source_store.put
    should_fail = True

    def flaky_put(source, **kwargs) -> None:
        nonlocal should_fail
        if should_fail:
            should_fail = False
            raise RuntimeError("injected source failure")
        original_put(source, **kwargs)

    monkeypatch.setattr(showcase_catalog, "get_connection_store", lambda: connection_store)
    monkeypatch.setattr(showcase_catalog, "_get_source_store", lambda: source_store)
    monkeypatch.setattr(showcase_catalog, "get_cost_store", lambda: cost_store)
    monkeypatch.setattr(source_store, "put", flaky_put)

    with pytest.raises(RuntimeError, match="injected source failure"):
        showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="retry-tenant")

    summary = showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="retry-tenant")
    assert summary == {"seeded": True, "connections": 0, "sources": 2, "cost_samples": 1}
    assert len(connection_store.list_for_tenant("retry-tenant")) == 3
    assert len(source_store.list_all("retry-tenant")) == 2
    assert len(cost_store.list_records("retry-tenant")) == 1


def test_demo_estate_bootstrap_is_idempotent(demo_estate_client: TestClient) -> None:
    first = demo_estate_client.get("/v1/jobs", headers=VIEWER).json()
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate

    second = maybe_bootstrap_demo_estate()
    assert second.get("reason") == "demo_jobs_present"
    again = demo_estate_client.get("/v1/jobs", headers=VIEWER).json()
    assert again.get("total") == first.get("total")


def test_demo_estate_reseeds_when_marker_job_has_no_findings(
    demo_estate_client: TestClient,
) -> None:
    """A demo-tagged job with empty findings must not block reseed (empty demo)."""
    import uuid

    from agent_bom.api import stores as api_stores
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.pipeline import _now
    from agent_bom.api.store import DEMO_ESTATE_TRIGGERED_BY
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    store = api_stores._get_store()
    for job in list(store.list_all(tenant_id=SHOWCASE_TENANT)):
        store.delete(job.job_id, tenant_id=SHOWCASE_TENANT)

    empty = ScanJob(
        job_id=str(uuid.uuid4()),
        tenant_id=SHOWCASE_TENANT,
        triggered_by=DEMO_ESTATE_TRIGGERED_BY,
        created_at=_now(),
        request=ScanRequest(offline=True),
    )
    empty.status = JobStatus.DONE
    empty.completed_at = _now()
    empty.result = {"scan_sources": ["demo", "demo-estate"], "findings": [], "agents": []}
    store.put(empty)

    before_total = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1}).json()
    assert before_total.get("total", 0) == 0

    summary = maybe_bootstrap_demo_estate()
    assert summary.get("seeded") is True, summary
    assert (summary.get("findings") or 0) >= 1

    after = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1}).json()
    assert after.get("total", 0) > 0
    _wait_for_current_graph(demo_estate_client)
