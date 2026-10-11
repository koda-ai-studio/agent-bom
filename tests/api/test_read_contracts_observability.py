"""Live-body contract for the runtime, cost and adoption observability reads."""

from __future__ import annotations

from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api.read_models import observability as obs
from tests.auth_helpers import proxy_headers
from tests.test_api_read_contracts import _contract_violations, empty_estate_client  # noqa: F401
from tests.test_demo_estate_bootstrap import demo_estate_client  # noqa: F401

TYPED_READS: dict[str, type[obs.ReadResponse]] = {
    "/v1/traces/connectors": obs.TraceConnectorsResponse,
    "/v1/runtime/sessions": obs.RuntimeSessionsResponse,
    "/v1/runtime/observations": obs.RuntimeObservationsResponse,
    "/v1/runtime/trace-explorer": obs.RuntimeTraceExplorerResponse,
    "/v1/runtime/approval-queue": obs.RuntimeApprovalQueueResponse,
    "/v1/runtime/sessions/{session_id}/observations": obs.RuntimeSessionObservationsResponse,
    "/v1/observability/costs": obs.ObservabilityCostsResponse,
    "/v1/observability/costs/budget": obs.ObservabilityCostBudgetResponse,
    "/v1/observability/costs/forecast": obs.ObservabilityCostForecastResponse,
    "/v1/observability/anomalies": obs.ObservabilityAnomaliesResponse,
    "/v1/observability/adoption": obs.ObservabilityAdoptionResponse,
}

_LIST_READS = [path for path in TYPED_READS if "{" not in path and path != "/v1/observability/adoption"]
_ADMIN = proxy_headers(role="admin", tenant="contract-empty")


def _check(client: TestClient, path: str, headers: dict[str, str], model: type[obs.ReadResponse] | None = None) -> list[str]:
    response = client.get(path, headers=headers)
    if response.status_code != 200:
        return [f"{path}: HTTP {response.status_code} {response.text[:200]}"]
    return _contract_violations(path, response.json(), model or TYPED_READS[path.split("?")[0]])


def test_observability_reads_document_their_models_in_openapi() -> None:
    from agent_bom.api.server import app

    app.openapi_schema = None
    schema = app.openapi()
    paths = schema["paths"]
    documented = {path: paths[path]["get"]["responses"]["200"]["content"]["application/json"]["schema"] for path in TYPED_READS}
    assert documented == {path: {"$ref": f"#/components/schemas/{model.__name__}"} for path, model in TYPED_READS.items()}
    assert {model.__name__ for model in TYPED_READS.values()} <= set(schema["components"]["schemas"])


def test_seeded_observability_bodies_match_documented_models(demo_estate_client: TestClient) -> None:  # noqa: F811
    problems: list[str] = []
    for path in [*_LIST_READS, "/v1/observability/costs?tag=team"]:
        problems.extend(_check(demo_estate_client, path, {}))
    explorer = demo_estate_client.get("/v1/runtime/trace-explorer").json()
    queue = demo_estate_client.get("/v1/runtime/approval-queue").json()
    costs = demo_estate_client.get("/v1/observability/costs?tag=team").json()
    assert not problems, "\n".join(problems)
    assert explorer["span_count"] > 0 and queue["count"] > 0
    assert costs["total_calls"] > 0 and costs["by_agent"] and costs["tag_rollup"]["by_tag"]


def test_adoption_summary_requires_config_permission_in_the_demo(demo_estate_client: TestClient) -> None:  # noqa: F811
    assert demo_estate_client.get("/v1/observability/adoption").status_code == 403


def test_empty_observability_bodies_match_documented_models(empty_estate_client: TestClient) -> None:  # noqa: F811
    problems: list[str] = []
    for path in [*_LIST_READS, "/v1/observability/adoption"]:
        problems.extend(_check(empty_estate_client, path, _ADMIN))
    assert not problems, "\n".join(problems)
    missing = empty_estate_client.get("/v1/runtime/sessions/absent/observations", headers=_ADMIN)
    assert missing.status_code == 404


@pytest.fixture()
def _adoption_enabled(tmp_path: Any):
    from agent_bom.db.adoption_events import AdoptionEventStore, get_adoption_event_store, set_adoption_event_store

    original = get_adoption_event_store()
    set_adoption_event_store(AdoptionEventStore(tmp_path / "adoption.db", enabled=True))
    try:
        yield
    finally:
        set_adoption_event_store(original)


def test_populated_runtime_cost_and_adoption_bodies_match(empty_estate_client: TestClient, _adoption_enabled: None) -> None:  # noqa: F811
    client = empty_estate_client
    events = [
        {"session_id": "contract-session", "trace_id": "t-1", "agent_name": "billing-agent", "tool_name": "sql.query", "message": "ok"},
        {
            "session_id": "contract-session",
            "trace_id": "t-1",
            "agent_name": "billing-agent",
            "tool_name": "shell.exec",
            "verdict": "blocked",
            "severity": "high",
            "reason": "destructive command",
        },
    ]
    assert client.post("/v1/runtime/events", json=events, headers=_ADMIN).status_code == 202
    queue = client.get("/v1/runtime/approval-queue", headers=_ADMIN).json()
    assert queue["pending_count"] == 1
    item_id = queue["items"][0]["item_id"]
    decision = client.post(f"/v1/runtime/approval-queue/{item_id}/decision", json={"decision": "deny", "note": "n"}, headers=_ADMIN)
    assert decision.status_code == 200
    assert client.put("/v1/observability/costs/budget", json={"limit_usd": 10, "mode": "enforce"}, headers=_ADMIN).status_code == 200
    for event in ("scan_completed", "artifact_created"):
        body = {"event": event, "channel": "cli", "outcome": "complete", "artifact_type": "sarif"}
        assert client.post("/v1/observability/adoption/events", json=body, headers=_ADMIN).status_code == 202

    problems: list[str] = []
    for path in [*_LIST_READS, "/v1/observability/adoption", "/v1/runtime/approval-queue?status=denied"]:
        problems.extend(_check(client, path, _ADMIN))
    problems.extend(_check(client, "/v1/runtime/sessions/contract-session/observations", _ADMIN, obs.RuntimeSessionObservationsResponse))
    assert not problems, "\n".join(problems)

    sessions = client.get("/v1/runtime/sessions", headers=_ADMIN).json()
    explorer = client.get("/v1/runtime/trace-explorer", headers=_ADMIN).json()
    denied = client.get("/v1/runtime/approval-queue?status=denied", headers=_ADMIN).json()
    budget = client.get("/v1/observability/costs/budget", headers=_ADMIN).json()
    adoption = client.get("/v1/observability/adoption", headers=_ADMIN).json()
    assert sessions["count"] == 1 and sessions["sessions"][0]["observation_count"] == 2
    assert explorer["sessions"][0]["first_seen"] and explorer["sessions"][0]["spans"][0]["trace_id"] == "t-1"
    assert denied["items"][0]["status"] == "denied" and denied["items"][0]["decided_at"]
    assert budget["configured"] is True and budget["mode"] == "enforce"
    assert adoption["enabled"] is True and adoption["funnel"]["transitions"]["scan_to_artifact"]["rate"] == 1.0


def test_anomaly_rows_match_documented_models() -> None:
    from agent_bom.api.anomaly import detect_behavior_anomalies, detect_cost_anomalies, detect_temporal_cost_anomalies

    cost = detect_cost_anomalies({"a": 1.0, "b": 1.1, "c": 0.9, "d": 1.0, "e": 250.0}, z_threshold=3.0)
    behavior = detect_behavior_anomalies({"s1": 3, "s2": 4, "s3": 3, "s4": 4, "s5": 400}, z_threshold=3.0)
    series = [(f"2026-10-01T{hour:02d}:00:00+00:00", 1.0) for hour in range(10)] + [("2026-10-01T10:00:00+00:00", 80.0)]
    temporal = detect_temporal_cost_anomalies({"agent-x": series})
    assert cost and behavior and temporal
    body = {
        "schema_version": "observability.anomalies.v1",
        "tenant_id": "t",
        "z_threshold": 3.0,
        "cost_anomalies": cost,
        "temporal_cost_anomalies": temporal,
        "behavior_anomalies": behavior,
        "anomaly_count": len(cost) + len(behavior) + len(temporal),
    }
    assert _contract_violations("/v1/observability/anomalies", body, obs.ObservabilityAnomaliesResponse) == []
