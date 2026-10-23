"""Live-body contract for governance, inventory and operator read endpoints.

Every typed GET is exercised against the seeded demo estate and an empty
estate (seeded per-test where a list is empty by default), and each real JSON
body must validate against its documented model with undeclared keys forbidden
and an exact round-trip. Endpoints that need Snowflake run against a stubbed
miner so the real handler and serializer still produce the body.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

import pytest
from pydantic import BaseModel
from starlette.testclient import TestClient

from agent_bom.api.read_models import governance_a as ga
from agent_bom.api.read_models import governance_b as gb
from tests.auth_helpers import proxy_headers
from tests.test_api_read_contracts import _contract_violations, empty_estate_client  # noqa: F401
from tests.test_graph_correlation_api import correlation_client  # noqa: F401
from tests.test_graph_scenario_routes import _create, scenario_client  # noqa: F401
from tests.test_intel_lookup import VIEWER_HEADERS, intel_client, intel_db  # noqa: F401

TYPED_PATHS: dict[str, type[BaseModel]] = {
    "/v1/governance": ga.GovernanceReportResponse,
    "/v1/governance/findings": ga.GovernanceFindingsResponse,
    "/v1/cortex/telemetry": ga.CortexTelemetryResponse,
    "/v1/cortex/agents/{name}/telemetry": ga.CortexTelemetryResponse,
    "/v1/cortex/health": ga.CortexHealthResponse,
    "/v1/governance/blueprints": ga.GovernanceBlueprintsResponse,
    "/v1/governance/blueprints/{blueprint_id}": ga.GovernanceBlueprintDetailResponse,
    "/v1/governance/blueprints/{blueprint_id}/versions": ga.GovernanceBlueprintVersionsResponse,
    "/v1/governance/blueprints/{blueprint_id}/versions/{version}": ga.GovernanceBlueprintVersionResponse,
    "/v1/governance/blueprints/{blueprint_id}/diff": ga.GovernanceBlueprintDiffResponse,
    "/v1/runtime/blueprints": ga.RuntimeRoleBlueprintsResponse,
    "/v1/runtime/blueprints/{blueprint_id}": ga.RuntimeRoleBlueprintResponse,
    "/v1/runtime/blueprints/{blueprint_id}/drift": ga.RuntimeBlueprintDriftResponse,
    "/v1/datasets/{dataset_id}/versions": ga.DatasetVersionsResponse,
    "/v1/datasets/{dataset_id}/versions/{version_id}": ga.DatasetVersionResponse,
    "/v1/evaluations": ga.EvaluationRunsResponse,
    "/v1/evaluations/{evaluation_id}": ga.EvaluationRunResponse,
    "/v1/graph/correlations/{correlation_id}": ga.GraphCorrelationRunResponse,
    "/v1/graph/correlations/{correlation_id}/runtime-facts": ga.GraphCorrelationRuntimeFactsResponse,
    "/v1/graph/scenarios/{scenario_id}": ga.GraphScenarioDetailResponse,
    "/v1/graph/scenarios/{scenario_id}/comparison": ga.GraphScenarioComparisonResponse,
    "/v1/inventory/summary": gb.InventorySummaryResponse,
    "/v1/inventory/assets": gb.InventoryAssetsResponse,
    "/v1/inventory/assets/{asset_id}": gb.InventoryAssetDetailResponse,
    "/v1/posture/webhooks/outbox": gb.PostureWebhookOutboxResponse,
    "/v1/posture/webhooks/outbox/stats": gb.PostureWebhookOutboxStatsResponse,
    "/v1/sources/{source_id}": gb.SourceDetailResponse,
    "/v1/sources/{source_id}/jobs": gb.SourceJobsResponse,
    "/v1/ticketing/connections/{connection_id}": gb.TicketingConnectionDetailResponse,
    "/v1/ticketing/tickets": gb.TicketingTicketsResponse,
    "/v1/assets": gb.VulnerabilityAssetsResponse,
    "/v1/assets/stats": gb.VulnerabilityAssetStatsResponse,
    "/v1/estate/correlations": gb.EstateCorrelationsResponse,
    "/v1/intel/advisories/{advisory_id}": gb.IntelAdvisoryResponse,
    "/v1/mitre/coverage": gb.MitreCoverageResponse,
    "/v1/overview/score-config": gb.OverviewScoreConfigResponse,
    "/v1/plugins/status": gb.PluginRegistryStatusResponse,
    "/v1/self-posture": gb.SelfPostureResponse,
}

# Reads with no path parameter, exercised in both estates.
_LIST_READS: tuple[str, ...] = (
    "/v1/governance/blueprints",
    "/v1/runtime/blueprints",
    "/v1/evaluations",
    "/v1/inventory/summary",
    "/v1/inventory/assets",
    "/v1/ticketing/tickets",
    "/v1/assets",
    "/v1/assets/stats",
    "/v1/estate/correlations",
    "/v1/mitre/coverage",
    "/v1/overview/score-config",
    "/v1/plugins/status",
)

_EMPTY_TENANT = "contract-empty"


def _admin() -> dict[str, str]:
    return proxy_headers(role="admin", tenant=_EMPTY_TENANT)


def _check(client: TestClient, template: str, url: str, headers: dict[str, str], problems: list[str], **params: Any) -> dict[str, Any]:
    response = client.get(url, headers=headers, params=params or None)
    if response.status_code != 200:
        problems.append(f"{url}: HTTP {response.status_code} {response.text[:200]}")
        return {}
    body = response.json()
    problems.extend(_contract_violations(url, body, TYPED_PATHS[template]))
    return body


def _blueprint_reads(client: TestClient, headers: dict[str, str], problems: list[str]) -> int:
    listed = _check(client, "/v1/governance/blueprints", "/v1/governance/blueprints", headers, problems)
    checked = 0
    for blueprint in listed.get("blueprints", [])[:2]:
        bid = blueprint["blueprint_id"]
        _check(client, "/v1/governance/blueprints/{blueprint_id}", f"/v1/governance/blueprints/{bid}", headers, problems)
        versions = _check(
            client, "/v1/governance/blueprints/{blueprint_id}/versions", f"/v1/governance/blueprints/{bid}/versions", headers, problems
        )
        for version in versions.get("versions", [])[:1]:
            number = version["version"]
            _check(
                client,
                "/v1/governance/blueprints/{blueprint_id}/versions/{version}",
                f"/v1/governance/blueprints/{bid}/versions/{number}",
                headers,
                problems,
            )
            _check(
                client,
                "/v1/governance/blueprints/{blueprint_id}/diff",
                f"/v1/governance/blueprints/{bid}/diff",
                headers,
                problems,
                from_version=number,
                to_version=number,
            )
        checked += 1
    return checked


def _runtime_blueprint_reads(client: TestClient, headers: dict[str, str], problems: list[str]) -> int:
    listed = _check(client, "/v1/runtime/blueprints", "/v1/runtime/blueprints", headers, problems)
    blueprints = listed.get("blueprints", [])
    for blueprint in blueprints:
        bid = blueprint["blueprint_id"]
        _check(client, "/v1/runtime/blueprints/{blueprint_id}", f"/v1/runtime/blueprints/{bid}", headers, problems)
        _check(client, "/v1/runtime/blueprints/{blueprint_id}/drift", f"/v1/runtime/blueprints/{bid}/drift", headers, problems)
    return len(blueprints)


def _inventory_detail_reads(client: TestClient, headers: dict[str, str], problems: list[str]) -> int:
    listed = _check(client, "/v1/inventory/assets", "/v1/inventory/assets", headers, problems, limit=3)
    assets = listed.get("assets", [])
    for asset in assets:
        _check(client, "/v1/inventory/assets/{asset_id}", f"/v1/inventory/assets/{asset['id']}", headers, problems)
    return len(assets)


def test_every_typed_governance_read_documents_its_model_in_openapi() -> None:
    from agent_bom.api.server import app

    app.openapi_schema = None
    paths = app.openapi()["paths"]
    documented = {path: paths[path]["get"]["responses"]["200"]["content"]["application/json"]["schema"] for path in TYPED_PATHS}
    assert documented == {path: {"$ref": f"#/components/schemas/{model.__name__}"} for path, model in TYPED_PATHS.items()}
    schemas = app.openapi()["components"]["schemas"]
    assert {model.__name__ for model in TYPED_PATHS.values()} <= set(schemas)


def test_seeded_demo_bodies_match_documented_models(demo_estate_client: TestClient) -> None:
    from agent_bom.api import stores as api_stores
    from agent_bom.api.models import ScanJob, ScanRequest

    problems: list[str] = []
    for path in _LIST_READS:
        _check(demo_estate_client, path, path, {}, problems)

    assert _blueprint_reads(demo_estate_client, {}, problems) > 0
    assert _runtime_blueprint_reads(demo_estate_client, {}, problems) > 0
    assert _inventory_detail_reads(demo_estate_client, {}, problems) > 0

    sources = demo_estate_client.get("/v1/sources").json()["sources"]
    assert sources, "demo estate seeds data sources"
    source = sources[0]
    api_stores._get_store().put(
        ScanJob(
            job_id="contract-source-job",
            tenant_id=source["tenant_id"],
            source_id=source["source_id"],
            triggered_by="contract-test",
            created_at=datetime.now(timezone.utc).isoformat(),
            request=ScanRequest(),
        )
    )
    _check(demo_estate_client, "/v1/sources/{source_id}", f"/v1/sources/{source['source_id']}", {}, problems)
    jobs = _check(demo_estate_client, "/v1/sources/{source_id}/jobs", f"/v1/sources/{source['source_id']}/jobs", {}, problems)
    assert jobs.get("count", 0) >= 1

    datasets = _check(demo_estate_client, "/v1/datasets/{dataset_id}/versions", "/v1/datasets/contract-ds/versions", {}, problems)
    assert datasets.get("versions") == []
    assert not problems, "\n".join(problems)


def test_demo_estate_operator_surfaces_answer_with_documented_errors(demo_estate_client: TestClient) -> None:
    statuses = {
        path: demo_estate_client.get(path).status_code
        for path in (
            "/v1/governance",
            "/v1/governance/findings",
            "/v1/self-posture",
            "/v1/cortex/telemetry",
            "/v1/cortex/health",
            "/v1/cortex/agents/demo/telemetry",
            "/v1/posture/webhooks/outbox",
            "/v1/posture/webhooks/outbox/stats",
        )
    }
    assert statuses == {
        # The public demo hides operator integrations and self-posture.
        "/v1/governance": 404,
        "/v1/governance/findings": 404,
        "/v1/self-posture": 404,
        # Cortex telemetry needs a Snowflake account the demo does not configure.
        "/v1/cortex/telemetry": 400,
        "/v1/cortex/health": 400,
        "/v1/cortex/agents/demo/telemetry": 400,
        # The outbox is analyst-only; the demo's anonymous principal is a viewer.
        "/v1/posture/webhooks/outbox": 403,
        "/v1/posture/webhooks/outbox/stats": 403,
    }


def test_empty_estate_bodies_match_documented_models(empty_estate_client: TestClient) -> None:  # noqa: F811
    headers = _admin()
    problems: list[str] = []
    for path in (*_LIST_READS, "/v1/self-posture", "/v1/posture/webhooks/outbox", "/v1/posture/webhooks/outbox/stats"):
        _check(empty_estate_client, path, path, headers, problems)
    assert _blueprint_reads(empty_estate_client, headers, problems) == 0
    _inventory_detail_reads(empty_estate_client, headers, problems)
    assert empty_estate_client.get("/v1/sources/missing-source", headers=headers).status_code == 404
    assert not problems, "\n".join(problems)


def test_empty_estate_seeded_records_match_documented_models(
    empty_estate_client: TestClient,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    from agent_bom import asset_tracker
    from agent_bom.api.routes.posture_streaming import set_posture_webhook_outbox
    from agent_bom.posture_streaming import PostureEvent, WebhookDestination, WebhookOutbox
    from agent_bom.ticketing.connection_store import TicketLink, get_ticketing_store
    from agent_bom.ticketing.models import TicketingConnectionRecord

    headers = _admin()
    problems: list[str] = []
    now = datetime.now(timezone.utc).isoformat()

    seeded = empty_estate_client.post("/v1/governance/blueprints/seed", headers=headers)
    assert seeded.status_code == 200, seeded.text
    assert _blueprint_reads(empty_estate_client, headers, problems) > 0
    assert _runtime_blueprint_reads(empty_estate_client, headers, problems) > 0

    created = empty_estate_client.post(
        "/v1/datasets/contract-ds/versions",
        headers=headers,
        json={"version_id": "v1", "artifact_uri": "s3://bucket/train.parquet", "digest": "abc123", "metadata": {"rows": 10}},
    )
    assert created.status_code == 201, created.text
    _check(empty_estate_client, "/v1/datasets/{dataset_id}/versions", "/v1/datasets/contract-ds/versions", headers, problems)
    _check(
        empty_estate_client,
        "/v1/datasets/{dataset_id}/versions/{version_id}",
        "/v1/datasets/contract-ds/versions/v1",
        headers,
        problems,
    )

    evaluation = empty_estate_client.post(
        "/v1/evaluations",
        headers=headers,
        json={
            "evaluation_id": "contract-eval",
            "name": "contract",
            "dataset_id": "contract-ds",
            "dataset_version_id": "v1",
            "scores": {"accuracy": 0.9, "passes": 3},
            "cases": [{"case_id": "c1", "scores": {"accuracy": 1.0}}],
        },
    )
    assert evaluation.status_code == 201, evaluation.text
    listed = _check(empty_estate_client, "/v1/evaluations", "/v1/evaluations", headers, problems)
    assert listed.get("count") == 1
    _check(empty_estate_client, "/v1/evaluations/{evaluation_id}", "/v1/evaluations/contract-eval", headers, problems)

    store = get_ticketing_store()
    store.put_connection(
        TicketingConnectionRecord(
            id="contract-conn",
            tenant_id=_EMPTY_TENANT,
            provider="jira",
            transport="rest",
            auth_method="api_token",
            display_name="Contract Jira",
            endpoint="https://jira.example.com",
            secret_encrypted="ciphertext",
            auth_params={"project": "SEC"},
            status="active",
            created_at=now,
            updated_at=now,
        )
    )
    store.claim_ticket_link(
        TicketLink(
            id="contract-ticket",
            tenant_id=_EMPTY_TENANT,
            connection_id="contract-conn",
            dedupe_key="finding-1",
            provider="jira",
            external_id="10001",
            key="SEC-1",
            url="https://jira.example.com/browse/SEC-1",
            created_at=now,
            updated_at=now,
        )
    )
    _check(
        empty_estate_client,
        "/v1/ticketing/connections/{connection_id}",
        "/v1/ticketing/connections/contract-conn",
        headers,
        problems,
    )
    tickets = _check(empty_estate_client, "/v1/ticketing/tickets", "/v1/ticketing/tickets", headers, problems)
    assert tickets.get("count") == 1

    monkeypatch.setattr(asset_tracker, "DEFAULT_DB_PATH", tmp_path / "assets.db")
    with asset_tracker.AssetTracker(tenant_id=_EMPTY_TENANT) as tracker:
        tracker.record_scan(
            {
                "blast_radius": [
                    {"vulnerability_id": "CVE-2026-0001", "package": "alpha", "ecosystem": "pypi", "severity": "critical"},
                    {"vulnerability_id": "CVE-2026-0002", "package": "beta", "ecosystem": "npm", "severity": "high"},
                ]
            }
        )
        tracker.record_scan(
            {"blast_radius": [{"vulnerability_id": "CVE-2026-0001", "package": "alpha", "ecosystem": "pypi", "severity": "critical"}]}
        )
    assets = _check(empty_estate_client, "/v1/assets", "/v1/assets", headers, problems)
    assert assets.get("count") == 2 and assets.get("mttr_days") is not None
    _check(empty_estate_client, "/v1/assets/stats", "/v1/assets/stats", headers, problems)

    outbox = WebhookOutbox(tmp_path / "outbox.db")
    outbox.enqueue(
        PostureEvent(event_type="posture.contract", tenant_id=_EMPTY_TENANT, source="contract", payload={"score": 1}),
        WebhookDestination(
            destination_id="contract-dest",
            tenant_id=_EMPTY_TENANT,
            url="https://hooks.example.com/agent-bom",
            signing_secret="contract-secret",
        ),
    )
    set_posture_webhook_outbox(outbox)
    try:
        rows = _check(empty_estate_client, "/v1/posture/webhooks/outbox", "/v1/posture/webhooks/outbox", headers, problems)
        assert rows.get("count") == 1
        _check(empty_estate_client, "/v1/posture/webhooks/outbox/stats", "/v1/posture/webhooks/outbox/stats", headers, problems)
    finally:
        set_posture_webhook_outbox(None)
    assert not problems, "\n".join(problems)


def _governance_report() -> Any:
    from agent_bom.governance import (
        AccessRecord,
        AgentUsageRecord,
        DataClassification,
        GovernanceCategory,
        GovernanceFinding,
        GovernanceReport,
        GovernanceSeverity,
        PrivilegeGrant,
    )

    return GovernanceReport(
        account="contract-account",
        access_records=[
            AccessRecord(
                query_id="q1",
                user_name="analyst",
                role_name="ANALYST",
                query_start="2026-10-01T00:00:00Z",
                object_name="DB.SCHEMA.PATIENTS",
                object_type="TABLE",
                columns=["SSN"],
                operation="READ",
            )
        ],
        privilege_grants=[
            PrivilegeGrant(
                grantee="AGENT_ROLE",
                grantee_type="ROLE",
                privilege="OWNERSHIP",
                granted_on="TABLE",
                object_name="DB.SCHEMA.PATIENTS",
                is_elevated=True,
            )
        ],
        data_classifications=[
            DataClassification(object_name="DB.SCHEMA.PATIENTS", object_type="COLUMN", column_name="SSN", tag_name="PII")
        ],
        agent_usage=[AgentUsageRecord(agent_name="claims-agent", total_tokens=1200, credits_used=0.25, tool_calls=3, status="SUCCESS")],
        findings=[
            GovernanceFinding(
                category=GovernanceCategory.PRIVILEGE,
                severity=GovernanceSeverity.HIGH,
                title="Agent role owns a PII table",
                description="Elevated ownership grant",
                agent_or_role="AGENT_ROLE",
                object_name="DB.SCHEMA.PATIENTS",
                details={"privilege": "OWNERSHIP"},
            ),
            GovernanceFinding(
                category=GovernanceCategory.ACCESS,
                severity=GovernanceSeverity.MEDIUM,
                title="Sensitive column read",
                description="SSN column read by analyst",
            ),
        ],
        warnings=["TAG_REFERENCES unavailable"],
    )


def test_snowflake_governance_bodies_match_documented_models(
    empty_estate_client: TestClient,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_bom.cloud import snowflake as snowflake_mod
    from agent_bom.governance import AgentUsageRecord, ObservabilityEvent

    headers = _admin()
    assert empty_estate_client.get("/v1/governance", headers=headers).status_code == 400
    assert empty_estate_client.get("/v1/cortex/health", headers=headers).status_code == 400

    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "contract-account")
    monkeypatch.setattr("agent_bom.cloud.discover_governance", lambda provider, days: _governance_report())

    class _Conn:
        def close(self) -> None:
            return None

    usage = [
        AgentUsageRecord(
            agent_name="claims-agent",
            start_time="2026-10-01T00:00:00+00:00",
            end_time="2026-10-01T00:00:02+00:00",
            total_tokens=900,
            credits_used=0.5,
            tool_calls=2,
            status="FAILED",
        ),
        AgentUsageRecord(agent_name="claims-agent", total_tokens=100, status="SUCCESS"),
    ]
    events = [
        ObservabilityEvent(
            event_id="e1", event_type="TOOL_CALL", agent_name="claims-agent", tool_name="lookup", duration_ms=40, trace_id="t1"
        ),
        ObservabilityEvent(event_id="e2", event_type="AGENT_RUN", agent_name="claims-agent", status="ERROR", trace_id="t1"),
    ]
    monkeypatch.setattr(snowflake_mod, "_get_connection", lambda *args, **kwargs: _Conn())
    monkeypatch.setattr(snowflake_mod, "_mine_cortex_agent_usage", lambda conn, days: (usage, ["usage view lagging"]))
    monkeypatch.setattr(snowflake_mod, "_mine_observability_events", lambda conn, days: (events, []))

    problems: list[str] = []
    report = _check(empty_estate_client, "/v1/governance", "/v1/governance", headers, problems)
    assert report.get("summary", {}).get("findings") == 2
    findings = _check(empty_estate_client, "/v1/governance/findings", "/v1/governance/findings", headers, problems, limit=1)
    assert findings.get("total") == 2 and findings.get("count") == 1
    _check(empty_estate_client, "/v1/governance/findings", "/v1/governance/findings", headers, problems, severity="high")
    telemetry = _check(empty_estate_client, "/v1/cortex/telemetry", "/v1/cortex/telemetry", headers, problems)
    assert telemetry.get("agents")
    _check(
        empty_estate_client,
        "/v1/cortex/agents/{name}/telemetry",
        "/v1/cortex/agents/claims-agent/telemetry",
        headers,
        problems,
    )
    health = _check(empty_estate_client, "/v1/cortex/health", "/v1/cortex/health", headers, problems)
    assert health.get("agents")
    assert not problems, "\n".join(problems)


def test_graph_correlation_bodies_match_documented_models(
    correlation_client: Any,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _store = correlation_client
    monkeypatch.setattr("agent_bom.config.RUNTIME_FACTS_HMAC_KEY", "correlation-runtime-facts-test-key-32-bytes")
    monkeypatch.setattr("agent_bom.config.RUNTIME_FACTS_HMAC_KEY_FILE", "")
    monkeypatch.setattr("agent_bom.config.RUNTIME_FACTS_KEY_ID", "contract-key")
    monkeypatch.setattr("agent_bom.config.RUNTIME_FACTS_TTL_SECONDS", 60)
    created = client.post(
        "/v1/graph/correlations",
        headers={"Idempotency-Key": "idem-contract"},
        json={"name": "contract", "scan_ids": ["repo-scan", "image-scan"], "max_age_hours": 168},
    ).json()
    url = f"/v1/graph/correlations/{created['correlation_id']}"
    problems: list[str] = []
    deadline = time.monotonic() + 5
    body = _check(client, "/v1/graph/correlations/{correlation_id}", url, {}, problems)
    while body.get("status") not in {"complete", "failed"} and time.monotonic() < deadline:
        time.sleep(0.01)
        body = _check(client, "/v1/graph/correlations/{correlation_id}", url, {}, problems)
    assert body.get("status") == "complete"
    _check(client, "/v1/graph/correlations/{correlation_id}/runtime-facts", f"{url}/runtime-facts", {}, problems)
    assert not problems, "\n".join(problems)


def test_graph_scenario_bodies_match_documented_models(scenario_client: Any) -> None:  # noqa: F811
    client, _graph_store, _scenario_store = scenario_client
    scenario = _create(
        client,
        changes=[
            {"kind": "add_node", "key": "waf", "entity_type": "policy", "label": "edge-waf", "assumption": "managed policy enabled"},
            {"kind": "patch_node", "node_id": "cloud:api", "patch": {"risk_score": 2.0}},
        ],
    )
    sid = scenario["scenario_id"]
    problems: list[str] = []
    _check(client, "/v1/graph/scenarios/{scenario_id}", f"/v1/graph/scenarios/{sid}", {}, problems)
    template = "/v1/graph/scenarios/{scenario_id}/comparison"
    available = _check(client, template, f"/v1/graph/scenarios/{sid}/comparison", {}, problems, scan_id="snapshot-old")
    assert available.get("available") is True
    mismatch = _check(client, template, f"/v1/graph/scenarios/{sid}/comparison", {}, problems, scan_id="snapshot-latest")
    assert mismatch.get("unavailable_reason") == "selected_snapshot_mismatch"
    assert not problems, "\n".join(problems)


def test_intel_advisory_bodies_match_documented_models(intel_client: TestClient) -> None:  # noqa: F811
    problems: list[str] = []
    template = "/v1/intel/advisories/{advisory_id}"
    found = _check(intel_client, template, "/v1/intel/advisories/CVE-2026-12345", VIEWER_HEADERS, problems)
    assert found.get("found") is True
    missing = _check(intel_client, template, "/v1/intel/advisories/CVE-2099-0001", VIEWER_HEADERS, problems)
    assert missing.get("found") is False and missing.get("advisory") is None
    assert not problems, "\n".join(problems)
