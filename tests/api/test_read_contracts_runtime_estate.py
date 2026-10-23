"""Live-body contract for the cloud, KSPM, gateway, runtime, connector, discovery, fleet and MCP-config reads."""

from __future__ import annotations

from urllib.parse import quote

from pydantic import BaseModel
from starlette.testclient import TestClient

from agent_bom.api.read_models import runtime_estate_a as a
from agent_bom.api.read_models import runtime_estate_b as b
from tests.auth_helpers import proxy_headers
from tests.test_api_read_contracts import _contract_violations, empty_estate_client  # noqa: F401

TYPED_READS: dict[str, type[BaseModel]] = {
    "/v1/cloud/{provider}/inventory": a.CloudInventorySummaryResponse,
    "/v1/cloud/{provider}/cis-benchmark": a.CloudCisBenchmarkResponse,
    "/v1/cloud/accounts/{account_ref}/summary": a.CloudAccountSummaryResponse,
    "/v1/cloud/side-scan": a.CloudSideScanListResponse,
    "/v1/cloud/side-scan/{execution_id}": a.CloudSideScanStatusResponse,
    "/v1/cloud/connections/{connection_id}": a.CloudConnectionDetailResponse,
    "/v1/kspm/clusters/posture": a.KspmClusterPostureResponse,
    "/v1/gateway/policies/{policy_id}": a.GatewayPolicyDetailResponse,
    "/v1/gateway/audit": a.GatewayAuditResponse,
    "/v1/gateway/upstreams/discovered": a.GatewayDiscoveredUpstreamsResponse,
    "/v1/gateway/stats": a.GatewayStatsResponse,
    "/v1/firewall/stats": a.FirewallStatsResponse,
    "/v1/runtime/production-index": b.RuntimeProductionIndexResponse,
    "/v1/shield/status": b.ShieldStatusResponse,
    "/v1/connectors/{name}/health": b.ConnectorHealthResponse,
    "/v1/malicious/check": b.MaliciousCheckResponse,
    "/v1/registry/{server_id}": b.RegistryServerDetailResponse,
    "/v1/scorecard/{ecosystem}/{package}": b.ScorecardLookupResponse,
    "/v1/agents/mesh": b.AgentMeshResponse,
    "/v1/agents/{agent_name}": b.AgentDetailResponse,
    "/v1/agents/{agent_name}/lifecycle": b.AgentLifecycleResponse,
    "/v1/fleet/endpoints": b.FleetEndpointsResponse,
    "/v1/fleet/endpoints/{endpoint_id}": b.FleetEndpointDetailResponse,
    "/v1/fleet/{agent_id}": b.FleetAgentDetailResponse,
    "/v1/mcp-config/assignments": b.McpConfigAssignmentsResponse,
    "/v1/mcp-config/assignments/{config_id}": b.McpConfigAssignmentDetailResponse,
}

_ADMIN = proxy_headers(role="admin", tenant="contract-empty")

# Requests that need no id; (template, concrete URL).
_STATIC: list[tuple[str, str]] = [
    ("/v1/cloud/{provider}/inventory", "/v1/cloud/aws/inventory"),
    ("/v1/cloud/{provider}/inventory", "/v1/cloud/all/inventory"),
    ("/v1/cloud/{provider}/cis-benchmark", "/v1/cloud/aws/cis-benchmark"),
    ("/v1/cloud/accounts/{account_ref}/summary", "/v1/cloud/accounts/aws:123456789012/summary"),
    ("/v1/cloud/accounts/{account_ref}/summary", "/v1/cloud/accounts/not-an-account/summary"),
    ("/v1/cloud/side-scan", "/v1/cloud/side-scan"),
    ("/v1/kspm/clusters/posture", "/v1/kspm/clusters/posture"),
    ("/v1/gateway/audit", "/v1/gateway/audit"),
    ("/v1/gateway/upstreams/discovered", "/v1/gateway/upstreams/discovered"),
    ("/v1/gateway/stats", "/v1/gateway/stats"),
    ("/v1/firewall/stats", "/v1/firewall/stats"),
    ("/v1/runtime/production-index", "/v1/runtime/production-index"),
    ("/v1/shield/status", "/v1/shield/status"),
    ("/v1/malicious/check", "/v1/malicious/check?name=reqeusts&ecosystem=pypi"),
    ("/v1/malicious/check", "/v1/malicious/check?name=lodash"),
    ("/v1/registry/{server_id}", "/v1/registry/@modelcontextprotocol/server-filesystem"),
    ("/v1/scorecard/{ecosystem}/{package}", "/v1/scorecard/pypi/requests"),
    ("/v1/agents/mesh", "/v1/agents/mesh"),
    ("/v1/fleet/endpoints", "/v1/fleet/endpoints"),
    ("/v1/mcp-config/assignments", "/v1/mcp-config/assignments"),
]

# The public demo serves reads as the anonymous viewer; these need scan/audit roles.
_DEMO_VIEWER_FORBIDDEN = {
    "/v1/cloud/aws/inventory",
    "/v1/cloud/all/inventory",
    "/v1/cloud/aws/cis-benchmark",
    "/v1/gateway/audit",
    "/v1/gateway/stats",
    "/v1/firewall/stats",
}


def _check(client: TestClient, template: str, url: str, headers: dict[str, str], problems: list[str]) -> dict | None:
    response = client.get(url, headers=headers)
    if response.status_code != 200:
        problems.append(f"{url}: HTTP {response.status_code} {response.text[:200]}")
        return None
    body = response.json()
    problems.extend(_contract_violations(url, body, TYPED_READS[template]))
    return body


def _check_id_routes(client: TestClient, headers: dict[str, str], problems: list[str]) -> list[str]:
    exercised: list[str] = []
    side_scans = client.get("/v1/cloud/side-scan", headers=headers).json()["executions"]
    for execution in side_scans[:3]:
        _check(client, "/v1/cloud/side-scan/{execution_id}", f"/v1/cloud/side-scan/{execution['execution_id']}", headers, problems)
        exercised.append("/v1/cloud/side-scan/{execution_id}")
    for connection in client.get("/v1/cloud/connections", headers=headers).json()["connections"][:3]:
        _check(client, "/v1/cloud/connections/{connection_id}", f"/v1/cloud/connections/{connection['id']}", headers, problems)
        exercised.append("/v1/cloud/connections/{connection_id}")
    for agent in client.get("/v1/fleet", headers=headers).json()["agents"][:3]:
        _check(client, "/v1/fleet/{agent_id}", f"/v1/fleet/{quote(agent['agent_id'], safe='')}", headers, problems)
        exercised.append("/v1/fleet/{agent_id}")
    for endpoint in client.get("/v1/fleet/endpoints", headers=headers).json()["endpoints"][:3]:
        _check(client, "/v1/fleet/endpoints/{endpoint_id}", f"/v1/fleet/endpoints/{endpoint['endpoint_id']}", headers, problems)
        exercised.append("/v1/fleet/endpoints/{endpoint_id}")
    for agent in client.get("/v1/agents", headers=headers).json()["agents"][:3]:
        ref = quote(str(agent.get("canonical_id") or agent.get("agent_id") or agent["name"]), safe="")
        _check(client, "/v1/agents/{agent_name}", f"/v1/agents/{ref}", headers, problems)
        _check(client, "/v1/agents/{agent_name}/lifecycle", f"/v1/agents/{ref}/lifecycle", headers, problems)
        exercised.extend(["/v1/agents/{agent_name}", "/v1/agents/{agent_name}/lifecycle"])
    return exercised


def test_every_typed_read_documents_its_model_in_openapi() -> None:
    from agent_bom.api.server import app

    app.openapi_schema = None
    paths = app.openapi()["paths"]
    documented = {path: paths[path]["get"]["responses"]["200"]["content"]["application/json"]["schema"] for path in TYPED_READS}
    assert documented == {path: {"$ref": f"#/components/schemas/{model.__name__}"} for path, model in TYPED_READS.items()}


def test_runtime_estate_models_have_unique_schema_names() -> None:
    from agent_bom.api.server import app

    app.openapi_schema = None
    schemas = app.openapi()["components"]["schemas"]
    missing = [model.__name__ for model in TYPED_READS.values() if model.__name__ not in schemas]
    assert not missing
    assert not [name for name in schemas if "__" in name]


def test_seeded_bodies_match_documented_models(demo_estate_client: TestClient) -> None:
    problems: list[str] = []
    for template, url in _STATIC:
        if url in _DEMO_VIEWER_FORBIDDEN:
            assert demo_estate_client.get(url).status_code == 403, url
            continue
        _check(demo_estate_client, template, url, {}, problems)
    exercised = _check_id_routes(demo_estate_client, {}, problems)
    assert not problems, "\n".join(problems)
    assert {
        "/v1/cloud/side-scan/{execution_id}",
        "/v1/cloud/connections/{connection_id}",
        "/v1/fleet/{agent_id}",
    } <= set(exercised)


def test_empty_estate_bodies_match_documented_models(empty_estate_client: TestClient) -> None:  # noqa: F811
    problems: list[str] = []
    for template, url in _STATIC:
        _check(empty_estate_client, template, url, _ADMIN, problems)
    _check_id_routes(empty_estate_client, _ADMIN, problems)
    assert not problems, "\n".join(problems)


def test_empty_estate_seeded_detail_reads_match_documented_models(empty_estate_client: TestClient) -> None:  # noqa: F811
    client = empty_estate_client
    problems: list[str] = []
    created = client.post(
        "/v1/gateway/policies",
        json={"name": "contract", "mode": "enforce", "rules": [{"id": "r1", "action": "block", "block_tools": ["run_shell"]}]},
        headers=_ADMIN,
    )
    assert created.status_code in (200, 201), created.text
    policy_id = created.json()["policy_id"]
    _check(client, "/v1/gateway/policies/{policy_id}", f"/v1/gateway/policies/{policy_id}", _ADMIN, problems)
    evaluated = client.post(
        "/v1/gateway/evaluate", json={"agent_name": "contract-agent", "tool_name": "run_shell", "arguments": {}}, headers=_ADMIN
    )
    assert evaluated.status_code == 200, evaluated.text
    audit = _check(client, "/v1/gateway/audit", "/v1/gateway/audit", _ADMIN, problems)
    stats = _check(client, "/v1/gateway/stats", "/v1/gateway/stats", _ADMIN, problems)
    assert audit is not None and stats is not None
    assert stats["total_policies"] == 1 and stats["policy_runtime"]["blocking_rules"] == 1

    assignment = client.post(
        "/v1/mcp-config/assignments",
        json={"name": "contract", "profile_id": "agent_bom_operator", "connector_ids": ["@modelcontextprotocol/server-filesystem"]},
        headers=_ADMIN,
    )
    assert assignment.status_code == 201, assignment.text
    config_id = assignment.json()["assignment"]["config_id"]
    _check(client, "/v1/mcp-config/assignments/{config_id}", f"/v1/mcp-config/assignments/{config_id}", _ADMIN, problems)
    listed = _check(client, "/v1/mcp-config/assignments", "/v1/mcp-config/assignments", _ADMIN, problems)
    assert listed is not None and listed["count"] == 1
    assert not problems, "\n".join(problems)


def test_unknown_ids_return_not_found(empty_estate_client: TestClient) -> None:  # noqa: F811
    client = empty_estate_client
    for url in (
        "/v1/cloud/side-scan/does-not-exist",
        "/v1/cloud/connections/does-not-exist",
        "/v1/gateway/policies/does-not-exist",
        "/v1/fleet/endpoints/does-not-exist",
        "/v1/fleet/does-not-exist",
        "/v1/mcp-config/assignments/does-not-exist",
        "/v1/registry/does/not-exist",
        "/v1/agents/does-not-exist",
        "/v1/connectors/does-not-exist/health",
    ):
        assert client.get(url, headers=_ADMIN).status_code == 404, url


def test_fleet_agent_row_accepts_unset_owner_and_environment() -> None:
    from agent_bom.api.fleet_models import FleetAgent
    from agent_bom.api.read_models import FleetAgentRow

    body = FleetAgent(agent_id="a-1", name="agent", agent_type="claude-desktop").model_dump(mode="json")
    assert body["owner"] is None and body["environment"] is None
    row = FleetAgentRow.model_validate(body)
    assert row.owner is None and row.environment is None
