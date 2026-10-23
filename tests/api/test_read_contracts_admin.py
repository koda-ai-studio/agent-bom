"""Live-body contract for the admin and governance read endpoints.

Every typed GET documents its 200 body as a named component, and the real JSON
bodies from a seeded demo estate and from an empty tenant that this test fills
through the public write API validate against those models with undeclared
keys forbidden and an exact round-trip.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.fernet import Fernet
from pydantic import BaseModel
from starlette.testclient import TestClient

from agent_bom.api.read_models import admin as m
from tests.auth_helpers import proxy_headers
from tests.test_api_read_contracts import _contract_violations, empty_estate_client  # noqa: F401

_TENANT = "contract-empty"
_ROW_KEYS = ("grants", "policies", "campaigns", "items", "credentials", "provider_keys", "virtual_keys", "subscriptions")

TYPED_ADMIN_READS: dict[str, type[BaseModel]] = {
    "/v1/identity-jit-grants": m.IdentityJitGrantsResponse,
    "/v1/identities/{identity_id}/jit-grants": m.IdentityJitGrantsResponse,
    "/v1/conditional-access-policies": m.ConditionalAccessPoliciesResponse,
    "/v1/conditional-access-policies/{policy_id}": m.ConditionalAccessPolicyResponse,
    "/v1/identities/access-reviews": m.AccessReviewsResponse,
    "/v1/identities/access-reviews/{campaign_id}": m.AccessReviewDetailResponse,
    "/v1/identities/access-reviews/{campaign_id}/evidence": m.AccessReviewEvidenceResponse,
    "/v1/identities/{identity_id}": m.AgentIdentityResponse,
    "/v1/device-posture/{device_id}": m.DevicePostureResponse,
    "/v1/credentials": m.CredentialRefsResponse,
    "/v1/credentials/posture": m.CredentialRotationPostureResponse,
    "/v1/credentials/{credential_ref_id}": m.CredentialRefResponse,
    "/v1/model-keys/providers": m.ModelProviderKeysResponse,
    "/v1/model-keys/providers/{provider_key_id}": m.ModelProviderKeyResponse,
    "/v1/model-keys/virtual-keys": m.ModelVirtualKeysResponse,
    "/v1/entitlements": m.EntitlementsResponse,
    "/v1/entitlements/check/{feature}": m.EntitlementCheckResponse,
    "/v1/tenant/{tenant_id}/data": m.TenantDataExportResponse,
    "/v1/webhooks": m.WebhookSubscriptionsResponse,
    "/v1/webhooks/{subscription_id}": m.WebhookSubscriptionResponse,
    "/v1/exports/destinations": m.ExportDestinationsResponse,
    "/v1/exports/destinations/{destination_id}": m.ExportDestinationResponse,
    "/v1/exports/schedules": m.ExportSchedulesResponse,
    "/v1/schedules": m.ScanSchedulesResponse,
    "/v1/schedules/{schedule_id}": m.ScanScheduleResponse,
    "/v1/reports/{job_id}": m.ReportJobStatusResponse,
}

# Paths callable without an id, read against the seeded demo estate as its anonymous viewer.
_DEMO_READS = [
    "/v1/identity-jit-grants",
    "/v1/conditional-access-policies",
    "/v1/identities/access-reviews",
    "/v1/credentials",
    "/v1/credentials/posture",
    "/v1/model-keys/providers",
    "/v1/model-keys/virtual-keys",
    "/v1/webhooks",
    "/v1/exports/destinations",
    "/v1/exports/schedules",
    "/v1/schedules",
]


def _headers() -> dict[str, str]:
    return proxy_headers(role="admin", tenant=_TENANT)


def _created(response: Any) -> dict[str, Any]:
    assert response.status_code in (200, 201, 202), response.text
    return response.json()


def _seed(client: TestClient) -> dict[str, str]:
    """Create one record of every kind through the public API; return the concrete read paths."""
    h = _headers()
    identity = _created(client.post("/v1/identities", json={"agent_id": "contract-agent", "allowed_tools": ["read_file"]}, headers=h))
    identity_id = identity["identity"]["identity_id"]
    grant = _created(
        client.post(f"/v1/identities/{identity_id}/jit-requests", json={"tool_name": "write_file", "reason": "contract"}, headers=h)
    )
    _created(client.post(f"/v1/identity-jit-grants/{grant['grant']['grant_id']}/approve", json={"ttl_seconds": 300}, headers=h))
    policy = _created(
        client.post(
            "/v1/conditional-access-policies",
            json={"name": "contract-hours", "effect": "require", "allowed_hours_utc": [9, 10], "allowed_source_cidrs": ["10.0.0.0/8"]},
            headers=h,
        )
    )
    campaign = _created(
        client.post(
            "/v1/identities/access-reviews",
            json={
                "name": "contract recert",
                "subjects": [
                    {"subject_id": "okta:s1", "subject_name": "svc1", "permissions": ["admin"], "privileged": True},
                    {"subject_id": "entra:s2", "subject_name": "svc2", "permissions": ["read"]},
                ],
            },
            headers=h,
        )
    )
    campaign_id = campaign["campaign"]["campaign_id"]
    first_item = client.get(f"/v1/identities/access-reviews/{campaign_id}", headers=h).json()["items"][0]["item_id"]
    _created(
        client.post(
            f"/v1/identities/access-reviews/{campaign_id}/items/{first_item}/decision",
            json={"decision": "revoke_recommended", "note": "unused"},
            headers=h,
        )
    )
    _created(
        client.post(
            "/v1/device-posture",
            json={"source": "intune", "payload": {"value": [{"id": "contract-dev", "complianceState": "compliant", "isEncrypted": True}]}},
            headers=h,
        )
    )
    credential = _created(
        client.post(
            "/v1/credentials",
            json={"display_name": "Contract role", "provider": "aws", "external_ref": "arn:aws:iam::123456789012:role/contract"},
            headers=h,
        )
    )
    _created(
        client.post(
            "/v1/credentials",
            json={
                "display_name": "Contract stale key",
                "provider": "aws",
                "external_ref": "arn:aws:secretsmanager:us-east-1:123456789012:secret:contract",
                "credential_class": "api_key",
                "last_rotated_at": "2020-01-01T00:00:00Z",
            },
            headers=h,
        )
    )
    provider_key = _created(
        client.post(
            "/v1/model-keys/providers", json={"provider": "openai", "display_name": "contract", "api_key": "sk-contract-0000"}, headers=h
        )
    )
    provider_key_id = provider_key["provider_key_id"]
    _created(client.post(f"/v1/model-keys/providers/{provider_key_id}/virtual-keys", json={"holder_id": "agent-a"}, headers=h))
    subscription = _created(
        client.post("/v1/webhooks", json={"url": "https://hooks.example.com/in", "event_types": ["drift.detected"]}, headers=h)
    )
    destination = _created(
        client.post("/v1/exports/destinations", json={"kind": "s3", "display_name": "Lake", "config": {"bucket": "b"}}, headers=h)
    )
    _created(
        client.post(
            "/v1/exports/schedules",
            json={"name": "nightly", "cron_expression": "0 2 * * *", "destination_id": destination["id"]},
            headers=h,
        )
    )
    schedule = _created(
        client.post(
            "/v1/schedules", json={"name": "contract", "cron_expression": "0 3 * * *", "enabled": False, "tenant_id": _TENANT}, headers=h
        )
    )
    report = _created(client.post("/v1/reports", json={}, headers=h))
    return {
        "/v1/identities/{identity_id}/jit-grants": f"/v1/identities/{identity_id}/jit-grants?include_inactive=true",
        "/v1/conditional-access-policies/{policy_id}": f"/v1/conditional-access-policies/{policy['policy']['policy_id']}",
        "/v1/identities/access-reviews/{campaign_id}": f"/v1/identities/access-reviews/{campaign_id}",
        "/v1/identities/access-reviews/{campaign_id}/evidence": f"/v1/identities/access-reviews/{campaign_id}/evidence",
        "/v1/identities/{identity_id}": f"/v1/identities/{identity_id}",
        "/v1/device-posture/{device_id}": "/v1/device-posture/contract-dev",
        "/v1/credentials/{credential_ref_id}": f"/v1/credentials/{credential['credential_ref_id']}",
        "/v1/model-keys/providers/{provider_key_id}": f"/v1/model-keys/providers/{provider_key_id}",
        "/v1/entitlements/check/{feature}": "/v1/entitlements/check/sso",
        "/v1/tenant/{tenant_id}/data": f"/v1/tenant/{_TENANT}/data?include_records=true",
        "/v1/webhooks/{subscription_id}": f"/v1/webhooks/{subscription['subscription']['subscription_id']}",
        "/v1/exports/destinations/{destination_id}": f"/v1/exports/destinations/{destination['id']}",
        "/v1/schedules/{schedule_id}": f"/v1/schedules/{schedule['schedule_id']}",
        "/v1/reports/{job_id}": f"/v1/reports/{report['job_id']}",
    }


@pytest.fixture()
def connection_key(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api import connection_crypto

    monkeypatch.setenv(connection_crypto.CONNECTIONS_KEY_ENV, Fernet.generate_key().decode("ascii"))
    monkeypatch.delenv(f"{connection_crypto.CONNECTIONS_KEY_ENV}_FILE", raising=False)
    monkeypatch.delenv(connection_crypto.CONNECTIONS_KEY_PROVIDER_ENV, raising=False)


def test_every_admin_read_documents_its_model_in_openapi() -> None:
    from agent_bom.api.server import app

    app.openapi_schema = None
    spec = app.openapi()
    paths = spec["paths"]
    documented = {path: paths[path]["get"]["responses"]["200"]["content"]["application/json"]["schema"] for path in TYPED_ADMIN_READS}
    assert documented == {path: {"$ref": f"#/components/schemas/{model.__name__}"} for path, model in TYPED_ADMIN_READS.items()}
    components = spec["components"]["schemas"]
    for model in set(TYPED_ADMIN_READS.values()):
        assert components[model.__name__]["title"] == model.__name__


def test_list_bodies_are_documented_as_arrays() -> None:
    from agent_bom.api.server import app

    app.openapi_schema = None
    components = app.openapi()["components"]["schemas"]
    for model in (m.ExportDestinationsResponse, m.ExportSchedulesResponse, m.ScanSchedulesResponse):
        assert components[model.__name__]["type"] == "array"


def test_empty_tenant_bodies_match_documented_models(empty_estate_client: TestClient) -> None:  # noqa: F811
    problems: list[str] = []
    for path in [*_DEMO_READS, "/v1/entitlements", f"/v1/tenant/{_TENANT}/data"]:
        response = empty_estate_client.get(path, headers=_headers())
        template = "/v1/tenant/{tenant_id}/data" if path.startswith("/v1/tenant/") else path
        if response.status_code != 200:
            problems.append(f"{path}: HTTP {response.status_code} {response.text[:200]}")
            continue
        problems.extend(_contract_violations(path, response.json(), TYPED_ADMIN_READS[template]))
    assert not problems, "\n".join(problems)


def test_seeded_tenant_bodies_match_documented_models(empty_estate_client: TestClient, connection_key: None) -> None:  # noqa: F811
    concrete = _seed(empty_estate_client)
    reads = {path: path for path in [*_DEMO_READS, "/v1/entitlements"]} | concrete
    assert set(reads) == set(TYPED_ADMIN_READS), sorted(set(TYPED_ADMIN_READS) ^ set(reads))
    problems: list[str] = []
    for template, path in sorted(reads.items()):
        response = empty_estate_client.get(path, headers=_headers())
        if response.status_code != 200:
            problems.append(f"{path}: HTTP {response.status_code} {response.text[:200]}")
            continue
        body = response.json()
        row_keys = [key for key in _ROW_KEYS if isinstance(body, dict) and key in body]
        rows = body if isinstance(body, list) else (body[row_keys[0]] if row_keys else None)
        if rows == []:
            problems.append(f"{path}: seeded read returned no rows")
        problems.extend(_contract_violations(template, body, TYPED_ADMIN_READS[template]))
    assert not problems, "\n".join(problems)


def test_seeded_rotation_posture_reports_findings(empty_estate_client: TestClient, connection_key: None) -> None:  # noqa: F811
    _seed(empty_estate_client)
    body = empty_estate_client.get("/v1/credentials/posture", headers=_headers()).json()
    assert body["summary"]["total"] == 2 and body["findings"]
    assert _contract_violations("/v1/credentials/posture", body, m.CredentialRotationPostureResponse) == []


def test_demo_estate_bodies_match_documented_models(demo_estate_client: TestClient) -> None:
    problems: list[str] = []
    for path in _DEMO_READS:
        response = demo_estate_client.get(path)
        if response.status_code != 200:
            problems.append(f"{path}: HTTP {response.status_code}")
            continue
        problems.extend(_contract_violations(path, response.json(), TYPED_ADMIN_READS[path]))
    assert not problems, "\n".join(problems)


def test_unknown_ids_answer_404_not_an_undocumented_body(empty_estate_client: TestClient) -> None:  # noqa: F811
    missing = [
        "/v1/identities/does-not-exist",
        "/v1/identities/does-not-exist/jit-grants",
        "/v1/conditional-access-policies/does-not-exist",
        "/v1/identities/access-reviews/does-not-exist",
        "/v1/identities/access-reviews/does-not-exist/evidence",
        "/v1/device-posture/does-not-exist",
        "/v1/credentials/does-not-exist",
        "/v1/model-keys/providers/does-not-exist",
        "/v1/webhooks/does-not-exist",
        "/v1/exports/destinations/does-not-exist",
        "/v1/schedules/does-not-exist",
        "/v1/reports/does-not-exist",
    ]
    statuses = {path: empty_estate_client.get(path, headers=_headers()).status_code for path in missing}
    assert statuses == dict.fromkeys(missing, 404)
