"""Typed 200 contracts for the enterprise auth, audit, exception and triage reads.

Every JSON GET on the enterprise router documents a response model, and the
live empty-estate bodies validate against it with undeclared keys forbidden.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel
from starlette.testclient import TestClient

from agent_bom.api import read_models
from agent_bom.api.read_models import enterprise as models
from tests.auth_helpers import proxy_headers
from tests.test_api_read_contracts import _undeclared_keys, empty_estate_client  # noqa: F401

TYPED_ENTERPRISE_READS: dict[str, type[BaseModel]] = {
    "/v1/auth/keys": models.ApiKeysResponse,
    "/v1/auth/policy": models.AuthPolicyResponse,
    "/v1/auth/scopes": models.AuthScopesResponse,
    "/v1/auth/secrets/lifecycle": models.SecretLifecycleResponse,
    "/v1/auth/secrets/rotation-plan": models.SecretRotationPlanResponse,
    "/v1/auth/secrets/credential-expiry": models.CredentialExpiryResponse,
    "/v1/auth/scim/config": models.ScimConfigResponse,
    "/v1/auth/quota": models.TenantQuotaRuntimeResponse,
    "/v1/auth/trial-tenants/{tenant_id}": models.ManagedTrialTenantResponse,
    "/v1/auth/debug": models.AuthDebugResponse,
    "/v1/audit": models.AuditEntriesResponse,
    "/v1/audit/integrity": models.AuditIntegrityResponse,
    "/v1/audit/export": models.AuditExportResponse,
    "/v1/exceptions": models.VulnExceptionsResponse,
    "/v1/exceptions/{exception_id}": models.VulnExceptionResponse,
    "/v1/findings/feedback": models.FindingFeedbackResponse,
    "/v1/findings/triage": models.FindingTriageResponse,
    "/v1/findings/triage/vex": models.FindingTriageVexResponse,
    "/v1/findings/false-positives": models.FalsePositivesResponse,
}

# Redirects and the SAML XML document have no JSON body to model.
NON_JSON_ENTERPRISE_GETS = frozenset(
    {
        "/v1/auth/oidc/login",
        "/v1/auth/oidc/callback",
        "/v1/auth/snowflake/login",
        "/v1/auth/snowflake/callback",
        "/v1/auth/saml/metadata",
    }
)


def _enterprise_get_paths() -> set[str]:
    from fastapi.routing import APIRoute, iter_route_contexts

    from agent_bom.api.routes.enterprise import router

    paths = set()
    for context in iter_route_contexts(router.routes):
        route = context.original_route
        if isinstance(route, APIRoute) and "GET" in (route.methods or set()) and route.include_in_schema:
            paths.add("/v1" + route.path)
    return paths


def _violations(path: str, body: Any) -> list[str]:
    model = TYPED_ENTERPRISE_READS[path]
    instance = model.model_validate(body, context={read_models.STRICT_CONTRACT: True})
    problems = []
    undeclared = _undeclared_keys(instance)
    if undeclared:
        problems.append(f"{path}: keys {model.__name__} does not document: {undeclared[:10]}")
    if instance.model_dump(mode="json", by_alias=True, exclude_unset=True) != body:
        problems.append(f"{path}: model round-trip changes the body")
    return problems


def test_every_json_enterprise_get_documents_a_model() -> None:
    from agent_bom.api.server import app

    app.openapi_schema = None
    spec_paths = app.openapi()["paths"]
    gets = _enterprise_get_paths()
    already_typed = {"/v1/auth/me", "/v1/trends", "/v1/siem/connectors"}
    assert gets == set(TYPED_ENTERPRISE_READS) | NON_JSON_ENTERPRISE_GETS | already_typed
    documented = {
        path: spec_paths[path]["get"]["responses"]["200"]["content"]["application/json"]["schema"] for path in TYPED_ENTERPRISE_READS
    }
    assert documented == {path: {"$ref": f"#/components/schemas/{model.__name__}"} for path, model in TYPED_ENTERPRISE_READS.items()}


def test_empty_estate_enterprise_bodies_match_documented_models(empty_estate_client: TestClient) -> None:  # noqa: F811
    headers = proxy_headers(role="admin", tenant="contract-empty")
    created = empty_estate_client.post(
        "/v1/exceptions", json={"vuln_id": "CVE-2024-0001", "package_name": "pkg", "reason": "contract"}, headers=headers
    )
    assert created.status_code == 201, created.text
    triage = empty_estate_client.post("/v1/findings/triage", json={"vulnerability_id": "CVE-2024-0002", "package": "pkg"}, headers=headers)
    assert triage.status_code == 201, triage.text
    feedback = empty_estate_client.post(
        "/v1/findings/false-positive", json={"vulnerability_id": "CVE-2024-0003", "package": "pkg", "reason": "fp"}, headers=headers
    )
    assert feedback.status_code == 201, feedback.text
    problems: list[str] = []
    for path in sorted(TYPED_ENTERPRISE_READS):
        if path == "/v1/auth/trial-tenants/{tenant_id}":
            continue
        url = path.replace("{exception_id}", created.json()["exception_id"])
        response = empty_estate_client.get(url, headers=headers)
        if response.status_code != 200:
            problems.append(f"{path}: HTTP {response.status_code} {response.text[:200]}")
            continue
        problems.extend(_violations(path, response.json()))
    assert not problems, "\n".join(problems)
