"""Live-body contract for the compliance and posture read endpoints.

Every JSON GET served by ``agent_bom.api.routes.compliance`` documents a typed
200 model. Each endpoint is called against an empty estate and its real JSON
body is validated against that model with undeclared keys forbidden, so the
documented contract cannot drift silently from the handler.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ValidationError
from starlette.testclient import TestClient

from agent_bom.api import read_models
from agent_bom.api.read_models import compliance as compliance_models
from tests.auth_helpers import proxy_headers
from tests.test_api_read_contracts import _undeclared_keys, empty_estate_client  # noqa: F401

# Documented path -> (model, concrete request path used for the live call).
TYPED_COMPLIANCE_READS: dict[str, tuple[type[BaseModel], str]] = {
    "/v1/cis/checks": (compliance_models.CisChecksResponse, "/v1/cis/checks"),
    "/v1/cis/trends": (compliance_models.CisTrendsResponse, "/v1/cis/trends"),
    "/v1/compliance/aisvs": (compliance_models.AisvsComplianceResponse, "/v1/compliance/aisvs"),
    "/v1/compliance/hub/findings": (compliance_models.HubFindingsResponse, "/v1/compliance/hub/findings"),
    "/v1/compliance/narrative/{framework}": (read_models.ComplianceNarrativeResponse, "/v1/compliance/narrative/owasp-llm"),
    "/v1/compliance/nist-800-53": (compliance_models.Nist80053DrillResponse, "/v1/compliance/nist-800-53"),
    "/v1/compliance/report/pack": (compliance_models.ComplianceEvidencePackResponse, "/v1/compliance/report/pack"),
    "/v1/compliance/summary": (compliance_models.ComplianceSummaryResponse, "/v1/compliance/summary"),
    "/v1/compliance/verification-key": (compliance_models.ComplianceVerificationKeyResponse, "/v1/compliance/verification-key"),
    "/v1/compliance/{framework}": (compliance_models.FrameworkComplianceResponse, "/v1/compliance/owasp-llm"),
    "/v1/posture/backpressure": (compliance_models.BackpressurePostureResponse, "/v1/posture/backpressure"),
    "/v1/posture/credentials": (compliance_models.CredentialRiskRankingResponse, "/v1/posture/credentials"),
    "/v1/posture/enrichment": (compliance_models.EnrichmentPostureResponse, "/v1/posture/enrichment"),
    "/v1/posture/incidents": (compliance_models.IncidentCorrelationResponse, "/v1/posture/incidents"),
}

# The AISVS slug of the per-framework route answers with the benchmark shape.
EXTRA_LIVE_CALLS: tuple[tuple[type[BaseModel], str], ...] = (
    (compliance_models.FrameworkComplianceResponse, "/v1/compliance/aisvs"),
    (compliance_models.FrameworkComplianceResponse, "/v1/compliance/cis"),
    (compliance_models.CisChecksResponse, "/v1/cis/checks?cloud=aws,gcp"),
)


def _compliance_get_paths() -> set[str]:
    from fastapi.routing import iter_route_contexts

    from agent_bom.api.routes.compliance import router

    paths: set[str] = set()
    for context in iter_route_contexts(router.routes):
        if "GET" in (context.methods or set()):
            paths.add(f"/v1{context.path}")
    return paths


def test_every_compliance_json_get_documents_a_typed_200() -> None:
    from agent_bom.api.server import app

    app.openapi_schema = None
    paths = app.openapi()["paths"]
    untyped = []
    for path in sorted(_compliance_get_paths()):
        operation = paths[path]["get"]
        schema = operation["responses"]["200"].get("content", {}).get("application/json", {}).get("schema", {})
        if "$ref" not in schema:
            untyped.append(path)
    assert untyped == []


def test_documented_compliance_models_match_openapi_refs() -> None:
    from agent_bom.api.server import app

    app.openapi_schema = None
    paths = app.openapi()["paths"]
    documented = {path: paths[path]["get"]["responses"]["200"]["content"]["application/json"]["schema"] for path in TYPED_COMPLIANCE_READS}
    expected = {path: {"$ref": f"#/components/schemas/{model.__name__}"} for path, (model, _) in TYPED_COMPLIANCE_READS.items()}
    assert documented == expected


def _violations(model: type[BaseModel], path: str, body: Any) -> list[str]:
    try:
        instance = model.model_validate(body, context={read_models.STRICT_CONTRACT: True})
    except ValidationError as exc:
        return [f"{path}: {exc}"]
    problems: list[str] = []
    undeclared = _undeclared_keys(instance)
    if undeclared:
        problems.append(f"{path}: keys {model.__name__} does not document: {undeclared[:10]}")
    if instance.model_dump(mode="json", by_alias=True, exclude_unset=True) != body:
        problems.append(f"{path}: model round-trip changes the body")
    return problems


def test_empty_estate_compliance_bodies_match_documented_models(empty_estate_client: TestClient) -> None:  # noqa: F811
    headers = proxy_headers(role="admin", tenant="contract-empty")
    problems: list[str] = []
    calls = [*TYPED_COMPLIANCE_READS.values(), *EXTRA_LIVE_CALLS]
    for model, path in calls:
        response = empty_estate_client.get(path, headers=headers)
        if response.status_code != 200:
            problems.append(f"{path}: HTTP {response.status_code} {response.text[:200]}")
            continue
        problems.extend(_violations(model, path, response.json()))
    assert not problems, "\n".join(problems)
