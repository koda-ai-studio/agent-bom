"""Real scan subresource bodies match the documented contracts."""

import pytest

from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.read_models import scan as m
from tests.auth_helpers import proxy_headers
from tests.test_api_read_contracts import empty_estate_client  # noqa: F401

CONTRACTS = {
    "/v1/scan/drivers": m.ScanDriversResponse,
    "/v1/scan/{job_id}/status": m.ScanStatusResponse,
    "/v1/scan/{job_id}/licenses": m.ScanLicensesResponse,
    "/v1/scan/{job_id}/vex": m.ScanVexResponse,
}


def test_scan_read_schema_references_named_contracts():
    from agent_bom.api.server import app

    app.openapi_schema = None
    paths = app.openapi()["paths"]
    for path, model in CONTRACTS.items():
        schema = paths[path]["get"]["responses"]["200"]["content"]["application/json"]["schema"]
        assert schema == {"$ref": f"#/components/schemas/{model.__name__}"}


@pytest.mark.parametrize("target", [None, {"path": "fixture-project"}])
@pytest.mark.parametrize("status", list(JobStatus))
def test_scan_status_preserves_lifecycle_and_nullable_fields(empty_estate_client, status, target):  # noqa: F811
    from agent_bom.api.stores import _get_store

    job = ScanJob(
        created_at="2026-01-01T00:00:00Z",
        job_id="contract-status",
        tenant_id="contract-empty",
        status=status,
        request=ScanRequest(),
        target=target,
    )
    _get_store().put(job)
    response = empty_estate_client.get(f"/v1/scan/{job.job_id}/status", headers=proxy_headers(role="admin", tenant=job.tenant_id))
    assert response.status_code == 200, response.text
    body = response.json()
    parsed = m.ScanStatusResponse.model_validate(body, strict=True, context={"strict_contract": True})
    assert parsed.model_dump(mode="json", exclude_unset=True) == body
    assert body["target"] == target
    assert body["status"] == status.value
    assert body["graph_scan_id"] == (job.job_id if status == JobStatus.DONE else None)


@pytest.mark.parametrize("precomputed", [False, True])
def test_scan_license_and_vex_fallback_and_persisted_contracts(empty_estate_client, precomputed):  # noqa: F811
    from agent_bom.api.stores import _get_store
    from agent_bom.license_policy import LicenseReport
    from agent_bom.license_policy import to_serializable as license_payload
    from agent_bom.vex import VexDocument, VexStatement, VexStatus
    from agent_bom.vex import to_serializable as vex_payload

    result = {"agents": []}
    if precomputed:
        result["license_report"] = license_payload(LicenseReport(compliant=False, status="undetermined", total_packages=1, unknown_count=1))
        result["vex"] = vex_payload(VexDocument(statements=[VexStatement("CVE-2026-0001", VexStatus.UNDER_INVESTIGATION)]))
    job = ScanJob(
        created_at="2026-01-01T00:00:00Z",
        job_id="contract-result",
        tenant_id="contract-empty",
        status=JobStatus.DONE,
        request=ScanRequest(),
        result=result,
    )
    _get_store().put(job)
    for suffix, model in [("licenses", m.ScanLicensesResponse), ("vex", m.ScanVexResponse)]:
        response = empty_estate_client.get(f"/v1/scan/{job.job_id}/{suffix}", headers=proxy_headers(role="admin", tenant=job.tenant_id))
        assert response.status_code == 200, response.text
        body = response.json()
        assert model.model_validate(body, strict=True).model_dump(mode="json", exclude_unset=True) == body


def test_scan_driver_contract_covers_active_and_planned(empty_estate_client):  # noqa: F811
    for planned in ["true", "false"]:
        response = empty_estate_client.get(
            f"/v1/scan/drivers?include_planned={planned}", headers=proxy_headers(role="admin", tenant="contract-empty")
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert m.ScanDriversResponse.model_validate(body, strict=True, context={"strict_contract": True}).model_dump(mode="json") == body
        assert body["drivers"]
        if planned == "false":
            assert all(driver["execution_state"] != "planned" for driver in body["drivers"])
