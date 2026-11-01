"""GET /v1/intel/advisories/{id}/affected and the findings it persists, on the PHP2Shell estate."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from fastapi.testclient import TestClient

from agent_bom.api import compliance_hub_store
from agent_bom.api.advisory_affected_read import persist_affected_answer, tenant_affected_answer
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.operator_advisory_store import InMemoryOperatorAdvisoryStore
from agent_bom.api.server import app
from agent_bom.api.storage.hub_memory import InMemoryComplianceHubStore
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store, set_operator_advisory_store
from agent_bom.db import schema
from tests._clock_helpers import recent

FIXTURES = Path(__file__).parents[1] / "fixtures" / "php2shell"
ADVISORY = json.loads((FIXTURES / "operator-advisory.json").read_text())
REPORTS = json.loads((FIXTURES / "affected-reports.json").read_text())
ROUTE = "/v1/intel/advisories/{}/affected"


def _job(tenant: str, report: dict, completed: str = "2026-10-23T09:00:00Z") -> ScanJob:
    image = report["agents"][0]["mcp_servers"][0]["name"]
    stamp = recent(completed)
    return ScanJob(
        job_id=str(uuid.uuid4()),
        tenant_id=tenant,
        status=JobStatus.DONE,
        created_at=stamp,
        completed_at=stamp,
        request=ScanRequest(images=[image]),
        result=json.loads(json.dumps(report)),
    )


@pytest.fixture()
def estate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(schema, "DB_PATH", tmp_path / "absent" / "vulns.db")
    jobs = InMemoryJobStore()
    for report in REPORTS:
        jobs.put(_job("default", report))
    jobs.put(_job("other-tenant", REPORTS[0]))
    set_job_store(jobs)
    set_operator_advisory_store(InMemoryOperatorAdvisoryStore())
    hub = InMemoryComplianceHubStore()
    compliance_hub_store.set_compliance_hub_store(hub)
    client = TestClient(app)
    assert client.post("/v1/intel/operator-advisories", json=ADVISORY).status_code == 201
    yield client, jobs, hub
    set_operator_advisory_store(None)
    compliance_hub_store.reset_compliance_hub_store()


def _brief(body: dict) -> list[tuple]:
    return [(r["asset_label"], r["package"]["name"], r["installed_version"], r["fixed_version"], r["verdict"]) for r in body["rows"]]


PHP2SHELL = [
    ("php:8.3.30-cli", "php", "8.3.30", "8.3.36", "affected"),
    ("abtest/php-debian:12", "php8.2-cli", "8.2.29-1~deb12u1", None, "possibly_affected"),
    ("php:8.3.36-cli", "php", "8.3.36", None, "not_affected"),
]


def test_affected_assets_answer(estate) -> None:
    client, _, _ = estate
    response = client.get(ROUTE.format("CVE-2026-109618"))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["schema_version"] == "advisory-affected.v1" and body["tenant_id"] == "default"
    assert body["summary"] == {
        "affected": 1,
        "possibly_affected": 1,
        "not_affected": 1,
        "clean_scanned": 1,
        "assets_examined": 3,
        "reports_examined": 3,
        "count_basis": "package_occurrence_per_holding_asset",
        "count_basis_note": body["summary"]["count_basis_note"],
    }
    assert "per package occurrence on each holding asset" in body["summary"]["count_basis_note"]
    assert all(set(row["asset_display"]) == {"name", "kind", "agent", "host"} for row in body["rows"])
    assert _brief(body) == PHP2SHELL
    assert body["rows"][1]["verdict_reason"] == "distro_backport_unverified"
    assert body["rows"][0]["graph"]["package_node_id"].startswith("pkg:")
    assert body["advisory"]["source"] == "operator_advisory"
    assert _brief(client.get(ROUTE.format("cve-2026-109619")).json()) == PHP2SHELL


def test_unknown_advisory_is_404_and_bad_params_422(estate) -> None:
    client, _, _ = estate
    assert client.get(ROUTE.format("CVE-2026-0000001")).status_code == 404
    assert client.get(ROUTE.format("CVE-2026-109618"), params={"verdict": "safe"}).status_code == 422
    assert client.get(ROUTE.format("CVE-2026-109618"), params={"limit": 0}).status_code == 422
    assert client.get(ROUTE.format("CVE-2026-109618"), params={"cursor": "junk"}).status_code == 422


def test_cursor_pages_and_409_when_the_estate_changes(estate) -> None:
    client, jobs, _ = estate
    first = client.get(ROUTE.format("CVE-2026-109618"), params={"limit": 2}).json()
    assert [r["verdict"] for r in first["rows"]] == ["affected", "possibly_affected"] and first["has_more"] is True
    second = client.get(ROUTE.format("CVE-2026-109618"), params={"limit": 2, "cursor": first["next_cursor"]}).json()
    assert [r["verdict"] for r in second["rows"]] == ["not_affected"] and second["next_cursor"] is None
    wrong_filter = client.get(ROUTE.format("CVE-2026-109618"), params={"limit": 2, "cursor": first["next_cursor"], "verdict": "affected"})
    assert wrong_filter.status_code == 422

    patched = json.loads(json.dumps(REPORTS[0]))
    patched["scan_id"] = "scan-php-8.3.30-rescan"
    patched["agents"][0]["mcp_servers"][0]["packages"][0].update({"version": "8.3.36", "cpe": "cpe:2.3:a:php:php:8.3.36:*:*:*:*:*:*:*"})
    jobs.put(_job("default", patched, completed="2026-10-24T09:00:00Z"))
    stale = client.get(ROUTE.format("CVE-2026-109618"), params={"limit": 2, "cursor": first["next_cursor"]})
    assert stale.status_code == 409


def test_other_tenant_sees_only_its_own_estate(estate) -> None:
    assert tenant_affected_answer("other-tenant", "CVE-2026-109618") is None
    answer = tenant_affected_answer("default", "CVE-2026-109618")
    assert answer is not None and {row["scan_id"] for row in answer["rows"]} == {
        "scan-php-8.3.30",
        "scan-php-8.3.36",
        "scan-php-debian-12",
    }


def _advisory_findings(client: TestClient) -> list[dict]:
    body = client.get("/v1/findings", params={"limit": 500}).json()
    return [row for row in body["findings"] if row.get("cve_id") == "CVE-2026-109618"]


def test_declaring_persists_findings_into_v1_findings(estate) -> None:
    client, _, _ = estate
    rows = {row["package"]: row for row in _advisory_findings(client)}
    assert set(rows) == {"php", "php8.2-cli"}
    assert rows["php"]["severity"] == "critical" and rows["php"]["advisory_source"] == "operator_advisory"
    assert rows["php"]["provenance"]["source"] == "operator_advisory"
    assert rows["php"]["fixed_version"] == "8.3.36" and rows["php"]["package_version"] == "8.3.30"
    distro = rows["php8.2-cli"]
    assert distro["verdict"] == "possibly_affected" and distro["severity"] == "unknown"
    assert distro["advisory_severity"] == "critical"
    assert distro["status_detail"] == "possibly affected — verify distro advisory"


def test_rescan_at_the_fix_retires_the_finding(estate) -> None:
    client, jobs, _ = estate
    patched = json.loads(json.dumps(REPORTS[0]))
    patched["agents"][0]["mcp_servers"][0]["packages"][0].update({"version": "8.3.36", "cpe": "cpe:2.3:a:php:php:8.3.36:*:*:*:*:*:*:*"})
    jobs.put(_job("default", patched, completed="2026-10-24T09:00:00Z"))
    answer = tenant_affected_answer("default", "CVE-2026-109618")
    assert answer is not None
    assert persist_affected_answer("default", answer)["retired"] == 1
    assert {row["package"] for row in _advisory_findings(client)} == {"php8.2-cli"}


def test_feed_record_at_scan_time_supersedes_the_operator_finding(estate) -> None:
    client, jobs, _ = estate
    covered = json.loads(json.dumps(REPORTS[0]))
    covered["agents"][0]["mcp_servers"][0]["packages"][0]["vulnerabilities"] = [
        {"id": "CVE-2026-109618", "severity": "critical", "fixed_version": "8.3.36", "source": "nvd"}
    ]
    jobs.put(_job("default", covered, completed="2026-10-24T09:00:00Z"))
    answer = tenant_affected_answer("default", "CVE-2026-109618")
    assert answer is not None
    assert [(r["verdict"], r["provenance"]) for r in answer["rows"] if r["verdict"] == "affected"] == [("affected", "scan")]
    persist_affected_answer("default", answer)
    operator_rows = [row for row in _advisory_findings(client) if row.get("advisory_source") == "operator_advisory"]
    assert [row["package"] for row in operator_rows] == ["php8.2-cli"]


def test_retiring_the_advisory_resolves_its_findings(estate) -> None:
    client, _, _ = estate
    assert client.delete("/v1/intel/operator-advisories/CVE-2026-109618").status_code == 204
    assert _advisory_findings(client) == []


def test_possibly_affected_is_not_counted_as_a_confirmed_severity(estate) -> None:
    _, _, hub = estate
    breakdown = hub.current_severity_breakdown("default", origin="bulk_ingest", status="open")
    assert breakdown.get("critical") == 1
    assert breakdown.get("unknown") == 1


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        ({"id": "not an id"}, "id must look like CVE-YYYY-NNNN or PREFIX-ID"),
        ({"affected": [{"cpe_product": "php", "ranges": [{"fixed": "8.3.36"}]}]}, "cpe_product must be vendor:product"),
        (
            {"affected": [{"ecosystem": "generic", "name": "php", "ranges": [{"introduced": "8.4.0", "fixed": "8.3.0"}]}]},
            "introduced must precede fixed",
        ),
        ({"affected": [{"ecosystem": "generic", "name": "php"}]}, "affected product needs ranges or versions"),
        ({"references": ["http://example.test/advisory"]}, "references must be https URLs"),
    ],
)
def test_declaring_an_invalid_advisory_is_422_with_a_clear_message(estate, patch: dict, message: str) -> None:
    client, _, _ = estate
    response = client.post("/v1/intel/operator-advisories", json={**ADVISORY, "id": "CVE-2026-777777", **patch})
    assert response.status_code == 422
    assert message in response.text


def test_unknown_to_feed_but_referenced_by_stored_findings_answers_from_them(estate) -> None:
    client, jobs, _ = estate
    report = json.loads(json.dumps(REPORTS[0]))
    report["scan_id"] = "scan-webp"
    report["agents"][0]["mcp_servers"][0]["name"] = "etl-server"
    report["agents"][0]["mcp_servers"][0]["packages"] = [
        {
            "name": "pillow",
            "version": "9.0.0",
            "ecosystem": "pypi",
            "vulnerabilities": [{"id": "CVE-2023-4863", "severity": "high", "fixed_version": "10.0.1"}],
        }
    ]
    jobs.put(_job("default", report))

    response = client.get(ROUTE.format("CVE-2023-4863"))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["advisory"]["source"] == "scan" and body["complete"] is False
    assert body["incomplete_reason"] == "no advisory feed record; answered from stored findings"
    assert [(r["asset_label"], r["package"]["name"], r["fixed_version"], r["verdict"], r["provenance"]) for r in body["rows"]] == [
        ("etl-server", "pillow", "10.0.1", "affected", "scan")
    ]
    # Another tenant's stored findings never answer for this one.
    assert tenant_affected_answer("other-tenant", "CVE-2023-4863") is None
    assert client.get(ROUTE.format("CVE-2099-0001")).status_code == 404
