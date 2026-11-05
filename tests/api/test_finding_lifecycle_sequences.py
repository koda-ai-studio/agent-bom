"""Finding lifecycle driven by real scan sequences, through real routes, on both stores.

Each test replays scans through ``POST /v1/results/push`` (the path ``agent-bom
scan --push-url`` uses) or ``POST /v1/findings/bulk`` and reads the result back
through ``GET /v1/findings``. The Postgres parameter runs when
``AGENT_BOM_POSTGRES_URL`` points at a migrated database.
"""

from __future__ import annotations

import os
from typing import Any
from uuid import uuid4

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.compliance_hub_store import set_compliance_hub_store
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

T = {day: f"2026-10-{day:02d}T10:00:00+00:00" for day in range(1, 29)}
VULN = ("CVE-2021-33503", "urllib3", "1.26.4", "high")
FIXED_VULN = ("CVE-2023-43804", "urllib3", "1.26.17", "medium")


def _scope_for(asset: str) -> str:
    return "v1:" + (asset.encode().hex() * 64)[:64]


def _finding(asset: str, cve: str, name: str, version: str, severity: str) -> dict[str, Any]:
    return {
        "id": f"{asset}:{cve}:{name}:{version}",
        "canonical_id": f"{asset}:{cve}:{name}:{version}",
        "finding_type": "CVE",
        "source": "package_vulnerability",
        "cve_id": cve,
        "vulnerability_id": cve,
        "severity": severity,
        "package": name,
        "package_name": name,
        "package_version": version,
        "ecosystem": "pypi",
        "asset": {"name": asset, "asset_type": "package", "identifier": asset},
    }


class Estate:
    """One tenant's scans through one ingest path."""

    def __init__(self, client: TestClient, mode: str, tenant: str) -> None:
        self.client, self.mode, self.tenant = client, mode, tenant
        self.headers = proxy_headers(role="admin", tenant=tenant)

    def scan(
        self,
        asset: str,
        findings: list[tuple[str, str, str, str]],
        at: str,
        *,
        outcome: str = "complete",
        extra: dict[str, Any] | None = None,
        rows: list[dict[str, Any]] | None = None,
        inventory: list[tuple[str, str]] | None = None,
        source: str | None = None,
    ) -> dict[str, Any]:
        payload_rows = rows if rows is not None else [_finding(asset, *item) for item in findings]
        if self.mode == "push":
            packages = inventory if inventory is not None else [(item[1], item[2]) for item in findings]
            body: dict[str, Any] = {
                "source_id": source or f"host-{asset}",
                "target_scope": _scope_for(asset),
                "generated_at": at,
                "findings": payload_rows,
                "packages": [{"name": name, "version": version} for name, version in packages],
                "agents": [],
                "summary": {"total_vulnerabilities": len(payload_rows)},
                "scan_run": {"outcome": outcome},
                **(extra or {}),
            }
            response = self.client.post("/v1/results/push", json=body, headers=self.headers)
        else:
            bulk: dict[str, Any] = {
                "findings": [{key: value for key, value in row.items() if key not in {"id", "canonical_id"}} for row in payload_rows],
                "source": source or "ci-scanner",
                "observed_at": at,
                "reconcile_absent": True,
                "scanned_assets": [asset],
                "scan_run": {"outcome": outcome},
                **(extra or {}),
            }
            response = self.client.post("/v1/findings/bulk", json=bulk, headers=self.headers)
        assert response.status_code in {200, 201}, response.text
        return response.json()

    def rows(self, status: str = "open", **params: Any) -> list[dict[str, Any]]:
        response = self.client.get(
            "/v1/findings", params={"status": status, "window_days": 0, "limit": 500, **params}, headers=self.headers
        )
        assert response.status_code == 200, response.text
        return response.json()["findings"]

    def one(self, cve: str, status: str = "all", asset: str | None = None) -> dict[str, Any]:
        matches = [
            row
            for row in self.rows(status)
            if row.get("cve_id") == cve and (asset is None or (row.get("asset") or {}).get("name") == asset)
        ]
        assert len(matches) == 1, [(row.get("cve_id"), row.get("status"), row.get("asset")) for row in self.rows("all")]
        return matches[0]

    def groups(self, status: str = "all") -> dict[str, dict[str, Any]]:
        response = self.client.get(
            "/v1/findings", params={"status": status, "window_days": 0, "group_occurrences": True, "limit": 200}, headers=self.headers
        )
        assert response.status_code == 200, response.text
        return {row["cve_id"]: row for row in response.json()["findings"] if row.get("cve_id")}

    def cves(self, status: str = "open") -> set[str]:
        return {str(row.get("cve_id")) for row in self.rows(status)}


def _instant(value: Any) -> str:
    from datetime import datetime, timezone

    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc).isoformat()


def assert_at(value: Any, expected: str) -> None:
    assert value is not None
    assert _instant(value) == _instant(expected)


@pytest.fixture(scope="module")
def client():
    # Starting the app is most of this suite's cost, and CI's Postgres job has a fixed budget.
    # The app's stores hold the Postgres pool for the module, so it opens and closes with the client.
    postgres = bool(os.environ.get("AGENT_BOM_POSTGRES_URL"))
    if postgres:
        from agent_bom.api import postgres_common

        postgres_common.reset_pool()
    with TestClient(app) as shared:
        yield shared
    if postgres:
        pool = postgres_common._pool
        if pool is not None:
            pool.close()
        postgres_common.reset_pool()


@pytest.fixture(params=["sqlite", "postgres"])
def store_kind(request, tmp_path, monkeypatch, client):
    original = stores._store
    monkeypatch.setattr("agent_bom.api.campaign_reconciliation.poll_campaign_reconciliation", lambda: None)
    monkeypatch.setenv("AGENT_BOM_NO_UPDATE_CHECK", "1")
    if request.param == "postgres":
        if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
            pytest.skip("AGENT_BOM_POSTGRES_URL is required for the Postgres lifecycle sequences")
        from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore
        from agent_bom.api.postgres_job_store import PostgresJobStore

        stores.set_job_store(PostgresJobStore())
        set_compliance_hub_store(PostgresComplianceHubStore())
    else:
        if os.environ.get("AGENT_BOM_POSTGRES_URL"):
            pytest.skip("the SQLite sequences run without a configured Postgres backend")
        from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore
        from agent_bom.api.store import SQLiteJobStore

        stores.set_job_store(SQLiteJobStore(str(tmp_path / "jobs.db")))
        set_compliance_hub_store(SQLiteComplianceHubStore(str(tmp_path / "hub.db")))
    enable_trusted_proxy_env()
    yield request.param
    stores.set_job_store(original)
    set_compliance_hub_store(None)
    disable_trusted_proxy_env()


@pytest.fixture(params=["push", "bulk"])
def estate(request, store_kind, client):
    return Estate(client, request.param, f"lifecycle-{uuid4().hex[:10]}")


# ── Sequences 1-5: appear, persist, resolve, change version, reopen ──────────


def test_first_scan_opens_with_first_and_last_seen(estate):
    estate.scan("asset-a", [VULN], T[1])
    row = estate.one(VULN[0], "open")
    assert row["status"] == "open"
    assert_at(row["first_seen"], T[1])
    assert_at(row["last_seen"], T[1])
    assert row["resolved_at"] is None
    assert row["reopened_at"] is None
    assert_at(row["status_updated_at"], T[1])
    assert row["package_version"] == "1.26.4"


def test_unchanged_rescan_keeps_first_seen_and_advances_last_seen(estate):
    estate.scan("asset-a", [VULN], T[1])
    estate.scan("asset-a", [VULN], T[2])
    row = estate.one(VULN[0], "open")
    assert row["status"] == "open"
    assert_at(row["first_seen"], T[1])
    assert_at(row["last_seen"], T[2])
    assert_at(row["status_updated_at"], T[1])


def test_patched_package_resolves_and_leaves_open_counts(estate):
    estate.scan("asset-a", [VULN], T[1])
    estate.scan("asset-a", [VULN], T[2])
    estate.scan("asset-a", [], T[3])
    assert estate.rows("open") == []
    row = estate.one(VULN[0], "resolved")
    assert row["status"] == "resolved"
    assert_at(row["first_seen"], T[1])
    assert_at(row["last_seen"], T[2])
    assert_at(row["resolved_at"], T[3])
    assert_at(row["status_updated_at"], T[3])
    assert row["package_version"] == "1.26.4"


def test_patch_to_version_with_a_different_cve_resolves_old_and_opens_new(estate):
    estate.scan("asset-a", [VULN], T[1])
    estate.scan("asset-a", [FIXED_VULN], T[2])
    assert estate.cves("open") == {FIXED_VULN[0]}
    assert estate.cves("resolved") == {VULN[0]}
    assert_at(estate.one(VULN[0])["resolved_at"], T[2])
    fresh = estate.one(FIXED_VULN[0])
    assert fresh["status"] == "open"
    assert fresh["package_version"] == "1.26.17"
    assert_at(fresh["first_seen"], T[2])


def test_returning_vulnerable_version_reopens_with_original_first_seen(estate):
    estate.scan("asset-a", [VULN], T[1])
    estate.scan("asset-a", [], T[2])
    estate.scan("asset-a", [VULN], T[3])
    row = estate.one(VULN[0], "open")
    assert row["status"] == "reopened"
    assert_at(row["first_seen"], T[1])
    assert_at(row["last_seen"], T[3])
    assert_at(row["reopened_at"], T[3])
    assert_at(row["status_updated_at"], T[3])
    # Currently open: no live resolution date, but the earlier fix stays visible.
    assert row["resolved_at"] is None
    assert_at(row["last_resolved_at"], T[2])
    estate.scan("asset-a", [], T[4])
    again = estate.one(VULN[0], "resolved")
    assert again["status"] == "resolved"
    assert_at(again["resolved_at"], T[4])
    assert_at(again["reopened_at"], T[3])


# ── Sequence 6: incomplete or differently scoped evidence resolves nothing ───


def test_scan_of_another_asset_does_not_resolve(estate):
    estate.scan("asset-a", [VULN], T[1])
    estate.scan("asset-b", [FIXED_VULN], T[2])
    estate.scan("asset-b", [], T[3])
    row = estate.one(VULN[0], "open")
    assert row["status"] == "open"
    assert row["resolved_at"] is None
    assert_at(row["last_seen"], T[1])


@pytest.mark.parametrize("outcome", ["partial", "failed"])
def test_partial_or_failed_scan_reporting_zero_does_not_resolve(estate, outcome):
    estate.scan("asset-a", [VULN], T[1])
    estate.scan("asset-a", [], T[2], outcome=outcome)
    row = estate.one(VULN[0], "open")
    assert row["status"] == "open"
    assert row["resolved_at"] is None
    assert_at(row["last_seen"], T[1])
    # The later complete scan is authoritative again.
    estate.scan("asset-a", [], T[3])
    assert_at(estate.one(VULN[0], "resolved")["resolved_at"], T[3])


def test_different_source_does_not_resolve_anothers_findings(estate):
    estate.scan("asset-a", [VULN], T[1], source="local-scan")
    estate.scan("asset-a", [], T[2], source="cloud-scan")
    assert estate.one(VULN[0], "open")["status"] == "open"


# ── Sequence 7: removal ──────────────────────────────────────────────────────


def test_package_removed_from_scanned_asset_resolves(estate):
    other = ("CVE-2024-0001", "requests", "2.0.0", "low")
    estate.scan("asset-a", [VULN, other], T[1])
    estate.scan("asset-a", [other], T[2])
    assert estate.cves("open") == {other[0]}
    assert_at(estate.one(VULN[0], "resolved")["resolved_at"], T[2])


def test_asset_no_longer_scanned_stays_open_with_aging_last_seen(estate):
    estate.scan("asset-a", [VULN], T[1])
    estate.scan("asset-b", [FIXED_VULN], T[5])
    row = estate.one(VULN[0], "open")
    assert row["status"] == "open"
    assert_at(row["last_seen"], T[1])


# ── Sequence 8: order and replay ─────────────────────────────────────────────


def test_older_observation_cannot_overwrite_latest_state(estate):
    estate.scan("asset-a", [VULN], T[10])
    estate.scan("asset-a", [], T[12])
    estate.scan("asset-a", [VULN], T[5])
    row = estate.one(VULN[0], "resolved")
    assert_at(row["first_seen"], T[5])
    assert_at(row["last_seen"], T[10])
    assert_at(row["resolved_at"], T[12])
    assert row["reopened_at"] is None


def test_late_absence_cannot_resolve_a_newer_observation(estate):
    estate.scan("asset-a", [VULN], T[10])
    estate.scan("asset-a", [], T[5])
    row = estate.one(VULN[0], "open")
    assert row["status"] == "open"
    assert row["resolved_at"] is None
    assert_at(row["last_seen"], T[10])


def test_replayed_batch_is_idempotent(estate):
    estate.scan("asset-a", [VULN], T[1])
    estate.scan("asset-a", [], T[2])
    estate.scan("asset-a", [], T[2])
    estate.scan("asset-a", [VULN], T[1])
    row = estate.one(VULN[0], "resolved")
    assert_at(row["first_seen"], T[1])
    assert_at(row["resolved_at"], T[2])
    assert row["reopened_at"] is None


# ── Sequence 9: one issue across assets ──────────────────────────────────────


def test_issue_on_two_assets_stays_open_until_both_are_fixed(estate):
    estate.scan("asset-a", [VULN], T[1])
    estate.scan("asset-b", [VULN], T[2])
    estate.scan("asset-a", [], T[3])
    assert estate.one(VULN[0], "resolved", asset="asset-a")["status"] == "resolved"
    assert estate.one(VULN[0], "open", asset="asset-b")["status"] == "open"
    group = estate.groups("all")[VULN[0]]
    assert group["status"] == "open"
    assert group["open_occurrence_count"] == 1
    assert group["resolved_occurrence_count"] == 1
    assert group["occurrence_count"] == 2
    assert group["resolved_at"] is None
    assert_at(group["first_seen"], T[1])
    assert_at(group["last_seen"], T[2])
    estate.scan("asset-b", [], T[4])
    assert VULN[0] not in estate.groups("open")
    closed = estate.groups("all")[VULN[0]]
    assert closed["status"] == "resolved"
    assert closed["open_occurrence_count"] == 0
    assert closed["resolved_occurrence_count"] == 2
    assert_at(closed["resolved_at"], T[4])


# ── Sequence 10: visibility, tenancy ─────────────────────────────────────────


def test_resolved_hidden_by_default_and_retrievable(estate):
    estate.scan("asset-a", [VULN], T[1])
    estate.scan("asset-a", [], T[2])
    response = estate.client.get("/v1/findings", params={"window_days": 0}, headers=estate.headers)
    assert response.json()["findings"] == []
    assert response.json()["total"] == 0
    assert estate.cves("resolved") == {VULN[0]}
    assert estate.cves("all") == {VULN[0]}


def test_tenants_are_isolated(estate):
    other = Estate(estate.client, estate.mode, f"lifecycle-{uuid4().hex[:10]}")
    estate.scan("asset-a", [VULN], T[1])
    other.scan("asset-a", [VULN], T[1])
    estate.scan("asset-a", [], T[2])
    assert estate.one(VULN[0], "resolved")["status"] == "resolved"
    assert other.one(VULN[0], "open")["status"] == "open"
    assert other.cves("resolved") == set()


def test_manual_sla_assignment_survives_reopen(estate):
    assigned = _finding("asset-a", *VULN)
    assigned.update(sla_due_at="2026-12-01T00:00:00+00:00", sla_due_at_source="explicit", owner="team-sec")
    estate.scan("asset-a", [], T[1], rows=[assigned])
    estate.scan("asset-a", [], T[2])
    estate.scan("asset-a", [VULN], T[3])
    row = estate.one(VULN[0], "open")
    assert row["status"] == "reopened"
    assert_at(row["sla_due_at"], "2026-12-01T00:00:00+00:00")


# ── Sequence 11: non-CVE findings ────────────────────────────────────────────


def _misconfig(asset: str, finding_type: str, rule: str) -> dict[str, Any]:
    return {
        "id": f"{asset}:{rule}",
        "canonical_id": f"{asset}:{rule}",
        "finding_type": finding_type,
        "source": "cloud_cis" if finding_type == "CIS" else "scanner",
        "rule_id": rule,
        "title": rule,
        "severity": "high",
        "asset": {"name": asset, "asset_type": "cloud_resource", "identifier": asset},
    }


def _by_rule(rows: list[dict[str, Any]], rule: str) -> dict[str, Any]:
    matches = [row for row in rows if row.get("rule_id") == rule or row.get("title") == rule]
    assert len(matches) == 1, rows
    return matches[0]


@pytest.mark.parametrize(
    ("finding_type", "rule"),
    [("CIS", "CIS-1.4"), ("IAC_MISCONFIGURATION", "CKV_AWS_20"), ("CREDENTIAL_EXPOSURE", "aws-access-key")],
)
def test_non_cve_findings_follow_the_same_lifecycle(estate, finding_type, rule):
    row = _misconfig("asset-a", finding_type, rule)
    estate.scan("asset-a", [], T[1], rows=[row])
    assert _by_rule(estate.rows("open"), rule)["status"] == "open"
    estate.scan("asset-a", [], T[2])
    resolved = _by_rule(estate.rows("resolved"), rule)
    assert_at(resolved["resolved_at"], T[2])
    estate.scan("asset-a", [], T[3], rows=[row])
    reopened = _by_rule(estate.rows("open"), rule)
    assert reopened["status"] == "reopened"
    assert_at(reopened["first_seen"], T[1])
    assert_at(reopened["reopened_at"], T[3])


# ── Push only: advisory outages and inventory runs ───────────────────────────


@pytest.fixture
def push_estate(store_kind, client):
    return Estate(client, "push", f"lifecycle-{uuid4().hex[:10]}")


_ADVISORY_OUTAGE = {
    "outcome": "partial",
    "issues": [
        {
            "code": "scanner_warning",
            "stage": "scanning",
            "source": "vulnerability-data",
            "message": "live OSV did not answer; results may be incomplete",
            "affects_coverage": True,
        }
    ],
}


def test_advisory_outage_reporting_zero_keeps_a_present_package_open(push_estate):
    push_estate.scan("asset-a", [VULN], T[1])
    push_estate.scan("asset-a", [], T[2], inventory=[("urllib3", "1.26.4")], extra={"scan_run": _ADVISORY_OUTAGE})
    row = push_estate.one(VULN[0], "open")
    assert row["status"] == "open"
    assert row["resolved_at"] is None
    assert row["observation_status"] == "unreconfirmed"
    assert_at(row["last_seen"], T[1])
    # Open views and the overview count agree during the outage.
    overview = push_estate.client.get("/v1/overview", headers=push_estate.headers).json()
    assert overview["issue_counts"]["total"] >= 1


def test_advisory_outage_with_the_package_gone_still_resolves(push_estate):
    push_estate.scan("asset-a", [VULN], T[1])
    push_estate.scan("asset-a", [], T[2], inventory=[("urllib3", "2.2.2")], extra={"scan_run": _ADVISORY_OUTAGE})
    assert_at(push_estate.one(VULN[0], "resolved")["resolved_at"], T[2])


def test_inventory_only_run_does_not_resolve(push_estate):
    push_estate.scan("asset-a", [VULN], T[1])
    push_estate.scan("asset-a", [], T[2], extra={"no_scan": True})
    push_estate.scan("asset-a", [], T[3], extra={"scan_skipped": True})
    assert push_estate.one(VULN[0], "open")["status"] == "open"


def test_overview_drops_resolved_findings(push_estate):
    push_estate.scan("asset-a", [VULN], T[1])
    before = push_estate.client.get("/v1/overview", headers=push_estate.headers).json()
    push_estate.scan("asset-a", [], T[2])
    after = push_estate.client.get("/v1/overview", headers=push_estate.headers).json()
    assert before["issue_counts"]["total"] == 1
    assert after["issue_counts"]["total"] == 0


# ── Bulk only: request contract ──────────────────────────────────────────────


@pytest.fixture
def bulk_estate(store_kind, client):
    return Estate(client, "bulk", f"lifecycle-{uuid4().hex[:10]}")


def test_bulk_rejects_an_unparseable_observed_at(bulk_estate):
    response = bulk_estate.client.post(
        "/v1/findings/bulk",
        json={"findings": [_finding("asset-a", *VULN)], "source": "ci", "observed_at": "not-a-date"},
        headers=bulk_estate.headers,
    )
    assert response.status_code == 422


def test_bulk_rejects_empty_batch_without_a_declared_scope(bulk_estate):
    for body in ({"findings": [], "source": "ci"}, {"findings": [], "source": "ci", "reconcile_absent": True}):
        response = bulk_estate.client.post("/v1/findings/bulk", json=body, headers=bulk_estate.headers)
        assert response.status_code == 422, response.text


def test_bulk_batch_without_scanned_assets_scopes_to_assets_it_names(bulk_estate):
    other = ("CVE-2024-0002", "flask", "1.0", "low")
    bulk_estate.scan("asset-a", [VULN], T[1])
    response = bulk_estate.client.post(
        "/v1/findings/bulk",
        json={"findings": [_finding("asset-b", *other)], "source": "ci-scanner", "observed_at": T[2], "reconcile_absent": True},
        headers=bulk_estate.headers,
    )
    assert response.status_code == 201
    assert response.json()["reconciled"] == 0
    assert bulk_estate.one(VULN[0], "open")["status"] == "open"


def test_bulk_explicit_source_scope_resolves_across_assets(bulk_estate):
    other = ("CVE-2024-0002", "flask", "1.0", "low")
    bulk_estate.scan("asset-a", [VULN], T[1])
    response = bulk_estate.client.post(
        "/v1/findings/bulk",
        json={
            "findings": [_finding("asset-b", *other)],
            "source": "ci-scanner",
            "observed_at": T[2],
            "reconcile_absent": True,
            "reconcile_scope": "source",
        },
        headers=bulk_estate.headers,
    )
    assert response.status_code == 201
    assert response.json()["reconciled"] == 1
    assert bulk_estate.one(VULN[0], "resolved")["status"] == "resolved"


def test_bulk_partial_outcome_reports_why_nothing_resolved(bulk_estate):
    bulk_estate.scan("asset-a", [VULN], T[1])
    payload = bulk_estate.scan("asset-a", [], T[2], outcome="partial")
    assert payload["reconciled"] == 0
    assert payload["reconcile_skipped"] == ["scan_partial"]


@pytest.mark.parametrize("observed_at", ["not-a-date", "2099-01-01T00:00:00+00:00"])
def test_compliance_ingest_rejects_unusable_observed_at(bulk_estate, observed_at):
    response = bulk_estate.client.post(
        "/v1/compliance/ingest",
        json={"format": "json", "content": "[]", "observed_at": observed_at},
        headers=bulk_estate.headers,
    )
    assert response.status_code == 422, response.text


def test_bulk_rejects_an_observation_far_in_the_future(bulk_estate):
    response = bulk_estate.client.post(
        "/v1/findings/bulk",
        json={"findings": [_finding("asset-a", *VULN)], "source": "ci", "observed_at": "2099-01-01T00:00:00+00:00"},
        headers=bulk_estate.headers,
    )
    assert response.status_code == 422


def test_push_without_target_identity_never_resolves_but_keeps_first_seen(push_estate):
    base = {"source_id": "cloud-host", "agents": [], "scan_run": {"outcome": "complete"}}
    finding = _finding("asset-a", *VULN)
    for at, rows in ((T[1], [finding]), (T[2], [finding]), (T[3], [])):
        response = push_estate.client.post(
            "/v1/results/push", json={**base, "generated_at": at, "findings": rows}, headers=push_estate.headers
        )
        assert response.status_code == 201, response.text
    row = push_estate.one(VULN[0], "open")
    assert row["status"] == "open"
    assert_at(row["first_seen"], T[1])
    assert_at(row["last_seen"], T[2])


def test_manual_exception_survives_resolve_and_reopen(estate):
    from datetime import datetime, timedelta, timezone

    from agent_bom.api.exception_store import ExceptionStatus, InMemoryExceptionStore, VulnException
    from agent_bom.api.suppression_approval import APPROVAL_VERSION

    now = datetime.now(timezone.utc)
    previous = stores._exception_store
    exceptions = InMemoryExceptionStore()
    stores.set_exception_store(exceptions)
    try:
        estate.scan("asset-a", [VULN], T[1])
        exceptions.put(
            VulnException(
                exception_id="exception-1",
                vuln_id=VULN[0],
                package_name=VULN[1],
                reason="accepted risk",
                requested_by="analyst",
                tenant_id=estate.tenant,
                status=ExceptionStatus.ACTIVE,
                approved_by="security-lead",
                approved_at=(now - timedelta(minutes=1)).isoformat(),
                approval_version=APPROVAL_VERSION,
                expires_at=(now + timedelta(days=30)).isoformat(),
            ),
            tenant_id=estate.tenant,
        )
        assert estate.one(VULN[0])["suppressed"] is True
        estate.scan("asset-a", [], T[2])
        estate.scan("asset-a", [VULN], T[3])
        row = estate.one(VULN[0])
        assert row["suppressed"] is True
        assert row["reopened_at"] is not None
        assert_at(row["first_seen"], T[1])
    finally:
        stores.set_exception_store(previous)


# ── Compressed payloads: SQL cannot read keys inside a zstd-wrapped overlay ──


def _stored_payload(tenant: str, canonical_fragment: str) -> Any:
    """The raw stored payload of the one current row whose canonical id holds the fragment."""
    from agent_bom.api.compliance_hub_store import get_compliance_hub_store

    store = get_compliance_hub_store()
    query = "SELECT canonical_id, payload FROM hub_findings_current WHERE tenant_id = {}"
    if hasattr(store, "_conn"):
        rows = store._conn.execute(query.format("?"), (tenant,)).fetchall()
    else:
        from agent_bom.api.postgres_common import _tenant_connection
        from agent_bom.api.tenant_worker import tenant_bound_context

        with tenant_bound_context(tenant), _tenant_connection(store._pool) as conn:
            rows = conn.execute(query.format("%s"), (tenant,)).fetchall()
    return next(row[1] for row in rows if canonical_fragment in str(row[0]))


def test_reconcile_scopes_asset_and_source_inside_compressed_payloads(bulk_estate):
    """Overlays of 512 bytes or more are wrapped, so scope must not depend on a SQL key read."""
    from agent_bom.api.hub_payload_codec import HUB_PAYLOAD_MARKER

    def row(asset: str, cve: str) -> dict[str, Any]:
        return {**_finding(asset, cve, "urllib3", "1.26.4", "high"), "id": f"{asset}-{cve}-" + "x" * 700}

    def post(asset: str, rows: list[dict[str, Any]], at: str, source: str = "long-source") -> dict[str, Any]:
        body = {"findings": rows, "source": source, "observed_at": at, "reconcile_absent": True, "scanned_assets": [asset]}
        response = bulk_estate.client.post("/v1/findings/bulk", json=body, headers=bulk_estate.headers)
        assert response.status_code == 201, response.text
        return response.json()

    post("asset-a", [row("asset-a", "CVE-2024-1111")], T[1])
    post("asset-b", [row("asset-b", "CVE-2024-2222")], T[1])
    stored = _stored_payload(bulk_estate.tenant, "asset-a-CVE-2024-1111")
    assert HUB_PAYLOAD_MARKER in str(stored), "the fixture must exercise a wrapped overlay"

    # Another source, then another asset of this source, resolve nothing.
    assert post("asset-a", [], T[2], source="other-source")["reconciled"] == 0
    assert post("asset-c", [], T[2])["reconciled"] == 0
    assert bulk_estate.cves("open") == {"CVE-2024-1111", "CVE-2024-2222"}
    # The scanned asset resolves its own wrapped row only.
    assert post("asset-a", [], T[3])["reconciled"] == 1
    assert bulk_estate.cves("resolved") == {"CVE-2024-1111"}
    assert bulk_estate.cves("open") == {"CVE-2024-2222"}


def test_batch_never_resolves_itself_when_a_client_sends_its_own_canonical_id(bulk_estate):
    """The store ignores a client canonical_id, so the present set must identify rows the same way."""
    row = {**_finding("asset-a", *VULN), "id": "client-id", "canonical_id": "client-canonical"}
    body = {"findings": [row], "source": "ci", "observed_at": T[1], "reconcile_absent": True}
    for at in (T[1], T[2]):
        response = bulk_estate.client.post("/v1/findings/bulk", json={**body, "observed_at": at}, headers=bulk_estate.headers)
        assert response.status_code == 201, response.text
        assert response.json()["reconciled"] == 0
    assert bulk_estate.one(VULN[0], "open")["status"] == "open"
