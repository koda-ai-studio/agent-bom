"""Durable finding history, project identity, stale label and resolution reasons, through real routes."""

# ruff: noqa: F811
from __future__ import annotations

import itertools
import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import pytest

from agent_bom.api import stores
from agent_bom.api.tenant_worker import tenant_bound_context
from tests.api.test_finding_lifecycle_sequences import (  # noqa: F401
    FIXED_VULN,
    VULN,
    Estate,
    T,
    _finding,
    _scope_for,
    assert_at,
    bulk_estate,
    client,
    estate,
    push_estate,
    store_kind,
)


def _expire_all_jobs() -> None:
    """Retention removed every scan; only durable state may answer from here on."""
    assert stores._get_store().cleanup_expired(-86400) >= 0


def _tenant_jobs(tenant: str) -> list[dict[str, Any]]:
    with tenant_bound_context(tenant):
        return stores._get_store().list_summary(tenant_id=tenant)


def _run_backfill() -> None:
    from agent_bom.api.finding_lifecycle_tick import run_finding_lifecycle_tick

    while run_finding_lifecycle_tick(budget_seconds=30):
        pass


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


# ── Durable history outlasts scan retention ──────────────────────────────────


def test_open_finding_keeps_dates_after_its_scans_expire(push_estate):
    push_estate.scan("asset-a", [VULN], T[1])
    push_estate.scan("asset-a", [VULN], T[2])
    _expire_all_jobs()
    row = push_estate.one(VULN[0], "open")
    assert row["status"] == "open"
    assert_at(row["first_seen"], T[1])
    assert_at(row["last_seen"], T[2])
    assert row["package_version"] == VULN[2]
    assert (row["asset"] or {}).get("name") == "asset-a"


def test_resolved_finding_stays_listed_after_its_scans_expire(push_estate):
    push_estate.scan("asset-a", [VULN], T[1])
    push_estate.scan("asset-a", [], T[2])
    _expire_all_jobs()
    row = push_estate.one(VULN[0], "resolved")
    assert_at(row["first_seen"], T[1])
    assert_at(row["resolved_at"], T[2])
    assert row["resolution_reason"] == "no_longer_detected"


def test_finding_returning_after_expiry_reopens_with_original_first_seen(push_estate):
    push_estate.scan("asset-a", [VULN], T[1])
    push_estate.scan("asset-a", [], T[2])
    _expire_all_jobs()
    push_estate.scan("asset-a", [VULN], T[3])
    row = push_estate.one(VULN[0], "open")
    assert row["status"] == "reopened"
    assert_at(row["first_seen"], T[1])
    assert_at(row["reopened_at"], T[3])
    assert_at(row["last_resolved_at"], T[2])
    assert row["resolved_at"] is None
    assert row["resolution_reason"] is None


def test_complete_scan_after_expiry_resolves_a_finding_only_durable_state_remembers(push_estate):
    push_estate.scan("asset-a", [VULN], T[1])
    _expire_all_jobs()
    push_estate.scan("asset-a", [], T[2])
    assert_at(push_estate.one(VULN[0], "resolved")["resolved_at"], T[2])


def test_explicitly_deleting_the_only_scan_removes_its_finding(push_estate):
    push_estate.scan("asset-a", [VULN], T[1])
    job = _tenant_jobs(push_estate.tenant)[0]
    with tenant_bound_context(push_estate.tenant):
        assert stores._get_store().delete(job["job_id"], tenant_id=push_estate.tenant)
    assert push_estate.rows("all") == []


def test_tenant_data_deletion_removes_durable_history(push_estate):
    from agent_bom.api.finding_lifecycle_read import purge_tenant_lifecycle

    other = Estate(push_estate.client, "push", f"lifecycle-{uuid4().hex[:10]}")
    push_estate.scan("asset-a", [VULN], T[1])
    push_estate.scan("asset-a", [VULN], T[2])
    other.scan("asset-a", [VULN], T[1])
    assert purge_tenant_lifecycle(stores._get_store(), push_estate.tenant) == 1
    _expire_all_jobs()
    assert push_estate.rows("all") == []
    assert other.one(VULN[0], "open")["status"] == "open"


def test_backfill_recovers_dates_from_retained_scans(push_estate):
    """Scans retained from before the table existed seed it on the first read."""
    push_estate.scan("asset-a", [VULN], T[1])
    push_estate.scan("asset-a", [VULN], T[2])
    push_estate.scan("asset-b", [FIXED_VULN], T[2])
    push_estate.scan("asset-b", [], T[3])
    store = stores._get_store()
    with store.finding_lifecycle_session(push_estate.tenant) as session:
        for table in ("finding_lifecycle", "finding_lifecycle_scans", "finding_lifecycle_backfill"):
            session.execute(f"DELETE FROM {table} WHERE tenant_id=?", (push_estate.tenant,))  # nosec B608
    # Until the maintenance tick runs, a read answers from the retained reports and writes nothing.
    assert_at(push_estate.one(VULN[0], "open")["first_seen"], T[1])
    assert_at(push_estate.one(FIXED_VULN[0], "resolved")["resolved_at"], T[3])
    with store.finding_lifecycle_session(push_estate.tenant, write=False) as session:
        assert session.execute("SELECT count(*) FROM finding_lifecycle WHERE tenant_id=?", (push_estate.tenant,)).fetchone()[0] == 0
    _run_backfill()
    kept = push_estate.one(VULN[0], "open")
    assert_at(kept["first_seen"], T[1])
    assert_at(kept["last_seen"], T[2])
    assert_at(push_estate.one(FIXED_VULN[0], "resolved")["resolved_at"], T[3])
    # Another tick must not count the same scans twice.
    _run_backfill()
    assert push_estate.one(VULN[0], "open")["scan_count"] == 2
    _expire_all_jobs()
    assert_at(push_estate.one(VULN[0], "open")["first_seen"], T[1])


def _count_scan_projection(monkeypatch, read) -> int:
    from agent_bom.api import scan_finding_projection, scan_finding_read

    calls = []
    original = scan_finding_projection._iter_scan_findings

    def counted(job):
        calls.append(job.job_id)
        return original(job)

    monkeypatch.setattr(scan_finding_read, "_iter_scan_findings", counted)
    read()
    return len(calls)


def _rescans(estate_: Estate, count: int) -> None:
    for day in range(count):
        at = (datetime(2026, 9, 1, tzinfo=timezone.utc) + timedelta(hours=day)).isoformat()
        estate_.scan("asset-a", [VULN], at)


def test_a_read_does_not_project_every_retained_scan(store_kind, client, monkeypatch):
    """A read's projection work follows the current scans, never how many are retained."""

    def calls_with(retained: int) -> int:
        estate_ = Estate(client, "push", f"lifecycle-{uuid4().hex[:10]}")
        _rescans(estate_, retained)

        def read() -> None:
            assert len(estate_.rows("all")) == 1
            with tenant_bound_context(estate_.tenant):
                from agent_bom.api.scan_finding_read import _completed_jobs_for_tenant, current_open_scan_findings

                assert len(current_open_scan_findings(_completed_jobs_for_tenant(estate_.tenant))) == 1

        return _count_scan_projection(monkeypatch, read)

    assert calls_with(2) == calls_with(40)


@pytest.mark.parametrize("failure", [None, RuntimeError("store down")])
def test_cleanup_loop_runs_the_backfill_tick_and_survives_its_failure(monkeypatch, failure):
    import asyncio

    from agent_bom.api import server

    ran: list[int] = []

    def tick() -> int:
        ran.append(1)
        if failure:
            raise failure
        return 0

    async def stop_after_second_pause(_seconds: float) -> None:
        if ran:
            raise asyncio.CancelledError

    async def no_cleanup() -> None:
        return None

    monkeypatch.setattr(server, "run_finding_lifecycle_tick", tick)
    monkeypatch.setattr(server, "_cleanup_tick", no_cleanup)
    monkeypatch.setattr(server.asyncio, "sleep", stop_after_second_pause)
    monkeypatch.setattr("agent_bom.api.campaign_reconciliation.poll_campaign_reconciliation", lambda: None)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(server._cleanup_loop())
    assert ran == [1]


def test_a_read_writes_no_backfill(push_estate, monkeypatch):
    from agent_bom.api.storage import finding_lifecycle as durable

    push_estate.scan("asset-a", [VULN], T[1])
    folded: list[Any] = []
    monkeypatch.setattr(durable, "apply_job_lifecycle", lambda *args: folded.append(args))
    with stores._get_store().finding_lifecycle_session(push_estate.tenant) as session:
        for table in ("finding_lifecycle", "finding_lifecycle_scans", "finding_lifecycle_backfill"):
            session.execute(f"DELETE FROM {table} WHERE tenant_id=?", (push_estate.tenant,))  # nosec B608
    assert push_estate.one(VULN[0], "open")["status"] == "open"
    assert folded == []


# ── Order, replay and concurrency against durable state ─────────────────────


def _outcome(row: dict[str, Any]) -> tuple[Any, ...]:
    return (row["status"] == "resolved", row["first_seen"], row["last_seen"], row["resolved_at"], row["last_resolved_at"])


_HISTORIES: list[list[tuple[int, bool]]] = [
    [(1, True), (2, False), (3, True)],
    [(1, True), (2, False), (3, True), (4, False)],
    [(1, True), (2, True), (3, False), (4, False)],
]


@pytest.mark.parametrize("history", _HISTORIES, ids=["reopened", "reresolved", "repeat-absence"])
def test_every_arrival_order_converges_on_the_same_dates(store_kind, client, history):
    def play(order: tuple[tuple[int, bool], ...]) -> dict[str, Any]:
        estate = Estate(client, "push", f"lifecycle-{uuid4().hex[:10]}")
        for day, present in order:
            estate.scan("asset-a", [VULN] if present else [], T[day])
        return estate.one(VULN[0])

    expected = play(tuple(history))
    for order in itertools.islice(itertools.permutations(history), 1, None):
        row = play(order)
        assert _outcome(row) == _outcome(expected), order
        assert row["scan_count"] == expected["scan_count"], order


def test_late_scan_older_than_everything_only_widens_first_seen_after_expiry(push_estate):
    push_estate.scan("asset-a", [VULN], T[10])
    push_estate.scan("asset-a", [], T[12])
    _expire_all_jobs()
    push_estate.scan("asset-a", [VULN], T[5])
    row = push_estate.one(VULN[0], "resolved")
    assert_at(row["first_seen"], T[5])
    assert_at(row["last_seen"], T[10])
    assert_at(row["resolved_at"], T[12])
    assert row["reopened_at"] is None


def test_late_absence_older_than_a_new_observation_changes_no_status_after_expiry(push_estate):
    push_estate.scan("asset-a", [VULN], T[10])
    _expire_all_jobs()
    push_estate.scan("asset-a", [], T[5])
    row = push_estate.one(VULN[0], "open")
    assert row["status"] == "open"
    assert row["resolved_at"] is None
    assert_at(row["last_seen"], T[10])


def test_late_finding_never_seen_before_arrives_resolved_when_a_newer_scan_disproves_it(push_estate):
    push_estate.scan("asset-a", [], T[10])
    push_estate.scan("asset-a", [VULN], T[5])
    row = push_estate.one(VULN[0], "resolved")
    assert_at(row["first_seen"], T[5])
    assert_at(row["resolved_at"], T[10])


def test_duplicate_delivery_of_one_job_counts_once(push_estate):
    body = {
        "source_id": "host-a",
        "target_scope": _scope_for("asset-a"),
        "generated_at": T[1],
        "findings": [_finding("asset-a", *VULN)],
        "agents": [],
        "scan_run": {"outcome": "complete"},
    }
    headers = {**push_estate.headers, "Idempotency-Key": f"dup-{uuid4().hex}"}
    for _ in range(3):
        assert push_estate.client.post("/v1/results/push", json=body, headers=headers).status_code in {200, 201}
    assert push_estate.one(VULN[0])["scan_count"] == 1


def test_rewriting_a_completed_job_does_not_replay_its_evidence(push_estate):
    push_estate.scan("asset-a", [VULN], T[1])
    store = stores._get_store()
    summary = _tenant_jobs(push_estate.tenant)[0]
    with tenant_bound_context(push_estate.tenant):
        job = store.get(summary["job_id"], push_estate.tenant)
        store.put(job)
        store.put(job)
    assert push_estate.one(VULN[0])["scan_count"] == 1


def test_future_dated_report_cannot_freeze_later_scans(push_estate):
    """An evidence time beyond the tolerated clock skew falls back to when the server stored it."""
    push_estate.scan("asset-a", [VULN], "2099-01-01T00:00:00+00:00")
    push_estate.scan("asset-a", [], _days_ago(0))
    row = push_estate.one(VULN[0], "resolved")
    assert row["status"] == "resolved"
    assert row["last_seen"] < "2099"


def test_concurrent_scans_of_one_scope_converge(store_kind, client):
    if store_kind == "sqlite":
        pytest.skip("the SQLite job store serializes writers")
    estate = Estate(client, "push", f"lifecycle-{uuid4().hex[:10]}")
    errors: list[BaseException] = []

    def push(day: int, present: bool) -> None:
        try:
            estate.scan("asset-a", [VULN] if present else [], T[day])
        except BaseException as exc:  # noqa: BLE001  # surfaced by the assertion below
            errors.append(exc)

    workers = [threading.Thread(target=push, args=(day, day % 4 != 0)) for day in range(1, 9)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert errors == []
    row = estate.one(VULN[0])
    assert row["status"] == "resolved"
    assert_at(row["first_seen"], T[1])
    assert_at(row["last_seen"], T[7])
    assert_at(row["resolved_at"], T[8])
    assert row["scan_count"] == 6


# ── Project in finding identity ──────────────────────────────────────────────


def _project_body(project: str, rows: list[dict[str, Any]], at: str, *, source: str = "ci") -> dict[str, Any]:
    return {
        "source_id": source,
        "target_scope": _scope_for(project),
        "generated_at": at,
        "findings": rows,
        "agents": [],
        "scan_run": {"outcome": "complete"},
    }


def _push(estate_: Estate, body: dict[str, Any]) -> None:
    response = estate_.client.post("/v1/results/push", json=body, headers=estate_.headers)
    assert response.status_code in {200, 201}, response.text


def test_same_package_version_in_two_projects_is_two_findings_with_their_own_lifecycle(push_estate):
    row = _finding("shared-host", *VULN)
    _push(push_estate, _project_body("project-a", [row], T[1]))
    _push(push_estate, _project_body("project-b", [row], T[2]))
    rows = push_estate.rows("open")
    assert len(rows) == 2
    assert len({item["id"] for item in rows}) == 2
    _push(push_estate, _project_body("project-a", [], T[3]))
    assert len(push_estate.rows("open")) == 1
    assert len(push_estate.rows("resolved")) == 1


def test_finding_without_a_project_keeps_the_reported_identity(push_estate):
    row = _finding("asset-a", *VULN)
    body = {"source_id": "laptop", "generated_at": T[1], "findings": [row], "agents": [], "scan_run": {"outcome": "complete"}}
    _push(push_estate, body)
    assert push_estate.one(VULN[0])["id"] == row["id"]


def test_project_identity_is_stable_and_never_exposes_the_scope(push_estate):
    row = _finding("shared-host", *VULN)
    _push(push_estate, _project_body("project-a", [row], T[1]))
    _push(push_estate, _project_body("project-a", [row], T[2]))
    found = push_estate.one(VULN[0])
    assert found["id"] != row["id"]
    assert found["canonical_id"] == found["id"]
    assert found["scan_count"] == 2
    wire = json.dumps(
        push_estate.client.get("/v1/findings", params={"status": "all", "window_days": 0}, headers=push_estate.headers).json()
    )
    assert _scope_for("project-a") not in wire
    assert "scope_hash" not in wire
    assert "target_scope" not in wire
    assert "report_canonical_id" not in wire


def test_project_identity_does_not_join_tenants(push_estate):
    other = Estate(push_estate.client, "push", f"lifecycle-{uuid4().hex[:10]}")
    row = _finding("shared-host", *VULN)
    _push(push_estate, _project_body("project-a", [row], T[1]))
    _push(other, _project_body("project-a", [row], T[1]))
    _push(push_estate, _project_body("project-a", [], T[2]))
    assert other.one(VULN[0], "open")["status"] == "open"
    assert push_estate.one(VULN[0], "resolved")["status"] == "resolved"


def test_exception_and_triage_owner_follow_both_projects(push_estate):
    from agent_bom.api.exception_store import ExceptionStatus, InMemoryExceptionStore, VulnException
    from agent_bom.api.suppression_approval import APPROVAL_VERSION

    now = datetime.now(timezone.utc)
    previous = stores._exception_store
    exceptions = InMemoryExceptionStore()
    stores.set_exception_store(exceptions)
    try:
        row = _finding("shared-host", *VULN)
        _push(push_estate, _project_body("project-a", [row], T[1]))
        _push(push_estate, _project_body("project-b", [row], T[1]))
        exceptions.put(
            VulnException(
                exception_id="exception-1",
                vuln_id=VULN[0],
                package_name=VULN[1],
                reason="accepted risk",
                requested_by="analyst",
                tenant_id=push_estate.tenant,
                status=ExceptionStatus.ACTIVE,
                approved_by="security-lead",
                approved_at=(now - timedelta(minutes=1)).isoformat(),
                approval_version=APPROVAL_VERSION,
                expires_at=(now + timedelta(days=30)).isoformat(),
            ),
            tenant_id=push_estate.tenant,
        )
        assert {item["suppressed"] for item in push_estate.rows("all")} == {True}
    finally:
        stores.set_exception_store(previous)


def test_ticket_link_filed_on_the_old_id_follows_each_project(push_estate):
    from agent_bom.ticketing.connection_store import InMemoryTicketingStore, TicketLink, set_ticketing_store

    tickets = InMemoryTicketingStore()
    set_ticketing_store(tickets)
    try:
        row = _finding("shared-host", *VULN)
        _push(push_estate, _project_body("project-a", [row], T[1]))
        _push(push_estate, _project_body("project-b", [row], T[1]))
        store = stores._get_store()
        with store.finding_lifecycle_session(push_estate.tenant) as session:
            for table in ("finding_lifecycle", "finding_lifecycle_scans", "finding_lifecycle_backfill"):
                session.execute(f"DELETE FROM {table} WHERE tenant_id=?", (push_estate.tenant,))  # nosec B608
        tickets.claim_ticket_link(
            TicketLink(
                id="link-1",
                tenant_id=push_estate.tenant,
                connection_id="conn-1",
                dedupe_key=row["id"],
                provider="jira",
                status="open",
                external_id="10001",
                key="SEC-1",
                url="https://tickets.example/SEC-1",
                created_at=T[1],
                updated_at=T[1],
            )
        )
        _run_backfill()
        ids = {item["id"] for item in push_estate.rows("all")}
        assert len(ids) == 2
        links = tickets.list_ticket_links_for_findings(push_estate.tenant, ids, limit=10)
        assert {link.dedupe_key for link in links} == ids
        assert {link.key for link in links} == {"SEC-1"}
    finally:
        set_ticketing_store(None)


# ── Stale label ──────────────────────────────────────────────────────────────


def test_unscanned_asset_is_stale_but_stays_open_and_counted(estate):
    estate.scan("asset-old", [VULN], _days_ago(40))
    estate.scan("asset-new", [FIXED_VULN], _days_ago(1))
    old = estate.one(VULN[0], "open")
    assert old["status"] == "open"
    assert old["stale"] is True
    assert estate.one(FIXED_VULN[0], "open")["stale"] is False
    assert estate.cves("open") == {VULN[0], FIXED_VULN[0]}
    assert estate.cves("stale") == {VULN[0]}
    assert estate.cves("resolved") == set()


def test_stale_period_is_configurable(estate, monkeypatch):
    estate.scan("asset-a", [VULN], _days_ago(10))
    assert estate.one(VULN[0], "open")["stale"] is False
    monkeypatch.setattr("agent_bom.config.FINDING_STALE_DAYS", 7)
    assert estate.cves("stale") == {VULN[0]}
    assert estate.one(VULN[0], "open")["stale"] is True


def test_resolved_finding_is_never_stale(estate):
    estate.scan("asset-a", [VULN], _days_ago(60))
    estate.scan("asset-a", [], _days_ago(50))
    assert estate.one(VULN[0], "resolved")["stale"] is False
    assert estate.cves("stale") == set()


def test_rescan_clears_stale(estate):
    estate.scan("asset-a", [VULN], _days_ago(40))
    estate.scan("asset-a", [VULN], _days_ago(1))
    assert estate.one(VULN[0], "open")["stale"] is False


def test_stale_finding_past_the_default_window_stays_in_the_default_list(push_estate):
    push_estate.scan("asset-a", [VULN], _days_ago(200))
    _expire_all_jobs()
    response = push_estate.client.get("/v1/findings", headers=push_estate.headers)
    assert response.status_code == 200
    rows = [row for row in response.json()["findings"] if row.get("cve_id") == VULN[0]]
    assert len(rows) == 1
    assert rows[0]["stale"] is True


def test_stale_finding_past_retention_still_counts_in_the_overview(push_estate):
    push_estate.scan("asset-a", [VULN], _days_ago(200))
    _expire_all_jobs()
    overview = push_estate.client.get("/v1/overview", headers=push_estate.headers).json()
    assert overview["issue_counts"]["total"] == 1


def test_stale_finding_outside_an_explicit_window_is_filtered(push_estate):
    push_estate.scan("asset-a", [VULN], _days_ago(200))
    _expire_all_jobs()
    response = push_estate.client.get("/v1/findings", params={"window_days": 7}, headers=push_estate.headers)
    assert [row for row in response.json()["findings"] if row.get("cve_id") == VULN[0]] == []


def test_invalid_status_filter_is_rejected(push_estate):
    response = push_estate.client.get("/v1/findings", params={"status": "bogus"}, headers=push_estate.headers)
    assert response.status_code == 422


def test_group_reports_stale_only_when_every_open_occurrence_is(estate):
    estate.scan("asset-a", [VULN], _days_ago(40))
    estate.scan("asset-b", [VULN], _days_ago(40))
    assert estate.groups("open")[VULN[0]]["stale"] is True
    estate.scan("asset-b", [VULN], _days_ago(1))
    assert estate.groups("open")[VULN[0]]["stale"] is False


# ── Resolution reason and deleted assets ─────────────────────────────────────

ACCOUNT = "123456789012"
BUCKET = "arn:aws:s3:::payments-exports"
INSTANCE = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0abc"
WEST_INSTANCE = f"arn:aws:ec2:us-west-2:{ACCOUNT}:instance/i-0def"
OTHER_ACCOUNT = "999999999999"
ALL_PERMISSIONS = ("ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "s3:ListAllMyBuckets", "iam:ListRoles", "ec2:DescribeRegions")


def _cloud_finding(arn: str, rule: str = "CIS-5.2") -> dict[str, Any]:
    return {
        "id": f"{arn}:{rule}",
        "canonical_id": f"{arn}:{rule}",
        "finding_type": "CIS_FAIL",
        "source": "cloud_cis",
        "rule_id": rule,
        "title": rule,
        "severity": "high",
        "provider": "aws",
        "account_ref": f"aws:{ACCOUNT}",
        "asset": {"name": arn.rsplit("/", 1)[-1], "asset_type": "cloud_resource", "identifier": arn},
    }


def _inventory(
    *,
    instances: tuple[str, ...] = (),
    buckets: tuple[str, ...] = (),
    regions: tuple[str, ...] = ("us-east-1", "us-west-2"),
    account: str = ACCOUNT,
    permissions: tuple[str, ...] = ALL_PERMISSIONS,
    warnings: list[str] | None = None,
    missing: list[dict[str, str]] | None = None,
    status: str = "ok",
) -> dict[str, Any]:
    """The real collector's payload shape, built by its own assembler."""
    from agent_bom.cloud.aws_inv._base import _ok_payload

    payload = _ok_payload(
        account_id=account,
        region=f"multi:{','.join(regions)}",
        scope_regions=list(regions),
        permissions_used=permissions,
        resources={
            "instances": [{"arn": arn, "instance_id": arn.rsplit("/", 1)[-1]} for arn in instances],
            "buckets": [{"arn": arn, "name": arn.rsplit(":", 1)[-1]} for arn in buckets],
        },
        warnings=warnings or [],
        missing=missing or [],
        regions=list(regions),
    )
    return {**payload, "status": status}


def _cloud_push(estate_: Estate, rows: list[dict[str, Any]], at: str, inventory: Any, *, scoped: bool = True, **extra: Any) -> None:
    body: dict[str, Any] = {
        "source_id": "aws-collector",
        "generated_at": at,
        "findings": rows,
        "agents": [],
        "cloud_inventory": inventory,
        "scan_run": {"outcome": "complete"},
        **extra,
    }
    if scoped:
        body["target_scope"] = _scope_for("aws-account")
    _push(estate_, body)


@pytest.fixture(params=[True, False], ids=["scoped", "unscoped"])
def scoped(request):
    return request.param


def _rule_row(estate_: Estate, status: str = "all") -> dict[str, Any]:
    matches = [row for row in estate_.rows(status) if row.get("title") == "CIS-5.2" or row.get("rule_id") == "CIS-5.2"]
    assert len(matches) == 1, estate_.rows("all")
    return matches[0]


def test_complete_inventory_without_the_asset_resolves_as_asset_deleted(push_estate, scoped):
    _cloud_push(push_estate, [_cloud_finding(INSTANCE)], T[1], _inventory(instances=(INSTANCE,)), scoped=scoped)
    _cloud_push(push_estate, [], T[2], _inventory(), scoped=scoped)
    row = _rule_row(push_estate, "resolved")
    assert row["status"] == "resolved"
    assert row["resolution_reason"] == "asset_deleted"
    assert_at(row["resolved_at"], T[2])
    assert_at(row["last_seen"], T[1])


def test_global_service_bucket_absent_from_complete_inventory_is_deleted(push_estate):
    _cloud_push(push_estate, [_cloud_finding(BUCKET)], T[1], _inventory(buckets=(BUCKET,)))
    _cloud_push(push_estate, [], T[2], _inventory())
    assert _rule_row(push_estate, "resolved")["resolution_reason"] == "asset_deleted"


def test_finding_gone_while_asset_remains_is_no_longer_detected(push_estate):
    _cloud_push(push_estate, [_cloud_finding(INSTANCE)], T[1], _inventory(instances=(INSTANCE,)))
    _cloud_push(push_estate, [], T[2], _inventory(instances=(INSTANCE,)))
    row = _rule_row(push_estate, "resolved")
    assert row["resolution_reason"] == "no_longer_detected"


def test_deleted_asset_returning_reopens_with_original_first_seen(push_estate, scoped):
    finding = _cloud_finding(INSTANCE)
    _cloud_push(push_estate, [finding], T[1], _inventory(instances=(INSTANCE,)), scoped=scoped)
    _cloud_push(push_estate, [], T[2], _inventory(), scoped=scoped)
    _cloud_push(push_estate, [finding], T[3], _inventory(instances=(INSTANCE,)), scoped=scoped)
    row = _rule_row(push_estate, "open")
    assert row["status"] == "reopened"
    assert_at(row["first_seen"], T[1])
    assert_at(row["reopened_at"], T[3])
    assert_at(row["last_resolved_at"], T[2])
    assert row["resolved_at"] is None
    assert row["resolution_reason"] is None


_THROTTLED = "[us-east-1] Could not list EC2 instances: ThrottlingException"
_REGION_DOWN = "Region us-east-1 skipped: EndpointConnectionError"
_DENIED = {
    "permission": "ec2:DescribeInstances",
    "resource_type": "EC2 instances",
    "cloud": "aws",
    "error_code": "AccessDenied",
}


@pytest.mark.parametrize(
    "inventory_kwargs",
    [
        pytest.param({"missing": [_DENIED]}, id="permission-removed"),
        pytest.param({"warnings": [_REGION_DOWN]}, id="region-failed"),
        pytest.param({"warnings": [_THROTTLED]}, id="throttled"),
        pytest.param({"missing": [_DENIED], "warnings": [_REGION_DOWN]}, id="permission-removed-and-region-failed"),
        pytest.param({"regions": ("us-west-2",)}, id="other-region"),
        pytest.param({"account": OTHER_ACCOUNT}, id="other-account"),
        pytest.param({"permissions": ("s3:ListAllMyBuckets",)}, id="service-not-enumerated"),
        pytest.param({"status": "no_credentials"}, id="no-credentials"),
    ],
)
def test_nothing_short_of_complete_coverage_touches_the_finding(push_estate, scoped, inventory_kwargs):
    _cloud_push(push_estate, [_cloud_finding(INSTANCE)], T[1], _inventory(instances=(INSTANCE,)), scoped=scoped)
    _cloud_push(push_estate, [], T[2], _inventory(**inventory_kwargs), scoped=scoped)
    row = _rule_row(push_estate, "open")
    assert row["status"] == "open"
    assert row["resolved_at"] is None
    assert_at(row["first_seen"], T[1])
    assert_at(row["last_seen"], T[1])


@pytest.mark.parametrize("outcome", ["partial", "failed"])
def test_partial_or_failed_receipt_with_a_clean_inventory_is_ignored(push_estate, scoped, outcome):
    _cloud_push(push_estate, [_cloud_finding(INSTANCE)], T[1], _inventory(instances=(INSTANCE,)), scoped=scoped)
    _cloud_push(push_estate, [], T[2], _inventory(), scoped=scoped, scan_run={"outcome": outcome})
    assert _rule_row(push_estate, "open")["status"] == "open"


def test_forged_complete_outcome_cannot_hide_a_permission_error(push_estate):
    _cloud_push(push_estate, [_cloud_finding(INSTANCE)], T[1], _inventory(instances=(INSTANCE,)))
    forged = _inventory(missing=[_DENIED])
    _cloud_push(push_estate, [], T[2], forged, scan_run={"outcome": "complete", "scopes": [], "issues": []})
    assert _rule_row(push_estate, "open")["status"] == "open"


def test_inventory_without_a_service_receipt_proves_nothing(push_estate):
    _cloud_push(push_estate, [_cloud_finding(INSTANCE)], T[1], _inventory(instances=(INSTANCE,)))
    bare = {"provider": "aws", "status": "ok", "account_id": ACCOUNT, "region": "us-east-1", "regions": ["us-east-1"], "instances": []}
    _cloud_push(push_estate, [], T[2], bare)
    assert _rule_row(push_estate, "open")["status"] == "open"


def test_another_sources_inventory_cannot_delete_this_sources_asset(push_estate, scoped):
    _cloud_push(push_estate, [_cloud_finding(INSTANCE)], T[1], _inventory(instances=(INSTANCE,)), scoped=scoped)
    _cloud_push(push_estate, [], T[2], _inventory(), scoped=scoped, source_id="other-collector")
    assert _rule_row(push_estate, "open")["status"] == "open"


def test_another_tenants_inventory_cannot_delete_this_tenants_asset(push_estate):
    other = Estate(push_estate.client, "push", f"lifecycle-{uuid4().hex[:10]}")
    _cloud_push(push_estate, [_cloud_finding(INSTANCE)], T[1], _inventory(instances=(INSTANCE,)))
    _cloud_push(other, [], T[2], _inventory())
    assert _rule_row(push_estate, "open")["status"] == "open"


def test_finding_without_a_provable_location_is_never_asset_deleted(push_estate):
    finding = _cloud_finding(INSTANCE)
    finding["asset"]["identifier"] = "web-server-1"
    _cloud_push(push_estate, [finding], T[1], _inventory())
    _cloud_push(push_estate, [], T[2], _inventory(), scoped=False)
    assert _rule_row(push_estate, "open")["status"] == "open"
    _cloud_push(push_estate, [], T[3], _inventory())
    assert _rule_row(push_estate, "resolved")["resolution_reason"] == "no_longer_detected"


def test_asset_in_another_region_is_untouched_by_a_regional_deletion(push_estate):
    east, west = _cloud_finding(INSTANCE), _cloud_finding(WEST_INSTANCE, "CIS-5.3")
    _cloud_push(push_estate, [east, west], T[1], _inventory(instances=(INSTANCE, WEST_INSTANCE)))
    _cloud_push(push_estate, [west], T[2], _inventory(instances=(WEST_INSTANCE,)))
    assert _rule_row(push_estate, "resolved")["resolution_reason"] == "asset_deleted"
    assert [row["rule_id"] for row in push_estate.rows("open")] == ["CIS-5.3"]


def test_bulk_resolutions_state_no_longer_detected(bulk_estate):
    bulk_estate.scan("asset-a", [VULN], T[1])
    bulk_estate.scan("asset-a", [], T[2])
    assert bulk_estate.one(VULN[0], "resolved")["resolution_reason"] == "no_longer_detected"
    bulk_estate.scan("asset-a", [VULN], T[3])
    assert bulk_estate.one(VULN[0], "open")["resolution_reason"] is None


def test_group_resolution_reason_folds_occurrences(push_estate):
    group_a, group_b = _finding("asset-a", *VULN), _finding("asset-b", *VULN)
    push_estate.scan("asset-a", [], T[1], rows=[group_a])
    push_estate.scan("asset-b", [], T[1], rows=[group_b])
    push_estate.scan("asset-a", [], T[2])
    push_estate.scan("asset-b", [], T[2])
    assert push_estate.groups("all")[VULN[0]]["resolution_reason"] == "no_longer_detected"
