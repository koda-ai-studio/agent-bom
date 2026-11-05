"""KEV, issue and coverage counts stay true when payloads are compressed at rest.

Payloads of 512 bytes or more are zstd-wrapped, so SQL cannot read keys inside
them. These contracts run on SQLite always and on Postgres when configured.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any
from uuid import uuid4

import pytest

from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore
from agent_bom.api.finding_grouping import _group_occurrence_rows
from agent_bom.api.hub_payload_codec import encode_hub_payload
from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
from agent_bom.core.severity import severity_display_bucket

LONG = "d/" * 300
OBSERVED = "2026-11-01T00:00:00Z"
SINCE = "2026-10-01T00:00:00Z"


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param(
            "postgres", marks=pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private Postgres")
        ),
    ]
)
def store(request, tmp_path) -> Iterator[Any]:
    if request.param == "sqlite":
        yield SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
        return
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    pool = _new_application_pool(min_size=1, max_size=4)
    try:
        yield PostgresComplianceHubStore(pool)
    finally:
        pool.close()


@pytest.fixture
def tenant() -> Iterator[str]:
    name = "counts-" + uuid4().hex
    token = set_current_tenant(name)
    try:
        yield name
    finally:
        reset_current_tenant(token)


def _finding(key: str, *, cve: str | None = None, package: str = "pkg", severity: str = "high", long: bool = False, **extra: Any) -> dict:
    row: dict[str, Any] = {
        "id": key,
        "severity": severity,
        "origin": "bulk_ingest",
        "source": "test",
        "package": package,
        "ingest_source": "test",
        "finding_type": "CVE" if cve else "POLICY",
        "location": f"srv/{key}/" + (LONG if long else "") + "requirements.txt",
        **extra,
    }
    if cve:
        row["vulnerability_id"] = cve
    return row


def _ingest(store: Any, tenant: str, rows: list[dict], batch: str = "b1", source: str = "test") -> None:
    store.ingest_batch_atomic(
        tenant, rows, observed_at=OBSERVED, batch_id=batch, source=source, reconcile_absent=False, present_canonical_ids=set()
    )


def _rows(store: Any, tenant: str, **kwargs: Any) -> list[dict]:
    rows, _total, _cursor = store.list_current_page(tenant, limit=500, origin="bulk_ingest", since=SINCE, status="open", **kwargs)
    return rows


def _kev(store: Any, tenant: str) -> int:
    return store.current_kev_count(tenant, origin="bulk_ingest", since=SINCE, status="open")


def test_compressed_cve_payloads_keep_their_kev_flag(store, tenant) -> None:
    short = [_finding(f"s{i}", cve=f"CVE-2095-{i}", is_kev=True) for i in range(5)]
    long = [_finding(f"l{i}", cve=f"CVE-2096-{i}", is_kev=True, long=True) for i in range(5)]
    plain = [_finding("p", cve="CVE-2097-1", long=True)]
    _ingest(store, tenant, short + long + plain)

    assert _kev(store, tenant) == 10
    assert {row["id"] for row in _rows(store, tenant, scope={"kev": "true"})} == {row["id"] for row in short + long}


def test_compressed_non_cve_payload_counts_through_its_own_flag(store, tenant) -> None:
    _ingest(
        store,
        tenant,
        [_finding("direct", long=True, is_kev=True), _finding("alias", long=True, cisa_kev=True), _finding("none", long=True)],
    )

    assert _kev(store, tenant) == 2


def test_string_false_is_not_kev(store, tenant) -> None:
    _ingest(store, tenant, [_finding("str-false", long=True, cisa_kev="false"), _finding("str-true", cisa_kev="true")])

    assert _kev(store, tenant) == 1


def test_large_cve_intel_blob_keeps_kev(store, tenant) -> None:
    _ingest(store, tenant, [_finding("big", cve="CVE-2095-9", is_kev=True, summary="s" * 2000)])

    assert _kev(store, tenant) == 1


def test_kev_survives_a_later_finding_without_a_kev_flag(store, tenant) -> None:
    _ingest(store, tenant, [_finding("first", cve="CVE-2095-7", is_kev=True, long=True)], batch="b1")
    _ingest(store, tenant, [_finding("second", cve="CVE-2095-7", summary="no verdict")], batch="b2")

    drill = [row for row in _rows(store, tenant) if row.get("is_kev") is True]
    assert _kev(store, tenant) == len(drill) == 2


def test_kev_survives_a_later_explicit_false(store, tenant) -> None:
    _ingest(store, tenant, [_finding("first", cve="CVE-2095-8", is_kev=True)], batch="b1")
    _ingest(store, tenant, [_finding("second", cve="CVE-2095-8", is_kev=False, cisa_kev=False)], batch="b2")

    drill = [row for row in _rows(store, tenant) if row.get("is_kev") is True]
    assert _kev(store, tenant) == len(drill) == 2


def test_finding_with_no_intel_fields_follows_its_cves_kev_verdict(store, tenant) -> None:
    _ingest(store, tenant, [_finding("bare-first", cve="CVE-2095-6")], batch="b0")
    _ingest(store, tenant, [_finding("flagged", cve="CVE-2095-6", is_kev=True)], batch="b1")
    _ingest(store, tenant, [_finding("bare-later", cve="CVE-2095-6")], batch="b2")

    drill = {row["id"] for row in _rows(store, tenant) if row.get("is_kev") is True}
    assert drill == {"bare-first", "flagged", "bare-later"}
    assert _kev(store, tenant) == 3


def test_later_partial_intel_keeps_earlier_cve_fields(store, tenant) -> None:
    first = _finding("first", cve="CVE-2095-9", summary="old", epss_percentile=0.91, nvd_url="https://nvd.example/1", long=True)
    _ingest(store, tenant, [first], batch="b1")
    _ingest(store, tenant, [_finding("second", cve="CVE-2095-9", summary="new", nvd_url="", references=[])], batch="b2")

    rows = {row["id"]: row for row in _rows(store, tenant)}
    assert rows["first"]["summary"] == rows["second"]["summary"] == "new"
    assert rows["second"]["epss_percentile"] == 0.91
    assert rows["second"]["nvd_url"] == "https://nvd.example/1"


def test_kev_is_scoped_by_tenant_on_a_shared_cve(store, tenant) -> None:
    other = tenant + "-b"
    _ingest(store, tenant, [_finding("a", cve="CVE-2095-1", is_kev=True, long=True)])
    token = set_current_tenant(other)
    try:
        _ingest(store, other, [_finding("a", cve="CVE-2095-1", summary="not exploited", long=True), _finding("b", long=True)])
        assert _kev(store, other) == 0
        counts = store.current_issue_group_counts(other, origin="bulk_ingest", since=SINCE, status="open")
        assert (counts["total"], counts["kev"]) == (2, 0)
        assert _rows(store, other, scope={"kev": "true"}) == []
    finally:
        reset_current_tenant(token)
    assert _kev(store, tenant) == 1


def test_kev_excludes_resolved_and_old_rows(store, tenant) -> None:
    _ingest(
        store,
        tenant,
        [_finding("open", cve="CVE-2095-2", is_kev=True, long=True), _finding("gone", cve="CVE-2095-3", is_kev=True, long=True)],
    )
    store.reconcile_current_absent(tenant, present_canonical_ids={"open"}, observed_at=OBSERVED)

    assert _kev(store, tenant) == 1
    assert store.current_kev_count(tenant, origin="bulk_ingest", since="2026-12-01T00:00:00Z", status="open") == 0


def test_scoped_reconcile_reads_source_from_compressed_overlay(store, tenant) -> None:
    long_id = "long-" + "x" * 600
    _ingest(store, tenant, [_finding(long_id, ingest_source="scope-a"), _finding("kept", ingest_source="scope-b")], source="scope-a")
    reconciled = store.reconcile_current_absent(tenant, present_canonical_ids=set(), observed_at=OBSERVED, scope_source="scope-a")

    assert reconciled == 1
    assert store.get_current(tenant, long_id)["status"] == "resolved"
    assert store.get_current(tenant, "kept")["status"] == "open"


def _issue_rows() -> list[dict]:
    return [
        # One advisory on one package across assets: one issue at its worst severity.
        _finding("a1", cve="CVE-2095-10", package="alpha", severity="low", long=True),
        _finding("a2", cve="CVE-2095-10", package="alpha", severity="critical", is_kev=True),
        _finding("b1", cve="CVE-2095-10", package="beta", severity="medium"),
        _finding("c1", severity="high", long=True),
        _finding("d1", severity="info"),
        _finding("e1", severity="unknown"),
        _finding("f1", severity="moderate", cve="CVE-2095-11", package="gamma"),
    ]


def test_issue_group_aggregate_equals_the_walk(store, tenant) -> None:
    _ingest(store, tenant, _issue_rows())

    counts = store.current_issue_group_counts(tenant, origin="bulk_ingest", since=SINCE, status="open")
    groups = _group_occurrence_rows(_rows(store, tenant))
    walked: dict[str, int] = {}
    for group in groups:
        band = severity_display_bucket(group.get("severity"))
        walked[band] = walked.get(band, 0) + 1
    assert counts["total"] == len(groups) == 6
    assert {band: counts[band] for band in walked} == walked
    assert (counts["critical"], counts["high"], counts["medium"], counts["low"], counts["unrated"]) == (1, 1, 2, 0, 2)
    assert (counts["info"], counts["unknown"]) == (1, 1)
    assert counts["kev"] == sum(1 for group in groups if group.get("is_kev")) == 2


def test_group_lookup_merges_named_groups_only(store, tenant) -> None:
    from agent_bom.api.storage.finding_materialized import issue_group_id

    _ingest(store, tenant, _issue_rows())
    groups = _group_occurrence_rows(_rows(store, tenant))
    alpha = next(group for group in groups if group.get("package") == "alpha")
    wanted = issue_group_id(alpha)

    found = store.current_issue_group_lookup(tenant, [wanted, "absent"], origin="bulk_ingest", since=SINCE, status="open")
    assert found == {wanted: (5, True)}


def test_coverage_aggregate_equals_the_row_fold(store, tenant) -> None:
    from agent_bom.api.overview_cve_counts import empty_cve_counts
    from agent_bom.api.overview_rollup import _COVERAGE_DOMAINS, _empty_severity, _fold_current_coverage

    _ingest(store, tenant, _issue_rows())
    lanes: dict[str, dict[str, int]] = {domain: _empty_severity() for domain in _COVERAGE_DOMAINS}
    lanes["_cves"] = empty_cve_counts()
    for row in _rows(store, tenant):
        _fold_current_coverage(lanes, row)

    assert store.current_coverage_counts(tenant, origin="bulk_ingest", since=SINCE, status="open") == lanes
    assert lanes["_cves"]["kev"] == 3


def _make_legacy(store: Any, tenant: str) -> None:
    """Return rows and intel to the state a pre-upgrade writer left them in."""
    params = (tenant,)
    if isinstance(store, SQLiteComplianceHubStore):
        store._conn.execute(
            "UPDATE hub_findings_current SET issue_group_id = NULL, kev_direct = 0, intel_ref = '', lens_mask = 0 WHERE tenant_id = ?",
            params,
        )
        store._conn.commit()
        return
    from agent_bom.api.postgres_common import _tenant_connection

    with _tenant_connection(store._pool) as conn:
        conn.execute(
            "UPDATE hub_findings_current SET issue_group_id = NULL, kev_direct = FALSE, intel_ref = '', lens_mask = 0 WHERE tenant_id = %s",
            params,
        )
        conn.commit()


def test_backfill_is_resumable_and_restores_every_count(store, tenant) -> None:
    if not isinstance(store, SQLiteComplianceHubStore) and not os.environ.get("AGENT_BOM_POSTGRES_MAINTENANCE_URL"):
        pytest.skip("requires the maintenance role")
    rows = _issue_rows() + [_finding(f"k{i}", cve=f"CVE-2094-{i}", is_kev=True, long=True) for i in range(4)]
    _ingest(store, tenant, rows)
    expected = store.current_issue_group_counts(tenant, origin="bulk_ingest", since=SINCE, status="open")
    expected_kev = _kev(store, tenant)
    before = store.overview_evidence_revision(tenant)
    _make_legacy(store, tenant)

    assert store.current_materialization_pending(tenant) is True
    assert store.current_issue_group_counts(tenant, origin="bulk_ingest", since=SINCE, status="open") is None
    assert store.current_coverage_counts(tenant, origin="bulk_ingest", since=SINCE, status="open") is None
    # While rows are pending the drill walks payloads, so it still finds compressed KEV rows.
    assert len(_rows(store, tenant, scope={"kev": "true"})) == expected_kev

    assert store.backfill_materialized_batch(3) == 3
    assert store.current_materialization_pending(tenant) is True
    while store.backfill_materialized_batch(3):
        pass

    assert store.current_materialization_pending(tenant) is False
    assert store.current_issue_group_counts(tenant, origin="bulk_ingest", since=SINCE, status="open") == expected
    assert _kev(store, tenant) == expected_kev
    assert store.overview_evidence_revision(tenant) > before


def test_sqlite_upgrade_backfills_an_existing_database(tmp_path) -> None:
    path = str(tmp_path / "old.db")
    tenant = "upgrade-" + uuid4().hex
    store = SQLiteComplianceHubStore(path)
    _ingest(store, tenant, [_finding("old", cve="CVE-2093-1", is_kev=True, long=True), _finding("own", long=True, is_kev=True)])
    conn = store._conn
    conn.execute("UPDATE hub_findings_current SET issue_group_id = NULL, kev_direct = 0, intel_ref = ''")
    conn.execute("DROP INDEX IF EXISTS idx_hub_cve_intel_kev")
    conn.execute("ALTER TABLE hub_cve_intel DROP COLUMN is_kev")
    conn.execute(
        "UPDATE hub_cve_intel SET payload = ?",
        (encode_hub_payload({"is_kev": True, "summary": "s" * 2000}),),
    )
    conn.commit()

    upgraded = SQLiteComplianceHubStore(path)

    assert upgraded.current_materialization_pending(tenant) is False
    assert _kev(upgraded, tenant) == 2


def test_failing_frameworks_read_live_severe_rows_only(store, tenant) -> None:
    tagged = {"applicable_frameworks": ["iso_27001", "soc2"]}
    _ingest(
        store,
        tenant,
        [
            _finding("hit", severity="critical", long=True, **tagged),
            _finding("alias", severity="high", applicable_frameworks=["ISO-27001"]),
            _finding("mild", severity="low", **tagged),
            _finding("gone", severity="critical", **tagged),
        ],
    )
    store.reconcile_current_absent(tenant, present_canonical_ids={"hit", "alias", "mild"}, observed_at=OBSERVED)

    counts = store.current_failing_framework_slug_counts(tenant, origin="bulk_ingest", since=SINCE, status="open")

    assert counts == {"iso-27001": 2, "soc2": 1}


def test_read_rows_resolve_to_the_group_id_the_write_stored(store, tenant) -> None:
    from agent_bom.api.storage.finding_materialized import issue_group_id

    _ingest(store, tenant, _issue_rows())
    ids = {issue_group_id(row) for row in _rows(store, tenant)}

    assert len(ids) == 6
    assert set(store.current_issue_group_lookup(tenant, list(ids), origin="bulk_ingest", since=SINCE, status="open")) == ids
