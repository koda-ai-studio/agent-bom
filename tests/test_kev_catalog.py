"""KEV follows the CISA catalog, and only a catalog that can be trusted may clear it."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import pytest

from agent_bom.api import hub_cve_intel_tick
from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore
from agent_bom.api.hub_payload_codec import decode_hub_payload, encode_hub_payload
from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
from agent_bom.api.read_models.estate import FindingRow
from agent_bom.api.storage.cve_intel_reconcile import reconcile_row
from agent_bom.db.kev_catalog import MIN_TRUSTED_ENTRIES, KevCatalog, KevEntry, load_trusted_kev_catalog
from agent_bom.db.schema import init_db
from agent_bom.db.sync_exploit_feeds import sync_kev
from agent_bom.finding_scope import safe_finding_response_payload

OBSERVED = "2026-11-01T00:00:00Z"
SINCE = "2026-10-01T00:00:00Z"
LISTED = "CVE-2090-1"
DELISTED = "CVE-2090-2"
LONG_AGO = "2020-01-01T00:00:00Z"


def _feed(cves: list[str], *, count: int | None = None) -> dict[str, Any]:
    return {
        "title": "t",
        "catalogVersion": "2026.11.04",
        "dateReleased": "2026-11-04T20:00:05.774Z",
        "count": len(cves) if count is None else count,
        "vulnerabilities": [
            {"cveID": cve, "dateAdded": "2026-10-01", "dueDate": "2026-10-22", "product": "p", "vendorProject": "v"} for cve in cves
        ],
    }


def _many(*extra: str) -> list[str]:
    return [f"CVE-2089-{index}" for index in range(MIN_TRUSTED_ENTRIES)] + list(extra)


def _catalog(*cves: str, synced_at: datetime | None = None) -> KevCatalog:
    entries = {cve: KevEntry("2026-10-01", "2026-10-22") for cve in cves}
    return KevCatalog(entries, synced_at or datetime.now(timezone.utc), "2026.11.04", "test")


def _sync(db: Path, feed: Any) -> int:
    conn = init_db(db)
    try:
        with patch("agent_bom.http_client.fetch_json", return_value=feed):
            return sync_kev(conn, url="https://fake/kev.json")
    finally:
        conn.close()


def _entries(db: Path) -> set[str]:
    conn = init_db(db)
    try:
        return {row[0] for row in conn.execute("SELECT cve_id FROM kev_entries").fetchall()}
    finally:
        conn.close()


NO_CACHE = Path("/nonexistent/kev_cache.json")


def test_complete_feed_replaces_entries_and_records_the_catalog(tmp_path) -> None:
    db = tmp_path / "vulns.db"
    _sync(db, _feed(_many(LISTED, DELISTED)))
    assert _sync(db, _feed(_many(LISTED))) == MIN_TRUSTED_ENTRIES + 1

    assert DELISTED not in _entries(db)
    catalog = load_trusted_kev_catalog(db_path=db, cache_path=NO_CACHE)
    assert catalog is not None
    assert catalog.version == "2026.11.04"
    assert catalog.entries[LISTED] == KevEntry("2026-10-01", "2026-10-22")
    assert DELISTED not in catalog.entries


@pytest.mark.parametrize(
    ("label", "second"),
    [
        ("declared count disagrees", _feed(_many(LISTED), count=99999)),
        ("no declared count", {"vulnerabilities": _feed(_many(LISTED))["vulnerabilities"]}),
    ],
)
def test_incomplete_feed_never_removes_and_is_not_trusted(tmp_path, label, second) -> None:
    db = tmp_path / "vulns.db"
    _sync(db, _feed(_many(LISTED, DELISTED)))
    _sync(db, second)

    assert DELISTED in _entries(db), label
    assert load_trusted_kev_catalog(db_path=db, cache_path=NO_CACHE) is None


@pytest.mark.parametrize("bad", [{"count": 0, "vulnerabilities": []}, {"vulnerabilities": "nope"}, [], "oops", None])
def test_empty_or_malformed_feed_keeps_entries_and_the_last_good_sync(tmp_path, bad) -> None:
    db = tmp_path / "vulns.db"
    _sync(db, _feed(_many(LISTED, DELISTED)))
    before = load_trusted_kev_catalog(db_path=db, cache_path=NO_CACHE)

    assert _sync(db, bad) == 0

    assert DELISTED in _entries(db)
    after = load_trusted_kev_catalog(db_path=db, cache_path=NO_CACHE)
    assert after is not None and before is not None
    assert after.synced_at == before.synced_at


def test_sharp_shrink_is_held_back_even_when_the_count_matches(tmp_path) -> None:
    db = tmp_path / "vulns.db"
    _sync(db, _feed(_many(LISTED, DELISTED) + [f"CVE-2088-{index}" for index in range(5000)]))
    _sync(db, _feed(_many(LISTED)))

    assert DELISTED in _entries(db)
    assert load_trusted_kev_catalog(db_path=db, cache_path=NO_CACHE) is None


def test_small_catalog_is_not_trusted(tmp_path) -> None:
    db = tmp_path / "vulns.db"
    _sync(db, _feed([LISTED]))
    assert load_trusted_kev_catalog(db_path=db, cache_path=NO_CACHE) is None


def test_stale_catalog_is_not_trusted(tmp_path) -> None:
    db = tmp_path / "vulns.db"
    _sync(db, _feed(_many(LISTED)))
    later = datetime.now(timezone.utc) + timedelta(days=8)
    assert load_trusted_kev_catalog(db_path=db, cache_path=NO_CACHE, now=later) is None


def test_missing_or_corrupt_sources_are_not_trusted(tmp_path) -> None:
    corrupt = tmp_path / "kev_cache.json"
    corrupt.write_text("{not json", encoding="utf-8")
    bad_db = tmp_path / "vulns.db"
    bad_db.write_bytes(b"not a database")
    assert load_trusted_kev_catalog(db_path=tmp_path / "absent.db", cache_path=tmp_path / "absent.json") is None
    assert load_trusted_kev_catalog(db_path=bad_db, cache_path=corrupt) is None


def _cache_file(path: Path, *, complete: bool, age_seconds: float = 0) -> None:
    data = {cve: {"date_added": "2026-10-01", "due_date": "2026-10-22"} for cve in _many(LISTED)}
    path.write_text(
        json.dumps({"_cached_at": time.time() - age_seconds, "data": data, "catalog": {"complete": complete, "catalog_version": "v"}}),
        encoding="utf-8",
    )


def test_scan_cache_is_used_only_when_complete_and_fresh(tmp_path) -> None:
    cache = tmp_path / "kev_cache.json"
    absent = tmp_path / "absent.db"
    _cache_file(cache, complete=True)
    catalog = load_trusted_kev_catalog(db_path=absent, cache_path=cache)
    assert catalog is not None and catalog.source == "scan_cache" and LISTED in catalog.entries

    _cache_file(cache, complete=False)
    assert load_trusted_kev_catalog(db_path=absent, cache_path=cache) is None
    _cache_file(cache, complete=True, age_seconds=8 * 86400)
    assert load_trusted_kev_catalog(db_path=absent, cache_path=cache) is None
    # A cache written before the file recorded completeness proves nothing.
    data = json.loads(cache.read_text(encoding="utf-8"))
    del data["catalog"]
    data["_cached_at"] = time.time()
    cache.write_text(json.dumps(data), encoding="utf-8")
    assert load_trusted_kev_catalog(db_path=absent, cache_path=cache) is None


def test_scan_path_persists_catalog_completeness(tmp_path, monkeypatch) -> None:
    import asyncio

    from agent_bom import enrichment

    cache = tmp_path / "kev_cache.json"
    monkeypatch.setattr(enrichment, "_KEV_CACHE_FILE", cache)
    monkeypatch.setattr(enrichment, "_kev_cache", None)
    monkeypatch.setattr(enrichment, "_kev_cache_time", None)

    class _Response:
        status_code = 200

        @staticmethod
        def json() -> dict[str, Any]:
            return _feed(_many(LISTED))

    async def fake_upstream(*_args: Any, **_kwargs: Any) -> Any:
        return _Response()

    monkeypatch.setattr(enrichment, "upstream_request", fake_upstream)
    asyncio.run(enrichment.fetch_cisa_kev_catalog(None))  # type: ignore[arg-type]

    catalog = load_trusted_kev_catalog(db_path=tmp_path / "absent.db", cache_path=cache)
    assert catalog is not None and catalog.version == "2026.11.04" and LISTED in catalog.entries


def test_row_rules_without_and_with_a_catalog() -> None:
    assert reconcile_row(LISTED, {"is_kev": True}, False, LONG_AGO, None) == ({"is_kev": True}, True)
    assert reconcile_row(LISTED, {"summary": "s"}, True, LONG_AGO, None) == ({"summary": "s", "is_kev": True}, True)
    assert reconcile_row(LISTED, {"is_kev": False}, False, LONG_AGO, None) == ({"is_kev": False}, False)

    listed, kev = reconcile_row(LISTED, {"is_kev": False}, False, LONG_AGO, _catalog(LISTED))
    assert kev is True
    assert listed == {"is_kev": True, "kev_added_date": "2026-10-01", "kev_due_date": "2026-10-22"}

    cleared, kev = reconcile_row(
        DELISTED, {"cisa_kev": True, "kev_due_date": "2026-01-01", "summary": "s"}, True, LONG_AGO, _catalog(LISTED)
    )
    assert kev is False
    assert cleared == {"is_kev": False, "summary": "s"}


def test_clear_drops_dates_when_only_the_column_claimed_kev() -> None:
    cleared, kev = reconcile_row(DELISTED, {"kev_due_date": "2026-01-01"}, True, LONG_AGO, _catalog(LISTED))
    assert kev is False
    assert cleared == {"is_kev": False}


def test_a_failing_intel_tick_does_not_stop_the_materialization_tick(monkeypatch) -> None:
    from agent_bom.api import hub_materialization

    calls: list[int] = []

    class _Store:
        @staticmethod
        def backfill_materialized_batch(limit: int) -> int:
            calls.append(limit)
            return 0

    def boom(**_kwargs: Any) -> int:
        raise RuntimeError("database unavailable")

    monkeypatch.setattr("agent_bom.api.compliance_hub_store.get_compliance_hub_store", lambda: _Store())
    monkeypatch.setattr(hub_materialization, "run_cve_intel_tick", boom)

    with pytest.raises(RuntimeError):
        hub_materialization.run_materialization_tick(budget_seconds=1, batch_rows=3)
    assert calls == [3]


def test_claim_newer_than_the_catalog_is_kept() -> None:
    synced = datetime(2026, 11, 1, tzinfo=timezone.utc)
    catalog = _catalog(LISTED, synced_at=synced)
    assert reconcile_row(DELISTED, {"is_kev": True}, True, "2026-11-02T00:00:00Z", catalog)[1] is True
    assert reconcile_row(DELISTED, {"is_kev": True}, True, "not a time", catalog)[1] is True
    assert reconcile_row(DELISTED, {"is_kev": True}, True, "2026-10-31T00:00:00Z", catalog)[1] is False


def test_response_carries_catalog_dates() -> None:
    row = {"id": "f", "severity": "high", "is_kev": True, "kev_added_date": "2026-10-01", "kev_due_date": "2026-10-22"}
    payload = safe_finding_response_payload(row)
    assert payload["kev_date_added"] == "2026-10-01"
    assert FindingRow.model_validate(payload).kev_date_added == "2026-10-01"
    assert str(payload["kev_due_date"]).startswith("2026-10-22")


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param(
            "postgres",
            marks=pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_MAINTENANCE_URL"), reason="requires maintenance role"),
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


def _ingest(store: Any, tenant: str, rows: list[dict[str, Any]], batch: str = "b1") -> None:
    store.ingest_batch_atomic(
        tenant, rows, observed_at=OBSERVED, batch_id=batch, source="test", reconcile_absent=False, present_canonical_ids=set()
    )


def _finding(key: str, cve: str, **extra: Any) -> dict[str, Any]:
    return {"id": key, "severity": "high", "origin": "bulk_ingest", "source": "test", "package": "pkg", "vulnerability_id": cve, **extra}


def _kev(store: Any, tenant: str) -> int:
    return store.current_kev_count(tenant, origin="bulk_ingest", since=SINCE, status="open")


def _rows(store: Any, tenant: str) -> list[dict[str, Any]]:
    rows, _total, _cursor = store.list_current_page(tenant, limit=100, origin="bulk_ingest", since=SINCE, status="open")
    return rows


def _intel(store: Any, tenant: str, cve: str) -> tuple[dict[str, Any], bool] | None:
    if isinstance(store, SQLiteComplianceHubStore):
        row = store._conn.execute("SELECT payload, is_kev FROM hub_cve_intel WHERE tenant_id = ? AND cve_id = ?", (tenant, cve)).fetchone()
    else:
        from agent_bom.api.postgres_common import _tenant_connection

        with _tenant_connection(store._pool) as conn:
            row = conn.execute("SELECT payload, is_kev FROM hub_cve_intel WHERE tenant_id = %s AND cve_id = %s", (tenant, cve)).fetchone()
            conn.rollback()
    return (decode_hub_payload(row[0]), bool(row[1])) if row else None


def _age_claims(store: Any, tenant: str) -> None:
    if isinstance(store, SQLiteComplianceHubStore):
        store._conn.execute("UPDATE hub_cve_intel SET updated_at = ? WHERE tenant_id = ?", (LONG_AGO, tenant))
        store._conn.commit()
        return
    from agent_bom.api.postgres_common import _tenant_connection

    with _tenant_connection(store._pool) as conn:
        conn.execute("UPDATE hub_cve_intel SET updated_at = %s WHERE tenant_id = %s", (LONG_AGO, tenant))
        conn.commit()


def _tenant_rows(store: Any, tenant: str) -> int:
    if isinstance(store, SQLiteComplianceHubStore):
        return int(store._conn.execute("SELECT COUNT(*) FROM hub_cve_intel WHERE tenant_id = ?", (tenant,)).fetchone()[0])
    from agent_bom.api.postgres_common import _tenant_connection

    token = set_current_tenant(tenant)
    try:
        with _tenant_connection(store._pool) as conn:
            count = conn.execute("SELECT COUNT(*) FROM hub_cve_intel WHERE tenant_id = %s", (tenant,)).fetchone()[0]
            conn.rollback()
    finally:
        reset_current_tenant(token)
    return int(count)


def _walk(store: Any, catalog: KevCatalog | None, tenants: tuple[str, str]) -> set[str]:
    """Walk exactly these sibling tenants: a test database is shared, and the walk crosses tenants."""
    first, second = sorted(tenants)
    page = store.reconcile_cve_intel_batch((first, ""), _tenant_rows(store, first) + _tenant_rows(store, second), catalog)
    return set(page.tenants)


@pytest.fixture
def tenants() -> Iterator[tuple[str, str]]:
    stem = "kev-" + uuid4().hex
    first, second = stem + "-a", stem + "-b"
    token = set_current_tenant(first)
    try:
        yield first, second
    finally:
        reset_current_tenant(token)


def test_catalog_sets_and_clears_within_each_tenant_only(store, tenants) -> None:
    alpha, beta = tenants
    cve_only_alpha = "CVE-2090-" + uuid4().hex[:8].upper()
    _ingest(store, alpha, [_finding("a1", LISTED), _finding("a2", DELISTED, is_kev=True), _finding("a3", cve_only_alpha, is_kev=True)])
    token = set_current_tenant(beta)
    try:
        _ingest(store, beta, [_finding("b1", LISTED, is_kev=False)])
        _age_claims(store, beta)
    finally:
        reset_current_tenant(token)
    _age_claims(store, alpha)
    assert _kev(store, alpha) == 2

    touched = _walk(store, _catalog(LISTED, cve_only_alpha), tenants)

    assert {alpha, beta} <= touched
    assert {row["id"] for row in _rows(store, alpha) if row.get("is_kev") is True} == {"a1", "a3"}
    assert _kev(store, alpha) == 2
    delisted = _intel(store, alpha, DELISTED)
    assert delisted is not None and delisted[1] is False and delisted[0]["is_kev"] is False
    listed = _intel(store, alpha, LISTED)
    assert (
        listed is not None
        and listed[1] is True
        and listed[0]["kev_added_date"] == "2026-10-01"
        and listed[0]["kev_due_date"] == "2026-10-22"
    )
    by_id = {row["id"]: row for row in _rows(store, alpha)}
    assert str(by_id["a1"]["kev_due_date"]).startswith("2026-10-22")

    # The catalog listed a CVE only alpha has; beta gains no record of it.
    token = set_current_tenant(beta)
    try:
        assert _intel(store, beta, cve_only_alpha) is None
        assert _intel(store, beta, DELISTED) is None
        assert _kev(store, beta) == 1
        assert {row["id"] for row in _rows(store, beta) if row.get("is_kev") is True} == {"b1"}
    finally:
        reset_current_tenant(token)


def test_without_a_catalog_every_flag_is_kept(store, tenants) -> None:
    alpha, _beta = tenants
    _ingest(store, alpha, [_finding("a", DELISTED, is_kev=True)])
    _age_claims(store, alpha)

    _walk(store, None, tenants)

    assert _kev(store, alpha) == 1
    assert {row["id"] for row in _rows(store, alpha) if row.get("is_kev") is True} == {"a"}


def test_a_later_scan_false_does_not_override_a_catalog_listing(store, tenants) -> None:
    alpha, _beta = tenants
    _ingest(store, alpha, [_finding("a", LISTED)])
    _walk(store, _catalog(LISTED), tenants)
    _ingest(store, alpha, [_finding("b", LISTED, is_kev=False, cisa_kev=False)], batch="b2")

    assert _kev(store, alpha) == 2
    intel = _intel(store, alpha, LISTED)
    assert intel is not None and intel[1] is True and intel[0]["kev_due_date"] == "2026-10-22"


def test_tick_spans_batches_and_keeps_flags_when_no_catalog_exists(tmp_path, monkeypatch) -> None:
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    tenant = "tick-" + uuid4().hex
    _ingest(store, tenant, [_finding(f"f{index}", f"CVE-2087-{index}", is_kev=True) for index in range(7)])
    _age_claims(store, tenant)
    monkeypatch.setattr("agent_bom.api.compliance_hub_store.get_compliance_hub_store", lambda: store)
    monkeypatch.setattr(hub_cve_intel_tick, "load_trusted_kev_catalog", lambda: None)
    hub_cve_intel_tick.reset_cve_intel_pass()
    try:
        assert hub_cve_intel_tick.run_cve_intel_tick(budget_seconds=5, batch_rows=2) >= 7
        assert _kev(store, tenant) == 7
        assert hub_cve_intel_tick.run_cve_intel_tick(budget_seconds=5, batch_rows=2) == 0, "no second pass within the hour"
    finally:
        hub_cve_intel_tick.reset_cve_intel_pass()


def test_tick_resumes_after_a_budget_runs_out_and_applies_the_catalog(tmp_path, monkeypatch) -> None:
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    tenant = "tick-" + uuid4().hex
    _ingest(store, tenant, [_finding(f"f{index}", f"CVE-2087-{index}") for index in range(5)])
    monkeypatch.setattr("agent_bom.api.compliance_hub_store.get_compliance_hub_store", lambda: store)
    monkeypatch.setattr(hub_cve_intel_tick, "load_trusted_kev_catalog", lambda: _catalog(*[f"CVE-2087-{index}" for index in range(5)]))
    hub_cve_intel_tick.reset_cve_intel_pass()
    try:
        ticks = 0
        hub_cve_intel_tick.run_cve_intel_tick(budget_seconds=0, batch_rows=2)
        while hub_cve_intel_tick._state.started:
            hub_cve_intel_tick._step(store, 2)
            ticks += 1
        assert ticks > 2
        assert _kev(store, tenant) == 5
    finally:
        hub_cve_intel_tick.reset_cve_intel_pass()


def test_payload_and_column_disagreement_is_repaired(store, tenants) -> None:
    alpha, _beta = tenants
    _ingest(
        store, alpha, [_finding("col", "CVE-2086-1", summary="s", is_kev=True), _finding("pay", "CVE-2086-2", summary="s", is_kev=True)]
    )
    if isinstance(store, SQLiteComplianceHubStore):
        store._conn.execute(
            "UPDATE hub_cve_intel SET payload = ? WHERE tenant_id = ? AND cve_id = 'CVE-2086-1'",
            (encode_hub_payload({"summary": "s"}), alpha),
        )
        store._conn.execute("UPDATE hub_cve_intel SET is_kev = 0 WHERE tenant_id = ? AND cve_id = 'CVE-2086-2'", (alpha,))
        store._conn.commit()
    else:
        from agent_bom.api.postgres_common import _tenant_connection

        with _tenant_connection(store._pool) as conn:
            conn.execute(
                "UPDATE hub_cve_intel SET payload = '{\"summary\": \"s\"}'::jsonb WHERE tenant_id = %s AND cve_id = 'CVE-2086-1'", (alpha,)
            )
            conn.execute("UPDATE hub_cve_intel SET is_kev = FALSE WHERE tenant_id = %s AND cve_id = 'CVE-2086-2'", (alpha,))
            conn.commit()

    _walk(store, None, tenants)

    for cve in ("CVE-2086-1", "CVE-2086-2"):
        intel = _intel(store, alpha, cve)
        assert intel is not None and intel[1] is True and intel[0]["is_kev"] is True
    assert {row["id"] for row in _rows(store, alpha) if row.get("is_kev") is True} == {"col", "pay"}
    assert _kev(store, alpha) == 2
