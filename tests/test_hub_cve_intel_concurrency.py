"""Concurrent writers on one CVE keep every field and agree on KEV in column and payload.

Postgres runs use real connections, because an in-process lock proves nothing about
two replicas. Ingest serializes on the tenant lock; these also write through
``persist_references`` without it, so the row lock is what they exercise.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from uuid import uuid4

import pytest

from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore
from agent_bom.api.hub_payload_codec import decode_hub_payload
from agent_bom.api.storage.finding_ledger_writes import write_ledger_batch
from agent_bom.api.storage.finding_payloads import persist_cve_intel, persist_references
from agent_bom.api.storage.sql import connection_session

OBSERVED = "2026-11-01T00:00:00Z"
FIELDS: dict[str, Any] = {
    "summary": "s",
    "epss_percentile": 0.91,
    "nvd_url": "https://nvd.example/1",
    "ghsa_id": "GHSA-aaaa-bbbb-cccc",
    "osv_id": "OSV-1",
    "cvss_vector": "CVSS:3.1/AV:N",
    "is_kev": True,
    "kev_date": "2026-01-01",
}
requires_postgres = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private Postgres")


def _run_together(workers: list[Callable[[], None]]) -> None:
    barrier = threading.Barrier(len(workers))

    def run(work: Callable[[], None]) -> None:
        barrier.wait(timeout=30)
        work()

    with ThreadPoolExecutor(len(workers)) as pool:
        for future in [pool.submit(run, work) for work in workers]:
            future.result(timeout=120)


@pytest.fixture
def pg_pool() -> Iterator[Any]:
    from agent_bom.api.postgres_common import _new_application_pool

    pool = _new_application_pool(min_size=1, max_size=12)
    try:
        yield pool
    finally:
        pool.close()


@pytest.fixture
def pg_tenant() -> Iterator[str]:
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    name = "intel-" + uuid4().hex
    token = set_current_tenant(name)
    try:
        yield name
    finally:
        reset_current_tenant(token)


def _in_tenant(tenant: str, work: Callable[[], None]) -> Callable[[], None]:
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    def wrapped() -> None:
        token = set_current_tenant(tenant)
        try:
            work()
        finally:
            reset_current_tenant(token)

    return wrapped


def _pg_row(pool: Any, tenant: str, cve: str) -> tuple[dict[str, Any], bool]:
    from agent_bom.api.postgres_common import _tenant_connection

    with _tenant_connection(pool) as conn:
        row = conn.execute("SELECT payload, is_kev FROM hub_cve_intel WHERE tenant_id = %s AND cve_id = %s", (tenant, cve)).fetchone()
        conn.rollback()
    return decode_hub_payload(row[0]), bool(row[1])


def _assert_all_fields_survived(payload: dict[str, Any], column: bool) -> None:
    for key, value in FIELDS.items():
        assert payload.get(key) == value, key
    assert column is True
    assert payload["is_kev"] is True


@requires_postgres
@pytest.mark.parametrize("round_", range(5))
def test_row_lock_keeps_every_field_without_the_tenant_lock(pg_pool, pg_tenant, round_) -> None:
    from agent_bom.api.postgres_common import _tenant_connection

    cve = f"CVE-2090-{round_}"

    def writer(key: str, value: Any) -> Callable[[], None]:
        def work() -> None:
            with _tenant_connection(pg_pool) as conn:
                tx = connection_session(conn, "postgres")
                persist_references(tx, "postgres", pg_tenant, {"id": key, "vulnerability_id": cve, key: value})
                # Widens the window a read-merge-write race needs.
                conn.execute("SELECT pg_sleep(0.05)")
                conn.commit()

        return _in_tenant(pg_tenant, work)

    _run_together([writer(key, value) for key, value in FIELDS.items()])

    payload, column = _pg_row(pg_pool, pg_tenant, cve)
    _assert_all_fields_survived(payload, column)


@requires_postgres
def test_ingest_from_many_connections_keeps_every_field(pg_pool, pg_tenant) -> None:
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    store = PostgresComplianceHubStore(pg_pool)
    cve = "CVE-2090-100"

    def writer(key: str, value: Any) -> Callable[[], None]:
        finding = {"id": f"f-{key}", "severity": "high", "origin": "bulk_ingest", "source": "t", "vulnerability_id": cve, key: value}
        return _in_tenant(
            pg_tenant,
            lambda: (
                store.ingest_batch_atomic(
                    pg_tenant,
                    [finding],
                    observed_at=OBSERVED,
                    batch_id=f"b-{key}",
                    source="t",
                    reconcile_absent=False,
                    present_canonical_ids=set(),
                )
                and None
            ),
        )

    _run_together([writer(key, value) for key, value in FIELDS.items()])

    payload, column = _pg_row(pg_pool, pg_tenant, cve)
    _assert_all_fields_survived(payload, column)
    assert store.current_kev_count(pg_tenant, origin="bulk_ingest", since="2026-10-01T00:00:00Z", status="open") == len(FIELDS)


@requires_postgres
def test_batches_writing_the_same_cves_in_opposite_order_do_not_deadlock(pg_pool, pg_tenant) -> None:
    import psycopg

    from agent_bom.api.postgres_common import _tenant_connection

    cves = [f"CVE-2091-{index:03d}" for index in range(40)]
    failures: list[BaseException] = []

    def writer(ordered: list[str], marker: str) -> Callable[[], None]:
        def work() -> None:
            rows = [{"id": f"{marker}-{cve}", "vulnerability_id": cve, "summary": marker} for cve in ordered]
            try:
                with _tenant_connection(pg_pool) as conn:
                    # No tenant lock: ordering alone must prevent the cycle.
                    write_ledger_batch(connection_session(conn, "postgres"), "postgres", pg_tenant, rows)
                    conn.commit()
            except psycopg.Error as exc:
                failures.append(exc)

        return _in_tenant(pg_tenant, work)

    for round_ in range(5):
        _run_together(
            [
                writer(cves, f"up{round_}"),
                writer(list(reversed(cves)), f"down{round_}"),
                writer(cves[20:] + cves[:20], f"mid{round_}"),
                writer(list(reversed(cves[20:] + cves[:20])), f"dim{round_}"),
            ]
        )

    assert failures == []


@requires_postgres
def test_lock_wait_respects_the_session_lock_timeout(pg_pool, pg_tenant) -> None:
    import psycopg

    from agent_bom.api.postgres_common import _tenant_connection

    cve = "CVE-2090-200"
    with _tenant_connection(pg_pool) as seed:
        persist_cve_intel(connection_session(seed, "postgres"), "postgres", pg_tenant, [{"vulnerability_id": cve, "summary": "seed"}])
        seed.commit()

    with _tenant_connection(pg_pool) as holder:
        holder.execute("SELECT 1 FROM hub_cve_intel WHERE tenant_id = %s AND cve_id = %s FOR UPDATE", (pg_tenant, cve))
        with _tenant_connection(pg_pool) as waiter:
            waiter.execute("SET LOCAL lock_timeout = '100ms'")
            with pytest.raises(psycopg.errors.LockNotAvailable):
                persist_cve_intel(
                    connection_session(waiter, "postgres"), "postgres", pg_tenant, [{"vulnerability_id": cve, "summary": "late"}]
                )
            waiter.rollback()
        holder.rollback()

    assert _pg_row(pg_pool, pg_tenant, cve)[0]["summary"] == "seed"


@requires_postgres
def test_unchanged_record_writes_nothing(pg_pool, pg_tenant) -> None:
    from agent_bom.api.postgres_common import _tenant_connection

    cve = "CVE-2090-300"
    finding = {"vulnerability_id": cve, "summary": "same", "is_kev": True}

    def xmin() -> str:
        with _tenant_connection(pg_pool) as conn:
            row = conn.execute(
                "SELECT updated_at, xmin::text FROM hub_cve_intel WHERE tenant_id = %s AND cve_id = %s", (pg_tenant, cve)
            ).fetchone()
            conn.rollback()
        return f"{row[0]}/{row[1]}"

    with _tenant_connection(pg_pool) as conn:
        persist_cve_intel(connection_session(conn, "postgres"), "postgres", pg_tenant, [finding])
        conn.commit()
    before = xmin()
    with _tenant_connection(pg_pool) as conn:
        persist_cve_intel(connection_session(conn, "postgres"), "postgres", pg_tenant, [finding])
        conn.commit()
    assert xmin() == before


@requires_postgres
def test_stored_column_repairs_a_payload_that_lost_kev(pg_pool, pg_tenant) -> None:
    from agent_bom.api.postgres_common import _tenant_connection

    cve = "CVE-2090-400"
    with _tenant_connection(pg_pool) as conn:
        conn.execute(
            "INSERT INTO hub_cve_intel (tenant_id, cve_id, payload, updated_at, is_kev) VALUES (%s, %s, CAST(%s AS JSONB), %s, TRUE)",
            (pg_tenant, cve, '{"summary": "lost it"}', OBSERVED),
        )
        persist_cve_intel(connection_session(conn, "postgres"), "postgres", pg_tenant, [{"vulnerability_id": cve, "summary": "lost it"}])
        conn.commit()

    payload, column = _pg_row(pg_pool, pg_tenant, cve)
    assert column is True
    assert payload["is_kev"] is True


def test_sqlite_write_transaction_serializes_two_connections(tmp_path) -> None:
    path = str(tmp_path / "hub.db")
    tenant = "intel-" + uuid4().hex
    cve = "CVE-2090-500"

    def writer(key: str, value: Any) -> Callable[[], None]:
        def work() -> None:
            # A store per writer means a connection per writer on the same file.
            store = SQLiteComplianceHubStore(path)
            finding = {"id": f"f-{key}", "severity": "high", "origin": "bulk_ingest", "source": "t", "vulnerability_id": cve, key: value}
            store.ingest_batch_atomic(
                tenant,
                [finding],
                observed_at=OBSERVED,
                batch_id=f"b-{key}",
                source="t",
                reconcile_absent=False,
                present_canonical_ids=set(),
            )

        return work

    SQLiteComplianceHubStore(path)
    _run_together([writer(key, value) for key, value in FIELDS.items()])

    store = SQLiteComplianceHubStore(path)
    row = store._conn.execute("SELECT payload, is_kev FROM hub_cve_intel WHERE tenant_id = ? AND cve_id = ?", (tenant, cve)).fetchone()
    _assert_all_fields_survived(decode_hub_payload(row[0]), bool(row[1]))


def test_every_cve_a_batch_names_gets_a_reference_row(tmp_path) -> None:
    """A bare finding links to its CVE, so the record it links to must exist for snapshots."""
    store = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
    tenant = "intel-" + uuid4().hex
    finding = {"id": "bare", "severity": "high", "origin": "bulk_ingest", "source": "t", "vulnerability_id": "CVE-2090-600"}
    store.ingest_batch_atomic(
        tenant, [finding], observed_at=OBSERVED, batch_id="b", source="t", reconcile_absent=False, present_canonical_ids=set()
    )

    row = store._conn.execute(
        "SELECT payload, is_kev FROM hub_cve_intel WHERE tenant_id = ? AND cve_id = ?", (tenant, "CVE-2090-600")
    ).fetchone()
    assert row is not None
    assert decode_hub_payload(row[0]) == {}
    assert not row[1]
