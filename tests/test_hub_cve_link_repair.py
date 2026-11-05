"""Rows an earlier writer left without a CVE link are repaired, resumably, on every path."""

from __future__ import annotations

import importlib.util
import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore
from agent_bom.api.hub_materialization import run_materialization_tick
from agent_bom.api.hub_payload_codec import encode_hub_payload
from agent_bom.api.hub_reference_payload import hydrate_reference_payload
from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
from agent_bom.api.storage.cve_intel_reconcile import START, mark_unlinked_rows_pending
from agent_bom.api.storage.registry_import import read_source

OBSERVED = "2026-11-01T00:00:00Z"
SINCE = "2026-10-01T00:00:00Z"
CVE = "CVE-2085-1"
VERSIONS = Path(__file__).resolve().parents[1] / "deploy/supabase/postgres/alembic/versions"
requires_maintenance = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_MAINTENANCE_URL"), reason="requires maintenance role")


def _finding(key: str, cve: str | None = CVE, **extra: Any) -> dict[str, Any]:
    row = {"id": key, "severity": "high", "origin": "bulk_ingest", "source": "test", "package": "pkg", "location": key, **extra}
    if cve:
        row["vulnerability_id"] = cve
    return row


def _ingest(store: Any, tenant: str, rows: list[dict[str, Any]], batch: str = "b1") -> None:
    store.ingest_batch_atomic(
        tenant, rows, observed_at=OBSERVED, batch_id=batch, source="test", reconcile_absent=False, present_canonical_ids=set()
    )


def _kev(store: Any, tenant: str) -> int:
    return store.current_kev_count(tenant, origin="bulk_ingest", since=SINCE, status="open")


def _drill(store: Any, tenant: str) -> set[str]:
    rows, _total, _cursor = store.list_current_page(tenant, limit=100, origin="bulk_ingest", since=SINCE, status="open")
    return {row["id"] for row in rows if row.get("is_kev") is True}


def _sqlite_legacy_ledger(conn: sqlite3.Connection, tenant: str, finding_id: str, cve: str) -> None:
    conn.execute(
        "UPDATE compliance_hub_findings SET payload = ? WHERE tenant_id = ? AND finding_id = ?",
        (encode_hub_payload({"id": finding_id, "vulnerability_id": cve, "severity": "high", "source": "test"}), tenant, finding_id),
    )
    conn.execute("UPDATE hub_findings_current SET intel_ref = '' WHERE tenant_id = ? AND ledger_finding_id = ?", (tenant, finding_id))


def test_hydration_follows_the_cve_record_without_a_stored_link() -> None:
    legacy = {"id": "f", "vulnerability_id": CVE}
    hydrated = hydrate_reference_payload(legacy, cve_intel={CVE: {"is_kev": True, "summary": "s"}}, framework_refs={})
    assert hydrated["is_kev"] is True
    assert hydrated["summary"] == "s"


def test_cve_record_decides_kev_over_a_copy_on_the_finding() -> None:
    legacy = {"id": "f", "vulnerability_id": CVE, "is_kev": True, "cisa_kev": True}
    hydrated = hydrate_reference_payload(legacy, cve_intel={CVE: {"is_kev": False}}, framework_refs={})
    assert hydrated["is_kev"] is False
    assert hydrated["cisa_kev"] is False


def test_bare_cve_finding_survives_a_compliance_snapshot(tmp_path) -> None:
    """A stored ``intel_ref`` with no record would fail the export as missing evidence."""
    path = str(tmp_path / "hub.db")
    store = SQLiteComplianceHubStore(path)
    tenant = "snap-" + uuid4().hex
    _ingest(store, tenant, [_finding("bare")])

    records = read_source(Path(path), {tenant: "target"}, ["compliance_hub"])

    assert [row["cve_id"] for row in records[0][1].tables["hub_cve_intel"]] == [CVE]


def test_sqlite_upgrade_relinks_unlinked_rows_once(tmp_path) -> None:
    path = str(tmp_path / "old.db")
    tenant = "up-" + uuid4().hex
    store = SQLiteComplianceHubStore(path)
    _ingest(store, tenant, [_finding("flagged", is_kev=True), _finding("bare"), _finding("policy", None)])
    conn = store._conn
    _sqlite_legacy_ledger(conn, tenant, "bare", CVE)
    conn.execute("DELETE FROM agent_bom_hub_backfills")
    conn.commit()
    assert _kev(store, tenant) == 1

    upgraded = SQLiteComplianceHubStore(path)

    assert upgraded.current_materialization_pending(tenant) is False
    assert _kev(upgraded, tenant) == 2
    assert _drill(upgraded, tenant) == {"flagged", "bare"}
    refs = dict(
        upgraded._conn.execute("SELECT ledger_finding_id, intel_ref FROM hub_findings_current WHERE tenant_id = ?", (tenant,)).fetchall()
    )
    assert refs == {"flagged": CVE, "bare": CVE, "policy": ""}

    # The marker stops a later start rewriting rows, and policy rows stay materialized.
    upgraded._conn.execute("UPDATE hub_findings_current SET issue_group_id = 'kept' WHERE ledger_finding_id = 'policy'")
    upgraded._conn.commit()
    again = SQLiteComplianceHubStore(path)
    assert again._conn.execute("SELECT issue_group_id FROM hub_findings_current WHERE ledger_finding_id = 'policy'").fetchone()[0] == "kept"


def test_sqlite_upgrade_walk_creates_records_and_reconciles(tmp_path) -> None:
    path = str(tmp_path / "old.db")
    tenant = "up-" + uuid4().hex
    store = SQLiteComplianceHubStore(path)
    _ingest(store, tenant, [_finding("flagged", "CVE-2085-2", is_kev=True), _finding("linked", "CVE-2085-3")])
    conn = store._conn
    conn.execute("UPDATE hub_cve_intel SET is_kev = 0 WHERE cve_id = 'CVE-2085-2'")
    conn.execute("DELETE FROM hub_cve_intel WHERE cve_id = 'CVE-2085-3'")
    conn.commit()

    upgraded = SQLiteComplianceHubStore(path)

    rows = dict(upgraded._conn.execute("SELECT cve_id, is_kev FROM hub_cve_intel WHERE tenant_id = ?", (tenant,)).fetchall())
    assert rows == {"CVE-2085-2": 1, "CVE-2085-3": 0}


def _load_revision() -> Any:
    path = VERSIONS / "20261105_01_repair_cve_intel_links.py"
    spec = importlib.util.spec_from_file_location("revision_20261105_01", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_repair_revision_is_chained_after_the_materialization_revision() -> None:
    pytest.importorskip("alembic")
    module = _load_revision()
    assert module.revision == "20261105_01"
    assert module.down_revision == "20261104_01"


@pytest.fixture
def pg_store() -> Iterator[Any]:
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    pool = _new_application_pool(min_size=1, max_size=4)
    try:
        yield PostgresComplianceHubStore(pool)
    finally:
        pool.close()


@pytest.fixture
def pg_tenant() -> Iterator[str]:
    name = "repair-" + uuid4().hex
    token = set_current_tenant(name)
    try:
        yield name
    finally:
        reset_current_tenant(token)


def _pg_make_legacy(store: Any, tenant: str, finding_id: str) -> None:
    from agent_bom.api.postgres_common import _tenant_connection

    with _tenant_connection(store._pool) as conn:
        conn.execute(
            "UPDATE compliance_hub_findings SET payload = payload - 'intel_ref' WHERE tenant_id = %s AND finding_id = %s",
            (tenant, finding_id),
        )
        conn.execute("UPDATE hub_findings_current SET intel_ref = '' WHERE tenant_id = %s AND ledger_finding_id = %s", (tenant, finding_id))
        conn.commit()


def _pg_refs(store: Any, tenant: str) -> dict[str, str]:
    from agent_bom.api.postgres_common import _tenant_connection

    with _tenant_connection(store._pool) as conn:
        rows = conn.execute("SELECT ledger_finding_id, intel_ref FROM hub_findings_current WHERE tenant_id = %s", (tenant,)).fetchall()
        conn.rollback()
    return {str(row[0]): str(row[1]) for row in rows}


def _mark_everything(store: Any, *, limit: int = 2) -> int:
    from agent_bom.api.storage.sql import PostgresBackend

    total = 0
    after: Any = START
    while after is not None:
        with PostgresBackend(store._pool).transaction(all_tenants=True) as tx:
            after, count = mark_unlinked_rows_pending(tx, after=after, limit=limit)
        total += count
    return total


@requires_maintenance
def test_postgres_repair_resumes_and_the_tick_finishes_it(pg_store, pg_tenant, monkeypatch) -> None:
    rows = [_finding("flagged", is_kev=True), _finding("policy", None)] + [_finding(f"bare{i}") for i in range(5)]
    _ingest(pg_store, pg_tenant, rows)
    for index in range(5):
        _pg_make_legacy(pg_store, pg_tenant, f"bare{index}")
    assert _kev(pg_store, pg_tenant) == 1

    assert _mark_everything(pg_store) >= 6
    assert pg_store.current_materialization_pending(pg_tenant) is True
    # While rows are pending the drill walks payloads and already finds every KEV row.
    assert len(_drill(pg_store, pg_tenant)) == 6

    # One batch stands in for a migration that ran out of budget; the tick finishes the rest.
    pg_store.backfill_materialized_batch(2)
    monkeypatch.setattr("agent_bom.api.compliance_hub_store.get_compliance_hub_store", lambda: pg_store)
    while run_materialization_tick(budget_seconds=5, batch_rows=500):
        pass

    assert pg_store.current_materialization_pending(pg_tenant) is False
    refs = _pg_refs(pg_store, pg_tenant)
    assert refs.pop("policy") == ""
    assert set(refs.values()) == {CVE}
    assert _kev(pg_store, pg_tenant) == 6
    assert len(_drill(pg_store, pg_tenant)) == 6


@requires_maintenance
def test_postgres_marking_is_repeatable_and_scoped_to_blank_rows(pg_store, pg_tenant) -> None:
    _ingest(pg_store, pg_tenant, [_finding("linked", "CVE-2085-9"), _finding("policy", None)])

    _mark_everything(pg_store)

    from agent_bom.api.postgres_common import _tenant_connection

    with _tenant_connection(pg_store._pool) as conn:
        rows = conn.execute(
            "SELECT ledger_finding_id, issue_group_id FROM hub_findings_current WHERE tenant_id = %s", (pg_tenant,)
        ).fetchall()
        conn.rollback()
    pending = {str(row[0]): row[1] for row in rows}
    assert pending["policy"] is None
    assert pending["linked"] is not None
