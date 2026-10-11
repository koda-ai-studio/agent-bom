"""Live restricted-role parity, invalidation and snapshot tests for history."""

import os
from copy import deepcopy
from uuid import uuid4

import pytest

from agent_bom.api.finding_history_read import current_findings_with_history
from agent_bom.api.findings_current import _finding_snapshot_jobs, current_scan_findings
from agent_bom.api.storage.finding_history import HistoryUnavailableError
from agent_bom.api.storage.jobs import get_job
from tests.api.test_scan_job_sla_history import job
from tests.test_postgres_job_evidence_revision import tenant_scope

pytestmark = pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires restricted-role Postgres")


@pytest.fixture
def history_store(monkeypatch):
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_job_store import PostgresJobStore

    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOTS", "1")
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS", "1")
    monkeypatch.delenv("AGENT_BOM_SCAN_SNAPSHOT_READS", raising=False)
    tenant = "history-" + uuid4().hex
    with _new_application_pool(min_size=1, max_size=3) as pool:
        store = PostgresJobStore(pool=pool)
        with tenant_scope(tenant):
            yield store, tenant


def _read(store, tenant):
    def collect(row):
        return deepcopy(row.result.get("findings", []))

    return current_findings_with_history(
        store,
        tenant,
        None,
        None,
        collect,
        lambda: current_scan_findings(store.list_all(tenant_id=tenant), since=None, scan_id=None, iter_findings=collect),
        fold=current_scan_findings,
        select_jobs=_finding_snapshot_jobs,
    )


def test_history_restricted_role_and_cross_tenant_same_ids(history_store):
    store, tenant = history_store
    for month in (8, 9):
        store.put(job(month, tenant=tenant))
    assert _read(store, tenant)[0]["first_seen"] == "2026-08-01T00:00:00+00:00"
    with store._pool.connection() as conn:
        assert conn.execute("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone() == (False, False)
        for table in ("finding_history_jobs", "finding_history_rows"):
            assert conn.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=%s::regclass", (table,)).fetchone() == (
                True,
                True,
            )
    with tenant_scope(tenant + "-other"):
        other = job(9, tenant=tenant + "-other")
        other.job_id = job(8, tenant=tenant).job_id
        store.put(other)
        with store.finding_history_read(tenant) as reader:
            assert reader.jobs() == []
        assert _read(store, other.tenant_id)[0]["first_seen"] == "2026-09-01T00:00:00+00:00"
    store.delete(job(8, tenant=tenant).job_id, tenant_id=tenant)
    assert _read(store, tenant)[0]["first_seen"] == "2026-09-01T00:00:00+00:00"


def test_raw_mutations_invalidate_atomically_and_backfill_locks_source(history_store):
    from agent_bom.api.postgres_common import _tenant_connection
    from agent_bom.api.storage.finding_history_cli import backfill_tenant_history

    store, tenant = history_store
    row = job(8, tenant=tenant)
    store.put(row)
    with _tenant_connection(store._pool) as conn:
        conn.execute("UPDATE scan_jobs SET data=data WHERE team_id=%s AND job_id=%s", (tenant, row.job_id))
        with store.finding_history_read(tenant) as reader:
            assert len(reader.jobs()) == 1
        conn.rollback()
    with store.finding_history_read(tenant) as reader:
        assert len(reader.jobs()) == 1
    with _tenant_connection(store._pool) as conn:
        conn.execute("UPDATE scan_jobs SET data=data WHERE team_id=%s AND job_id=%s", (tenant, row.job_id))
        conn.commit()
    with store.finding_history_read(tenant) as reader:
        with pytest.raises(HistoryUnavailableError):
            reader.jobs()
    assert len(_read(store, tenant)) == 1
    revision = store.overview_evidence_revision(tenant)
    assert backfill_tenant_history(store, tenant) == 1
    assert store.overview_evidence_revision(tenant) == revision
    with store.finding_history_read(tenant) as reader:
        assert len(reader.jobs()) == 1


def test_repeatable_read_cannot_mix_metadata_and_replaced_source(history_store):
    store, tenant = history_store
    source = job(8, tenant=tenant)
    store.put(source)
    with store.finding_history_read(tenant) as reader:
        assert len(reader.jobs()) == 1
        replacement = source.model_copy(deep=True)
        replacement.result["findings"] = []
        store.put(replacement)
        assert get_job(reader.session, reader.dialect, source.job_id, tenant).result == source.result
    assert _read(store, tenant) == []


def test_paged_history_preserves_ordinal_and_multiple_key_batches(history_store, monkeypatch):
    store, tenant = history_store
    for month in (8, 9):
        row = job(month, tenant=tenant)
        finding = row.result["findings"][0]
        row.result["findings"] = [dict(finding, id=f"finding-{i}", canonical_id=f"canonical-{i}") for i in range(150)]
        # Repeated canonical IDs exercise page-boundary ordinals and explicit
        # assignment ordering inside one job, as well as the 64-key query cap.
        row.result["findings"] += [dict(item, sla_due_at="2026-12-31", sla_due_at_source="explicit") for item in row.result["findings"]]
        store.put(row)
    fast = _read(store, tenant)
    assert len(fast) == 150
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS", "0")
    assert fast == _read(store, tenant)


def test_dynamic_enrichment_can_reuse_a_single_connection_pool(history_store):
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.postgres_job_store import PostgresJobStore

    store, tenant = history_store
    source = job(8, tenant=tenant)
    store.put(source)
    with _new_application_pool(min_size=1, max_size=1) as pool:
        single = PostgresJobStore(pool=pool)

        def enrich(row):
            assert single.get(row.job_id, tenant_id=tenant) is not None
            return deepcopy(row.result["findings"])

        rows = current_findings_with_history(
            single,
            tenant,
            None,
            None,
            enrich,
            lambda: pytest.fail("history unexpectedly fell back"),
            fold=current_scan_findings,
            select_jobs=_finding_snapshot_jobs,
        )
        assert len(rows) == 1
