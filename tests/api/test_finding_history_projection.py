"""Projected retained history must avoid deserializing superseded reports."""

import logging
from copy import deepcopy

import pytest

from agent_bom.api import scan_finding_read as scan
from agent_bom.api.storage.finding_history import HistoryReader, HistoryUnavailableError, identity_hash
from agent_bom.api.store import SQLiteJobStore
from tests.api.test_scan_job_sla_history import job


@pytest.fixture
def projected_store(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOTS", "1")
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS", "1")
    monkeypatch.delenv("AGENT_BOM_SCAN_SNAPSHOT_READS", raising=False)
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    monkeypatch.setattr(scan, "_get_store", lambda: store)
    monkeypatch.setattr(scan, "_cached_scan_findings", lambda row: deepcopy(row.result.get("findings", [])))
    monkeypatch.setattr(scan, "_iter_scan_findings", lambda row: deepcopy(row.result.get("findings", [])))
    return store


def test_current_findings_load_only_selected_reports(projected_store, monkeypatch):
    old, new = job(8), job(9)
    old.result["findings"][0].update(sla_due_at="2026-12-31", sla_due_at_source="explicit")
    projected_store.put(old)
    projected_store.put(new)

    def no_full_history(**kwargs):
        pytest.fail("findings read deserialized all retained scan results")

    monkeypatch.setattr(projected_store, "list_all", no_full_history)
    rows = scan._current_scan_rows("history-tenant", "2026-08-31T00:00:00Z", None)
    assert len(rows) == 1
    assert rows[0]["first_seen"] == "2026-08-01T00:00:00+00:00"
    assert rows[0]["sla_due_at"] == "2026-12-31"
    assert rows[0]["sla_due_at_source"] == "explicit"


@pytest.mark.parametrize("change", ["delete", "replace", "raw_sql", "disabled_write", "old_version", "malformed"])
def test_invalidation_and_fallback_preserve_current_history(projected_store, monkeypatch, change):
    old, new = job(8), job(9)
    projected_store.put(old)
    projected_store.put(new)
    if change == "delete":
        projected_store.delete(old.job_id, tenant_id=old.tenant_id)
    elif change in {"replace", "disabled_write"}:
        old.result["findings"] = []
        if change == "disabled_write":
            monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOTS", "0")
        projected_store.put(old)
    else:
        conn = projected_store._conn
        if change == "raw_sql":
            old.result["findings"] = []
            conn.execute("UPDATE jobs SET data=? WHERE tenant_id=? AND job_id=?", (old.model_dump_json(), old.tenant_id, old.job_id))
        elif change == "old_version":
            conn.execute("UPDATE finding_history_jobs SET version=0")
        else:
            conn.execute("UPDATE finding_history_jobs SET metadata='{}'")
        conn.commit()
        projected_store._close_thread_connection()
    fast = scan._current_scan_rows("history-tenant", None, None)
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS", "0")
    assert fast == scan._current_scan_rows("history-tenant", None, None)
    assert fast[0]["first_seen"] == ("2026-08-01T00:00:00+00:00" if change in {"old_version", "malformed"} else "2026-09-01T00:00:00+00:00")


def test_backfill_rebuilds_legacy_jobs_without_rewriting_source(projected_store, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOTS", "0")
    rows = [job(8), job(9)]
    for row in rows:
        projected_store.put(row)
    before = projected_store.overview_evidence_revision("history-tenant")
    with projected_store.finding_history_read("history-tenant") as reader:
        with pytest.raises(HistoryUnavailableError):
            reader.jobs()
    assert projected_store.backfill_finding_history("history-tenant", [row.job_id for row in rows]) == 2
    assert projected_store.overview_evidence_revision("history-tenant") == before
    monkeypatch.setattr(projected_store, "list_all", lambda **kw: pytest.fail("backfilled history fell back"))
    assert scan._current_scan_rows("history-tenant", None, None)[0]["first_seen"] == "2026-08-01T00:00:00+00:00"
    with pytest.raises(ValueError, match="64 jobs"):
        projected_store.backfill_finding_history("history-tenant", ["missing"] * 65)


@pytest.mark.parametrize("reason", ["partial", "failed", "permission_denied", "skipped"])
def test_partial_attempts_aliases_and_history_match_legacy(projected_store, monkeypatch, reason):
    old, new = job(8), job(9, findings=[])
    new.result["scan_id"] = "result-alias"
    new.result["scan_run"] = (
        {"scan_id": "nested-alias", "outcome": reason}
        if reason in {"partial", "failed"}
        else {"scopes": [{"requested": True, "status": reason}]}
    )
    for row in (old, new):
        projected_store.put(row)
    for scan_id in (None, new.job_id, "result-alias", "nested-alias"):
        monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS", "1")
        fast = scan._current_scan_rows("history-tenant", None, scan_id)
        monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS", "0")
        assert fast == scan._current_scan_rows("history-tenant", None, scan_id)
        if scan_id is None:
            assert fast[0]["observation_status"] == "unreconfirmed"


def test_projection_failure_does_not_commit_partial_history_or_fail_job(projected_store, monkeypatch):
    from agent_bom.api.storage import finding_history

    old = job(8)
    projected_store.put(old)

    def fail(session, batch):
        raise RuntimeError("injected projection failure")

    monkeypatch.setattr(finding_history, "_insert_rows", fail)
    old.result["findings"][0]["first_seen"] = "2026-08-02T00:00:00Z"
    projected_store.put(old)
    assert projected_store.get(old.job_id, tenant_id=old.tenant_id).result == old.result
    with projected_store.finding_history_read(old.tenant_id) as reader:
        with pytest.raises(HistoryUnavailableError):
            reader.jobs()
    assert scan._current_scan_rows(old.tenant_id, None, None)[0]["first_seen"] == "2026-08-02T00:00:00+00:00"


def test_one_read_snapshot_survives_concurrent_replacement(projected_store, monkeypatch):
    old, new = job(8), job(9)
    projected_store.put(old)
    projected_store.put(new)
    writer = SQLiteJobStore(projected_store._db_path)
    original = HistoryReader.jobs

    def replace_after_metadata(reader):
        result = original(reader)
        replacement = new.model_copy(deep=True)
        replacement.result["findings"] = []
        writer.put(replacement)
        return result

    monkeypatch.setattr(HistoryReader, "jobs", replace_after_metadata)
    assert scan._current_scan_rows("history-tenant", None, None) == []
    monkeypatch.setattr(HistoryReader, "jobs", original)
    assert scan._current_scan_rows("history-tenant", None, None) == []


def test_query_batches_are_bounded_and_only_hydrate_selected_job(projected_store, monkeypatch):
    from agent_bom.api.storage import jobs

    source = job(8)
    for index in range(270):
        source.job_id = f"history-{index:04}"
        projected_store.put(source)
    parsed = []
    parse = jobs.parse_job_payload

    def record(payload):
        value = parse(payload)
        parsed.append(value.job_id)
        return value

    monkeypatch.setattr(jobs, "parse_job_payload", record)
    rows = scan._current_scan_rows("history-tenant", None, None)
    assert len(rows) == 1
    assert parsed == ["history-0269"]
    with projected_store.finding_history_read("history-tenant") as reader:
        metadata = reader.jobs()
        key = ("history-tenant", metadata[0].scope_key, source.result["findings"][0]["canonical_id"], "")
        assert len(list(reader.occurrences({key}))) == 270
        plan = reader.session.execute(
            "EXPLAIN QUERY PLAN SELECT job_id,ordinal,payload FROM finding_history_rows WHERE tenant_id=? AND history_key=?",
            ("history-tenant", identity_hash(key)),
        ).fetchall()
        assert any("idx_finding_history_identity" in row[-1] for row in plan)
        with pytest.raises(ValueError, match="reader tenant"):
            list(reader.occurrences({("another-tenant", *key[1:])}))


def test_failed_batch_rolls_back_projection_and_source(projected_store, monkeypatch):
    old = job(8)
    projected_store.put(old)
    put = projected_store._put_on_connection

    def fail_second(row, **kwargs):
        if row.job_id == "fail":
            raise RuntimeError("injected transaction failure")
        return put(row, **kwargs)

    changed = old.model_copy(deep=True)
    changed.result["findings"] = []
    monkeypatch.setattr(projected_store, "_put_on_connection", fail_second)
    with pytest.raises(RuntimeError):
        projected_store.put_many_atomic([changed, old.model_copy(update={"job_id": "fail"})])
    assert len(scan._current_scan_rows("history-tenant", None, None)) == 1


def test_backfill_rereads_after_enumeration_and_emits_receipt(projected_store, monkeypatch, capsys):
    from agent_bom.api.storage import finding_history_cli, job_backends

    source = job(8)
    projected_store.put(source)
    backfill = projected_store.backfill_finding_history

    def update_before_lock(tenant, ids):
        source.result["findings"] = []
        projected_store.put(source)
        return backfill(tenant, ids)

    monkeypatch.setattr(projected_store, "backfill_finding_history", update_before_lock)
    monkeypatch.setattr(job_backends, "configured_job_store", lambda: projected_store)
    assert finding_history_cli.main(["--tenant", "history-tenant"]) == 0
    assert '"projected_jobs": 1' in capsys.readouterr().out
    assert scan._current_scan_rows("history-tenant", None, None) == []


@pytest.mark.parametrize("result", ["postgresql://user:private-password@db/internal", None])
def test_backfill_cli_rejects_non_numeric_receipt_without_disclosing_store_data(monkeypatch, capsys, result):
    from agent_bom.api import tenant_worker
    from agent_bom.api.storage import finding_history_cli, job_backends

    monkeypatch.setattr(job_backends, "configured_job_store", lambda: object())
    monkeypatch.setattr(tenant_worker, "run_tenant_bound", lambda *args: result)
    assert finding_history_cli.main(["--tenant", "history-tenant"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "Finding history backfill failed; check tenant, database configuration and migrations.\n"


@pytest.mark.parametrize("qualify", [False, True])
def test_qualification_compares_whole_history_and_uses_legacy_on_mismatch(projected_store, monkeypatch, caplog, qualify):
    from agent_bom.api.storage.finding_history import HistoryReader

    projected_store.put(job(8))
    projected_store.put(job(9))
    if qualify:
        monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_READS", "1")
    monkeypatch.setattr(HistoryReader, "history", lambda *args: {})
    reader_logger = "agent_bom.api.finding_history_read"
    caplog.set_level(logging.DEBUG, logger=reader_logger)
    rows = scan._current_scan_rows("history-tenant", None, None)
    assert rows[0]["first_seen"] == ("2026-08-01T00:00:00+00:00" if qualify else "2026-09-01T00:00:00+00:00")
    # Every branch logs its outcome; naming the one taken separates a real
    # mismatch from a fallback (incomplete/unavailable) that returns the same rows.
    outcomes = [record.getMessage() for record in caplog.records if record.name == reader_logger]
    assert outcomes == (["finding_history_read outcome=mismatch; using retained jobs"] if qualify else []), outcomes


def test_streamed_history_keeps_kev_and_identity_batches(projected_store, monkeypatch):
    old, new = job(8), job(9)
    for source in (old, new):
        row = source.result["findings"][0]
        source.result["findings"] = [dict(row, id=f"id-{i}", canonical_id=f"canonical-{i}") for i in range(150)]
    for row in old.result["findings"]:
        row["evidence"] = {"kev_due_date": "2026-08-03"}
    for source in (old, new):
        projected_store.put(source)
    fast = scan._current_scan_rows("history-tenant", None, None)
    assert len(fast) == 150
    assert {row["sla_due_at"] for row in fast} == {"2026-08-03T00:00:00+00:00"}
    monkeypatch.setenv("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS", "0")
    assert fast == scan._current_scan_rows("history-tenant", None, None)


def test_insert_if_absent_does_not_replace_existing_history(projected_store):
    source = job(8)
    assert projected_store.put_many_if_absent_atomic([source]) == [source.job_id]
    changed = source.model_copy(deep=True)
    changed.result["findings"] = []
    assert projected_store.put_many_if_absent_atomic([changed]) == []
    assert len(scan._current_scan_rows("history-tenant", None, None)) == 1


def test_projection_uses_exact_serialized_source_not_mutable_caller(projected_store, monkeypatch):
    from agent_bom.api.storage import finding_history

    old = job(8)
    old.result["findings"][0].update(sla_due_at="2026-12-31", sla_due_at_source="explicit")
    project = finding_history.replace_history

    def mutate_caller_after_source_write(session, persisted):
        old.result["findings"][0]["sla_due_at"] = "1900-01-01"
        project(session, persisted)

    monkeypatch.setattr(finding_history, "replace_history", mutate_caller_after_source_write)
    projected_store.put(old)
    projected_store.put(job(9))
    assert scan._current_scan_rows("history-tenant", None, None)[0]["sla_due_at"] == "2026-12-31"


def test_dynamic_enrichment_does_not_hold_a_job_database_connection(projected_store, monkeypatch):
    source = job(8)
    projected_store.put(source)

    def collect(row):
        assert getattr(projected_store._local, "conn", None) is None, "dynamic enrichment can exhaust a shared database pool"
        return deepcopy(row.result["findings"])

    monkeypatch.setattr(scan, "_iter_scan_findings", collect)
    monkeypatch.setattr(scan, "_cached_scan_findings", collect)
    monkeypatch.setattr(projected_store, "list_all", lambda **kw: pytest.fail("projected read unexpectedly fell back"))
    assert len(scan._current_scan_rows("history-tenant", None, None)) == 1
