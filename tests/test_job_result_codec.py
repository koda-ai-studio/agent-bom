"""Job results are stored zstd-compressed and stay readable in every shape."""

from __future__ import annotations

import json
import os
import re
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4

import pytest

from agent_bom.api.job_payload_codec import RESULT_CODEC_KEY, decode_result_field, encode_job_payload
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
from agent_bom.api.store import SQLiteJobStore

SRC = Path(__file__).resolve().parents[1] / "src" / "agent_bom"


@contextmanager
def tenant(value: str):
    token = set_current_tenant(value)
    try:
        yield
    finally:
        reset_current_tenant(token)


def _finding(index: int) -> dict:
    return {
        "id": f"finding-{index}",
        "severity": "high",
        "title": f"CVE-2024-{index:04d} in lodash@4.17.20",
        "controls": [{"framework": "iso_27001", "control": f"A.5.{n}", "version": "2022", "confidence": 0.75} for n in range(30)],
        "evidence": {"package_name": "lodash", "package_version": "4.17.20", "affected_server_count": 2},
    }


def _result(findings: int = 120) -> dict:
    return {
        "scan_id": "scan-1",
        "scan_sources": ["agent_discovery", "demo-estate"],
        "summary": {"total_findings": findings},
        "findings": [_finding(i) for i in range(findings)],
        "blast_radius": [{"vulnerability_id": f"CVE-2024-{i:04d}", "risk_score": 8.1} for i in range(findings)],
    }


def _job(tenant_id: str, job_id: str | None = None, result: dict | None = None, **extra) -> ScanJob:
    return ScanJob(
        job_id=job_id or uuid4().hex,
        tenant_id=tenant_id,
        status=JobStatus.DONE,
        created_at="2026-10-26T12:00:00Z",
        completed_at="2026-10-26T12:01:00Z",
        request=extra.pop("request", ScanRequest()),
        result=_result() if result is None else result,
        **extra,
    )


def _raw_row(store: SQLiteJobStore, job_id: str) -> str:
    return store._conn.execute("SELECT data FROM jobs WHERE job_id = ?", (job_id,)).fetchone()[0]


def test_large_result_is_stored_compressed_with_a_versioned_header(tmp_path: Path) -> None:
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    job = _job("acme")
    store.put(job)

    raw = _raw_row(store, job.job_id)
    stored = json.loads(raw)
    header = stored["result"][RESULT_CODEC_KEY]
    assert header["codec"] == "zstd" and header["v"] == 1
    assert header["raw_bytes"] > len(raw) * 5
    assert len(raw) * 5 < len(job.model_dump_json())
    assert stored["job_id"] == job.job_id and stored["request"]["format"] == "json"
    assert store.get(job.job_id, tenant_id="acme").model_dump() == job.model_dump()


def test_rows_written_before_compression_still_read(tmp_path: Path) -> None:
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    job = _job("acme")
    store.put(job)
    store._conn.execute("UPDATE jobs SET data = ? WHERE job_id = ?", (job.model_dump_json(), job.job_id))
    store._conn.commit()

    assert RESULT_CODEC_KEY not in _raw_row(store, job.job_id)
    assert store.get(job.job_id, tenant_id="acme").model_dump() == job.model_dump()
    assert [j.job_id for j in store.list_all(tenant_id="acme")] == [job.job_id]


def test_codec_none_writes_rows_older_releases_can_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_JOB_RESULT_CODEC", "none")
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    job = _job("acme")
    store.put(job)
    assert json.loads(_raw_row(store, job.job_id))["result"] == job.result


def test_small_and_empty_results_stay_plain_json(tmp_path: Path) -> None:
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    small = _job("acme", result={"summary": {"total_findings": 0}})
    pending = ScanJob(job_id=uuid4().hex, tenant_id="acme", created_at="2026-10-26T12:00:00Z", request=ScanRequest())
    store.put(small)
    store.put(pending)
    assert json.loads(_raw_row(store, small.job_id))["result"] == {"summary": {"total_findings": 0}}
    assert json.loads(_raw_row(store, pending.job_id))["result"] is None
    assert store.get(small.job_id, tenant_id="acme").result == small.result


def test_result_document_renderings_are_compressed_too(tmp_path: Path) -> None:
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    sarif = json.dumps({"runs": [{"results": [_finding(i) for i in range(80)]}]})
    job = _job("acme", result_document=sarif, request=ScanRequest(format="sarif"))
    store.put(job)
    stored = json.loads(_raw_row(store, job.job_id))
    assert RESULT_CODEC_KEY in stored["result_document"]
    assert store.get(job.job_id, tenant_id="acme").result_document == sarif


def test_sql_projections_keep_working_on_compressed_rows(tmp_path: Path) -> None:
    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    demo = _job("acme", triggered_by="manual", source_id="source-findme")
    store.put(demo)
    assert RESULT_CODEC_KEY in _raw_row(store, demo.job_id)
    assert store.has_usable_demo_job("acme") is True
    assert store.has_usable_demo_job("other") is False
    assert [row["job_id"] for row in store.list_summary(tenant_id="acme", query="findme")] == [demo.job_id]

    no_findings = _job("beta", result={**_result(), "findings": [], "blast_radius": [{"x": "y" * 9000}]})
    store.put(no_findings)
    assert RESULT_CODEC_KEY in _raw_row(store, no_findings.job_id)
    assert store.has_usable_demo_job("beta") is False


def test_history_backfill_reads_compressed_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.storage.finding_history import backfill_history
    from agent_bom.api.storage.sql import connection_session

    store = SQLiteJobStore(str(tmp_path / "jobs.db"))
    job = _job("acme")
    store.put(job)
    session = connection_session(store._conn, "sqlite")
    assert backfill_history(session, "sqlite", "acme", [job.job_id]) == 1


def test_codec_round_trips_and_refuses_unknown_versions() -> None:
    job = _job("acme")
    payload = encode_job_payload(job)
    assert ScanJob.model_validate_json(payload).model_dump() == job.model_dump()
    assert ScanJob.model_validate(json.loads(payload)).model_dump() == job.model_dump()
    envelope = json.loads(payload)["result"]
    envelope[RESULT_CODEC_KEY]["v"] = 99
    with pytest.raises(ValueError, match="codec version"):
        decode_result_field(envelope)


def test_every_sql_path_into_a_stored_result_reads_a_projected_key() -> None:
    """Compressed results only expose header keys to SQL; nothing may query deeper."""
    from agent_bom.api.job_payload_codec import SQL_PROJECTED_RESULT_KEYS

    pattern = re.compile(r"\$\.result\.(\w+)|'result'\s*->>?\s*'(\w+)'|\{result,(\w+)")
    found: dict[str, set[str]] = {}
    for path in SRC.rglob("*.py"):
        for match in pattern.finditer(path.read_text(encoding="utf-8")):
            key = next(group for group in match.groups() if group)
            found.setdefault(key, set()).add(str(path.relative_to(SRC)))
    assert found, "the guard must see the known demo projection"
    assert set(found) <= SQL_PROJECTED_RESULT_KEYS, found


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private Postgres")
def test_postgres_rows_are_compressed_and_projections_hold() -> None:
    from agent_bom.api.postgres_common import _new_application_pool, _tenant_connection
    from agent_bom.api.postgres_job_store import PostgresJobStore

    pool = _new_application_pool(min_size=1, max_size=3)
    owner = "codec-" + uuid4().hex
    try:
        store = PostgresJobStore(pool)
        job = _job(owner, source_id="source-pgfind")
        with tenant(owner):
            store.put(job)
            with _tenant_connection(pool) as conn:
                raw = conn.execute("SELECT data::text FROM scan_jobs WHERE job_id = %s", (job.job_id,)).fetchone()[0]
            assert RESULT_CODEC_KEY in raw
            assert len(raw) * 5 < len(job.model_dump_json())
            assert store.get(job.job_id, tenant_id=owner).model_dump() == job.model_dump()
            assert store.has_usable_demo_job(owner) is True
            assert [row["job_id"] for row in store.list_summary(tenant_id=owner, query="pgfind")] == [job.job_id]
            legacy = _job(owner)
            store.put(legacy)
            with _tenant_connection(pool) as conn:
                conn.execute("UPDATE scan_jobs SET data = %s::jsonb WHERE job_id = %s", (legacy.model_dump_json(), legacy.job_id))
                conn.commit()
            assert store.get(legacy.job_id, tenant_id=owner).model_dump() == legacy.model_dump()
            store.delete(job.job_id, tenant_id=owner)
            store.delete(legacy.job_id, tenant_id=owner)
    finally:
        pool.close()
