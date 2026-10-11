"""Versioned metadata and bounded identity queries for retained scan history.

The job writer owns the transaction. Job-table triggers discard these derived
rows for every mutation, including older writers and direct SQL. Missing or
old versions are never treated as an empty history. Readers fence source and
history snapshots with the durable tenant revision, releasing the database
connection during dynamic enrichment.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Iterator
from typing import Any

from agent_bom.api import finding_job_metadata as fold
from agent_bom.api.finding_job_metadata import FindingHistoryJob, HistoryKey, _merge_retained_history_row, _retained_finding_key
from agent_bom.api.models import JobStatus, ScanJob
from agent_bom.api.storage.sql import Dialect, SqlSession, load_json, require_tenant_id

VERSION = 1
PAGE_SIZE = 256
KEY_BATCH = 64


class HistoryUnavailableError(ValueError):
    """Incomplete projection: callers must use authoritative retained jobs."""


def identity_hash(key: HistoryKey) -> str:
    return hashlib.sha256(json.dumps(key, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def metadata_for_job(job: ScanJob) -> FindingHistoryJob:
    result = job.result if isinstance(job.result, dict) else {}
    run = result.get("scan_run")
    run = run if isinstance(run, dict) else {}
    return FindingHistoryJob(
        job_id=job.job_id,
        tenant_id=job.tenant_id,
        status=job.status,
        created_at=job.created_at,
        completed_at=job.completed_at,
        child_job_ids=job.child_job_ids,
        result={"retained": True} if result else {} if isinstance(job.result, dict) else None,
        scope_key=fold.scan_scope_key(job),
        authority_key=fold.scan_evidence_authority_key(job),
        authoritative=fold.job_has_authoritative_scan_evidence(job),
        incomplete_reasons=fold.scan_collection_incomplete_reasons(job),
        scan_aliases=[str(result.get("scan_id") or ""), str(run.get("scan_id") or "")],
    )


def replace_history(session: SqlSession, job: ScanJob) -> None:
    """Replace one projection inside the locked source job's transaction."""
    require_tenant_id(job.tenant_id)
    for table in ("finding_history_rows", "finding_history_jobs"):
        session.execute(f"DELETE FROM {table} WHERE tenant_id=? AND job_id=?", (job.tenant_id, job.job_id))  # nosec B608 - fixed tables
    if job.status != JobStatus.DONE:
        return
    metadata = metadata_for_job(job)
    session.execute(
        "INSERT INTO finding_history_jobs (tenant_id,job_id,version,metadata) VALUES (?,?,?,?)",
        (job.tenant_id, job.job_id, VERSION, metadata.model_dump_json()),
    )
    if not isinstance(job.result, dict) or job.child_job_ids:
        return
    batch = []
    for ordinal, row in enumerate(job.result.get("findings", []) or []):
        if not isinstance(row, dict) or (key := _retained_finding_key(job, row, scope=metadata.scope_key)) is None:
            continue
        # These are the inputs to merge_finding_sla, not a merged finding. Keep
        # missing fields and JSON types, including unknown manual assignments.
        payload = {
            name: row[name]
            for name in (
                "first_seen",
                "sla_due_at",
                "sla_due_at_source",
                "severity",
                "effective_severity",
                "kev_due_date",
            )
            if name in row
        }
        evidence = row.get("evidence")
        if isinstance(evidence, dict) and "kev_due_date" in evidence:
            payload["evidence"] = {"kev_due_date": evidence["kev_due_date"]}
        encoded = json.dumps({"key": key, "row": payload}, allow_nan=False, separators=(",", ":"))
        batch.append((job.tenant_id, job.job_id, ordinal, identity_hash(key), *metadata.authority_key[:2], encoded))
        if len(batch) == PAGE_SIZE:
            _insert_rows(session, batch)
            batch.clear()
    _insert_rows(session, batch)


def _insert_rows(session: SqlSession, batch: list[tuple[Any, ...]]) -> None:
    session.executemany(
        "INSERT INTO finding_history_rows (tenant_id,job_id,ordinal,history_key,evidence_at,completed_at,payload) VALUES (?,?,?,?,?,?,?)",
        batch,
    )


def record_history_write(session: SqlSession, job: ScanJob) -> None:
    """Keep a materialization failure from failing the authoritative job write."""
    # Job-table invalidation ran before this savepoint. A rollback therefore
    # leaves no stale or partial projection and readers use retained jobs.
    session.execute("SAVEPOINT finding_history_write")
    try:
        replace_history(session, job)
    except Exception:  # broad-except: derived history is optional; source job persistence remains authoritative
        import logging

        session.execute("ROLLBACK TO SAVEPOINT finding_history_write")
        logging.getLogger(__name__).warning("finding_history_write outcome=unavailable")
    finally:
        session.execute("RELEASE SAVEPOINT finding_history_write")


def backfill_history(session: SqlSession, dialect: Dialect, tenant_id: str, job_ids: list[str]) -> int:
    """Bounded backfill; lock before reading so a stale source cannot win."""
    require_tenant_id(tenant_id)
    if len(job_ids) > KEY_BATCH:
        raise ValueError("finding history backfill is limited to 64 jobs per transaction")
    table, tenant = ("scan_jobs", "team_id") if dialect == "postgres" else ("jobs", "tenant_id")
    count = 0
    for job_id in sorted(set(job_ids)):
        lock = " FOR UPDATE" if dialect == "postgres" else ""
        row = session.execute(
            f"SELECT data FROM {table} WHERE {tenant}=? AND job_id=?{lock}",  # nosec B608 - fixed identifiers and lock suffix
            (tenant_id, job_id),  # nosec B608 - fixed SQL
        ).fetchone()
        if row is not None:
            job = ScanJob.model_validate(load_json(row[0]))
            replace_history(session, job)
            count += int(job.status == JobStatus.DONE)
    return count


class HistoryReader:
    """Transaction-scoped reader; callers never keep it after the snapshot ends."""

    def __init__(self, session: SqlSession, dialect: Dialect, tenant_id: str):
        self.session, self.dialect, self.tenant_id = session, dialect, require_tenant_id(tenant_id)

    def revision(self) -> str:
        if self.dialect == "postgres":
            row = self.session.execute(
                "SELECT generation,revision FROM job_overview_revisions WHERE tenant_id=?",
                (self.tenant_id,),
            ).fetchone()
        else:
            row = self.session.execute(
                "SELECT i.identity,COALESCE(r.revision,0) FROM job_overview_identity i "
                "LEFT JOIN job_overview_revisions r ON r.tenant_id=? WHERE i.singleton=1",
                (self.tenant_id,),
            ).fetchone()
        return f"{row[0]}:{row[1]}" if row else "empty"

    def require_complete(self) -> None:
        table, tenant = ("scan_jobs", "team_id") if self.dialect == "postgres" else ("jobs", "tenant_id")
        missing = self.session.execute(
            f"SELECT 1 FROM {table} j LEFT JOIN finding_history_jobs h "
            f"ON h.tenant_id=j.{tenant} AND h.job_id=j.job_id "
            f"WHERE j.{tenant}=? AND j.status=? AND (h.version IS NULL OR h.version<>?) LIMIT 1",  # nosec B608
            (self.tenant_id, JobStatus.DONE.value, VERSION),
        ).fetchone()
        if missing:
            raise HistoryUnavailableError("retained finding history requires backfill")

    def jobs(self) -> list[FindingHistoryJob]:
        self.require_complete()
        jobs: list[FindingHistoryJob] = []
        after: str | None = None
        while True:
            cursor_sql = " AND job_id>?" if after is not None else ""
            params = (self.tenant_id, VERSION, after, PAGE_SIZE) if after is not None else (self.tenant_id, VERSION, PAGE_SIZE)
            rows = self.session.execute(
                "SELECT job_id, metadata FROM finding_history_jobs WHERE tenant_id=? AND version=?"  # nosec B608 - fixed cursor predicate
                + cursor_sql
                + " ORDER BY job_id LIMIT ?",
                params,
            ).fetchall()
            for job_id, payload in rows:
                job = FindingHistoryJob.model_validate_json(payload)
                if job.job_id != job_id or job.tenant_id != self.tenant_id:
                    raise HistoryUnavailableError("invalid finding history scope")
                if job.status == JobStatus.DONE and job.result:
                    jobs.append(job)
            if len(rows) < PAGE_SIZE:
                return jobs
            after = rows[-1][0]

    def occurrences(self, wanted: set[HistoryKey]) -> Iterator[tuple[str, int, HistoryKey, dict[str, Any]]]:
        if any(key[0] != self.tenant_id for key in wanted):
            raise ValueError("finding history keys must belong to the reader tenant")
        keys = sorted({identity_hash(key) for key in wanted})
        for start in range(0, len(keys), KEY_BATCH):
            batch = keys[start : start + KEY_BATCH]
            placeholders = ",".join("?" for _ in batch)
            after: tuple[Any, ...] | None = None
            order = (
                ",".join(
                    f'{column} COLLATE "C"' if self.dialect == "postgres" else column
                    for column in ("evidence_at", "completed_at", "job_id")
                )
                + ",ordinal"
            )
            while True:
                cursor_sql = f" AND ({order})>(?,?,?,?)" if after is not None else ""
                rows = self.session.execute(
                    "SELECT evidence_at,completed_at,job_id,ordinal,payload FROM finding_history_rows WHERE tenant_id=? "
                    f"AND history_key IN ({placeholders}){cursor_sql} ORDER BY {order} LIMIT ?",  # nosec B608 - fixed order and placeholders
                    (self.tenant_id, *batch, *(after or ()), PAGE_SIZE),
                ).fetchall()
                for _, _, job_id, ordinal, payload in rows:
                    value = json.loads(payload)
                    key = tuple(value["key"])
                    if key not in wanted or not isinstance(value["row"], dict):
                        raise HistoryUnavailableError("invalid finding history occurrence")
                    yield job_id, ordinal, key, value["row"]
                if len(rows) < PAGE_SIZE:
                    break
                after = tuple(rows[-1][:4])

    def history(self, jobs: Iterable[FindingHistoryJob], wanted: set[HistoryKey], authoritative: bool) -> dict[HistoryKey, dict[str, Any]]:
        eligible = {job.job_id: job for job in jobs if not job.child_job_ids and (not authoritative or job.authoritative)}
        history: dict[HistoryKey, dict[str, Any]] = {}
        for job_id, _, key, row in self.occurrences(wanted):
            if job_id in eligible:
                _merge_retained_history_row(history, key, row)
        return history
