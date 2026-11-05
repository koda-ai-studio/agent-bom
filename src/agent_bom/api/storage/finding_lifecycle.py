"""Durable finding lifecycle: fold one scan in its job's transaction, and read it back."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from agent_bom.api.finding_collection import collect_scan_findings
from agent_bom.api.finding_lifecycle_fold import FindingState, ScanEvidence, apply_evidence, scan_evidence
from agent_bom.api.hub_payload_codec import decode_hub_payload, encode_hub_payload
from agent_bom.api.storage.hub_filters import _redact_finding
from agent_bom.api.storage.sql import Dialect, SqlSession
from agent_bom.graph.sla import merge_finding_sla

_KEY_BATCH = 400
_LIVE = ("open", "reopened")
BACKFILL_VERSION = 1
_NEVER_EXECUTED_SCOPE = ""
_STATE_COLUMNS = (
    "scope_hash,finding_key,canonical_id,environment,report_canonical_id,first_seen,last_seen,status,resolved_at,"
    "resolution_reason,reopened_at,scan_count,last_job_id,unconfirmed_job_id,unconfirmed_at,asset_key,coverage_key,payload_hash"
)
_UPSERT = (
    "INSERT INTO finding_lifecycle (tenant_id,scope_hash,finding_key,canonical_id,environment,report_canonical_id,first_seen,last_seen,"
    "status,resolved_at,resolution_reason,reopened_at,scan_count,last_job_id,unconfirmed_job_id,unconfirmed_at,asset_key,coverage_key,"
    "payload_hash,payload) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (tenant_id,scope_hash,finding_key) DO UPDATE SET "
    "first_seen=excluded.first_seen,last_seen=excluded.last_seen,status=excluded.status,resolved_at=excluded.resolved_at,"
    "resolution_reason=excluded.resolution_reason,reopened_at=excluded.reopened_at,scan_count=excluded.scan_count,"
    "last_job_id=excluded.last_job_id,unconfirmed_job_id=excluded.unconfirmed_job_id,unconfirmed_at=excluded.unconfirmed_at,"
    "asset_key=excluded.asset_key,coverage_key=excluded.coverage_key,payload_hash=excluded.payload_hash,payload=excluded.payload"
)
# Rewriting an unchanged payload would churn storage on every rescan of every finding.
_UPDATE_STATE = (
    "UPDATE finding_lifecycle SET first_seen=?,last_seen=?,status=?,resolved_at=?,resolution_reason=?,reopened_at=?,scan_count=?,"
    "last_job_id=?,unconfirmed_job_id=?,unconfirmed_at=?,asset_key=?,coverage_key=? "
    "WHERE tenant_id=? AND scope_hash=? AND finding_key=?"
)


def _state(row: Sequence[Any]) -> FindingState:
    return FindingState(
        scope_hash=row[0],
        finding_key=row[1],
        canonical_id=row[2],
        environment=row[3],
        report_canonical_id=row[4],
        first_seen=row[5],
        last_seen=row[6],
        status=row[7],
        resolved_at=row[8],
        resolution_reason=row[9],
        reopened_at=row[10],
        scan_count=int(row[11]),
        last_job_id=row[12],
        unconfirmed_job_id=row[13],
        unconfirmed_at=row[14],
        asset_key=row[15],
        coverage_key=row[16],
        payload_hash=row[17],
    )


def _lock_scope(session: SqlSession, dialect: Dialect, evidence: ScanEvidence) -> None:
    """Serialize writers of one scope, including replicas; SQLite already holds its single writer lock."""
    if dialect == "postgres":
        session.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", (f"finding-lifecycle:{evidence.tenant_id}:{evidence.scope_hash}",)
        )


def _load_scope_states(session: SqlSession, evidence: ScanEvidence, *, whole_scope: bool) -> dict[str, FindingState]:
    scope = (evidence.tenant_id, evidence.scope_hash)
    where = "" if whole_scope else " AND status IN (?,?)"
    params = scope if whole_scope else (*scope, *_LIVE)
    rows = session.execute(
        f"SELECT {_STATE_COLUMNS} FROM finding_lifecycle WHERE tenant_id=? AND scope_hash=?{where}",  # nosec B608 - fixed columns and predicate
        params,
    ).fetchall()
    states = {row[1]: _state(row) for row in rows}
    wanted = sorted(key for key in evidence.observed if key not in states)
    for start in range(0, len(wanted), _KEY_BATCH):
        batch = wanted[start : start + _KEY_BATCH]
        marks = ",".join("?" for _ in batch)
        rows = session.execute(
            f"SELECT {_STATE_COLUMNS} FROM finding_lifecycle WHERE tenant_id=? AND scope_hash=? AND finding_key IN ({marks})",  # nosec B608
            (*scope, *batch),
        ).fetchall()
        states.update((row[1], _state(row)) for row in rows)
    return states


def _encoded_payload(state: FindingState) -> str:
    """The redacted row, keeping a manual SLA assignment the previous row carried."""
    payload = _redact_finding(state.new_row or {})
    if state.payload:
        payload = merge_finding_sla(payload, state.payload, first_seen=state.first_seen)
    return encode_hub_payload(payload)


def _write_states(session: SqlSession, tenant_id: str, changed: list[FindingState], existing: set[str]) -> None:
    full = [state for state in changed if state.new_row is not None]
    partial = [state for state in changed if state.new_row is None]
    attach_payloads(session, tenant_id, [state for state in full if state.finding_key in existing and state.payload is None])
    if full:
        session.executemany(
            _UPSERT,
            [
                (
                    tenant_id,
                    state.scope_hash,
                    state.finding_key,
                    state.canonical_id,
                    state.environment,
                    state.report_canonical_id,
                    state.first_seen,
                    state.last_seen,
                    state.status,
                    state.resolved_at,
                    state.resolution_reason,
                    state.reopened_at,
                    state.scan_count,
                    state.last_job_id,
                    state.unconfirmed_job_id,
                    state.unconfirmed_at,
                    state.asset_key,
                    state.coverage_key,
                    state.payload_hash,
                    _encoded_payload(state),
                )
                for state in full
            ],
        )
    if partial:
        session.executemany(
            _UPDATE_STATE,
            [
                (
                    state.first_seen,
                    state.last_seen,
                    state.status,
                    state.resolved_at,
                    state.resolution_reason,
                    state.reopened_at,
                    state.scan_count,
                    state.last_job_id,
                    state.unconfirmed_job_id,
                    state.unconfirmed_at,
                    state.asset_key,
                    state.coverage_key,
                    tenant_id,
                    state.scope_hash,
                    state.finding_key,
                )
                for state in partial
            ],
        )


def apply_job_lifecycle(session: SqlSession, dialect: Dialect, job: Any) -> bool:
    """Fold a finished scan into durable state, once; ``False`` when it adds nothing.

    A job row is rewritten after completion (graph receipts, repair), and a
    delivery can repeat: the scan ledger makes the fold idempotent per job.
    """
    evidence = scan_evidence(job, collect_scan_findings)
    if evidence is None:
        # Recorded too, so "every finished job is folded" can be answered from SQL.
        session.execute(
            "INSERT INTO finding_lifecycle_scans (tenant_id,scope_hash,job_id,evidence_at,complete) VALUES (?,?,?,?,0) "
            "ON CONFLICT (tenant_id,scope_hash,job_id) DO NOTHING",
            (job.tenant_id, _NEVER_EXECUTED_SCOPE, job.job_id, ""),
        )
        return False
    tenant_id = evidence.tenant_id
    _lock_scope(session, dialect, evidence)
    scope = (tenant_id, evidence.scope_hash)
    if session.execute(
        "SELECT 1 FROM finding_lifecycle_scans WHERE tenant_id=? AND scope_hash=? AND job_id=?", (*scope, evidence.job_id)
    ).fetchone():
        return False
    newer = session.execute(
        "SELECT 1 FROM finding_lifecycle_scans WHERE tenant_id=? AND scope_hash=? AND evidence_at>? LIMIT 1", (*scope, evidence.at)
    ).fetchone()
    session.execute(
        "INSERT INTO finding_lifecycle_scans (tenant_id,scope_hash,job_id,evidence_at,complete) VALUES (?,?,?,?,?)",
        (*scope, evidence.job_id, evidence.at, int(evidence.complete)),
    )
    states = _load_scope_states(session, evidence, whole_scope=newer is not None)
    existing = set(states)
    complete_times: list[str] = []
    if newer is not None:
        rows = session.execute(
            "SELECT evidence_at FROM finding_lifecycle_scans WHERE tenant_id=? AND scope_hash=? AND complete=1 ORDER BY evidence_at", scope
        ).fetchall()
        complete_times = [row[0] for row in rows]
    if evidence.degraded:
        attach_payloads(session, tenant_id, [state for key, state in states.items() if state.live and key not in evidence.observed])
    changed = apply_evidence(states, evidence, complete_times, lambda state: state.payload or {})
    _write_states(session, tenant_id, changed, existing)
    return True


def purge_tenant(session: SqlSession, tenant_id: str) -> int:
    deleted = int(session.execute("DELETE FROM finding_lifecycle WHERE tenant_id=?", (tenant_id,)).rowcount or 0)
    for table in ("finding_lifecycle_scans", "finding_lifecycle_backfill"):
        session.execute(f"DELETE FROM {table} WHERE tenant_id=?", (tenant_id,))  # nosec B608 - fixed tables
    return deleted


def _job_table(dialect: Dialect) -> tuple[str, str]:
    return ("scan_jobs", "team_id") if dialect == "postgres" else ("jobs", "tenant_id")


def pending_job_ids(session: SqlSession, dialect: Dialect, tenant_id: str, limit: int) -> list[str]:
    """Finished jobs not yet folded, which only exist for scans from before this table."""
    table, tenant = _job_table(dialect)
    rows = session.execute(
        f"SELECT j.job_id FROM {table} j WHERE j.{tenant}=? AND j.status='done' AND NOT EXISTS ("  # nosec B608 - fixed identifiers
        f"SELECT 1 FROM finding_lifecycle_scans s WHERE s.tenant_id=j.{tenant} AND s.job_id=j.job_id) "
        "ORDER BY j.completed_at LIMIT ?",
        (tenant_id, limit),
    ).fetchall()
    return [row[0] for row in rows]


def unbackfilled_tenants(session: SqlSession, dialect: Dialect, limit: int) -> list[str]:
    table, tenant = _job_table(dialect)
    rows = session.execute(
        f"SELECT DISTINCT {tenant} FROM {table} WHERE status='done' AND {tenant} NOT IN "  # nosec B608 - fixed identifiers
        "(SELECT tenant_id FROM finding_lifecycle_backfill) LIMIT ?",
        (limit,),
    ).fetchall()
    return [row[0] for row in rows]


def backfilled(session: SqlSession, tenant_id: str) -> bool:
    row = session.execute("SELECT version FROM finding_lifecycle_backfill WHERE tenant_id=?", (tenant_id,)).fetchone()
    return row is not None and int(row[0]) >= BACKFILL_VERSION


def mark_backfilled(session: SqlSession, tenant_id: str) -> None:
    session.execute(
        "INSERT INTO finding_lifecycle_backfill (tenant_id,version) VALUES (?,?) "
        "ON CONFLICT (tenant_id) DO UPDATE SET version=excluded.version",
        (tenant_id, BACKFILL_VERSION),
    )


def renamed_findings(session: SqlSession, tenant_id: str) -> list[tuple[str, str]]:
    """``(reported id, project id)`` pairs, for state keyed on an id from before projects joined identity."""
    rows = session.execute(
        "SELECT DISTINCT report_canonical_id,canonical_id FROM finding_lifecycle WHERE tenant_id=? AND report_canonical_id IS NOT NULL",
        (tenant_id,),
    ).fetchall()
    return [(row[0], row[1]) for row in rows]


def live_states(session: SqlSession, tenant_id: str) -> list[FindingState]:
    rows = session.execute(
        f"SELECT {_STATE_COLUMNS} FROM finding_lifecycle WHERE tenant_id=? AND status<>'resolved'",  # nosec B608 - fixed columns
        (tenant_id,),
    ).fetchall()
    return [_state(row) for row in rows]


def resolved_states(session: SqlSession, tenant_id: str, since: str | None, limit: int) -> list[FindingState]:
    """Newest resolutions first, with their rows: these usually have no retained scan left to read from."""
    where = " AND resolved_at>=?" if since else ""
    bound = (tenant_id, since, limit) if since else (tenant_id, limit)
    rows = session.execute(
        f"SELECT {_STATE_COLUMNS},payload FROM finding_lifecycle WHERE tenant_id=? AND status='resolved'{where} "  # nosec B608 - fixed columns
        "ORDER BY resolved_at DESC,canonical_id LIMIT ?",
        bound,
    ).fetchall()
    states = []
    for row in rows:
        state = _state(row)
        state.payload = decode_hub_payload(row[18])
        states.append(state)
    return states


def resolved_exceeds(session: SqlSession, tenant_id: str, since: str | None, limit: int) -> bool:
    where = " AND resolved_at>=?" if since else ""
    bound = (tenant_id, since, limit) if since else (tenant_id, limit)
    row = session.execute(
        f"SELECT 1 FROM finding_lifecycle WHERE tenant_id=? AND status='resolved'{where} ORDER BY resolved_at DESC,canonical_id "  # nosec B608
        "LIMIT 1 OFFSET ?",
        bound,
    ).fetchone()
    return row is not None


def attach_payloads(session: SqlSession, tenant_id: str, states: list[FindingState]) -> None:
    by_scope: dict[str, dict[str, FindingState]] = {}
    for state in states:
        by_scope.setdefault(state.scope_hash, {})[state.finding_key] = state
    for scope_hash, keyed in by_scope.items():
        keys = sorted(keyed)
        for start in range(0, len(keys), _KEY_BATCH):
            batch = keys[start : start + _KEY_BATCH]
            marks = ",".join("?" for _ in batch)
            rows = session.execute(
                f"SELECT finding_key,payload FROM finding_lifecycle WHERE tenant_id=? AND scope_hash=? AND finding_key IN ({marks})",  # nosec B608
                (tenant_id, scope_hash, *batch),
            ).fetchall()
            for key, payload in rows:
                keyed[key].payload = decode_hub_payload(payload)
