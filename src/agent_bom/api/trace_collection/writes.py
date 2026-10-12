"""Transaction-owned runtime observation writes, with immutable replay receipts."""

import hashlib
import json

from agent_bom.analytics_retention import prune_runtime_observations_for_tenant
from agent_bom.api.runtime_event_store import RuntimeObservationRecord, RuntimeSessionRecord, _merge_session, _session_from_json
from agent_bom.api.storage.runtime_trace_revisions import reconcile_sql
from agent_bom.api.storage.sql import SqlSession
from agent_bom.api.trace_collection.contracts import MAX_RECEIPTS, CollectionConflictError


def put_page(tx: SqlSession, tenant: str, connection: str, records: list[RuntimeObservationRecord]) -> int:
    if any(record.tenant_id != tenant for record in records):
        raise CollectionConflictError("Observation tenant does not match collection.")
    # Window imports and resumable collection share native IDs and append-only
    # revisions. A changed native span updates its projection, not its count.
    native = {record.observation_id: record for record in records if record.surface == "imported_trace"}
    _, first_seen = reconcile_sql(tx, list(native.values()))
    records = [record for record in records if record.surface != "imported_trace"] + first_seen
    prior_receipts: dict[str, str] = {}
    retained: dict[str, str] = {}
    keys = list(dict.fromkeys(record.observation_id for record in records))
    for start in range(0, len(keys), 200):
        batch = keys[start : start + 200]
        placeholders = ",".join("?" for _ in batch)
        prior_receipts.update(
            tx.execute(
                "SELECT observation_id,digest FROM trace_collection_receipts "
                f"WHERE tenant_id=? AND connection_id=? AND observation_id IN ({placeholders})",  # nosec B608
                (tenant, connection, *batch),
            ).fetchall()
        )
        retained.update(
            tx.execute(
                f"SELECT observation_id,data FROM runtime_observations WHERE tenant_id=? AND observation_id IN ({placeholders})",  # nosec B608
                (tenant, *batch),
            ).fetchall()
        )
    added = 0
    sessions: dict[str, RuntimeSessionRecord] = {}
    receipts = []
    observations = []
    for record in records:
        if record.tenant_id != tenant:
            raise CollectionConflictError("Observation tenant does not match collection.")
        payload = record.to_dict()
        data = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(data.encode()).hexdigest()
        prior = prior_receipts.get(record.observation_id)
        if prior:
            if prior != digest:
                raise CollectionConflictError("Conflicting observation replay; checkpoint retained.")
            continue
        existing = retained.get(record.observation_id)
        if existing and json.loads(existing) != payload:
            raise CollectionConflictError("Conflicting retained observation; checkpoint retained.")
        receipts.append((tenant, connection, record.observation_id, record.observed_at, digest))
        prior_receipts[record.observation_id] = digest
        if existing:
            continue
        observations.append((tenant, record.observation_id, record.session_id, record.observed_at, data))
        retained[record.observation_id] = data
        if record.session_id not in sessions:
            row = tx.execute("SELECT data FROM runtime_sessions WHERE tenant_id=? AND session_id=?", (tenant, record.session_id)).fetchone()
            previous = _session_from_json(row[0]) if row else None
        else:
            previous = sessions[record.session_id]
        sessions[record.session_id] = _merge_session(previous, record)
        added += 1
    for rows, insert in (
        (receipts, "INSERT INTO trace_collection_receipts(tenant_id,connection_id,observation_id,observed_at,digest) VALUES "),
        (observations, "INSERT INTO runtime_observations(tenant_id,observation_id,session_id,observed_at,data) VALUES "),
    ):
        for start in range(0, len(rows), 100):
            insert_batch = rows[start : start + 100]
            tx.execute(insert + ",".join("(?,?,?,?,?)" for _ in insert_batch), tuple(value for row in insert_batch for value in row))
    # Rollups and page/checkpoint writes still share the same transaction. Work
    # scales with distinct sessions instead of repeatedly reading each span's
    # growing session from SQL and rewriting the same row.
    for session in sessions.values():
        tx.execute(
            "INSERT INTO runtime_sessions(tenant_id,session_id,last_seen,data) VALUES(?,?,?,?) "
            "ON CONFLICT(tenant_id,session_id) DO UPDATE SET last_seen=excluded.last_seen,data=excluded.data",
            (tenant, session.session_id, session.last_seen, json.dumps(session.to_dict(), sort_keys=True)),
        )
    count = tx.execute(
        "SELECT COUNT(*) FROM trace_collection_receipts WHERE tenant_id=? AND connection_id=?", (tenant, connection)
    ).fetchone()[0]
    if count > MAX_RECEIPTS:
        raise CollectionConflictError("Collection replay capacity reached; checkpoint retained.")
    prune_runtime_observations_for_tenant(tx, tenant)
    tx.execute(
        "DELETE FROM runtime_sessions WHERE tenant_id=? AND session_id LIKE ? AND session_id NOT LIKE ? "
        "AND NOT EXISTS (SELECT 1 FROM runtime_observations o WHERE o.tenant_id=runtime_sessions.tenant_id "
        "AND o.session_id=runtime_sessions.session_id)",
        # Native history retains lifetime rollups after projection retention.
        (tenant, "trace:%", "trace:session:%"),
    )
    return added
