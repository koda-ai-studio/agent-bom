"""Transaction-owned runtime observation writes, with immutable replay receipts."""

import hashlib
import json

from agent_bom.analytics_retention import prune_runtime_observations_for_tenant
from agent_bom.api.runtime_event_store import RuntimeObservationRecord, _merge_session, _session_from_json
from agent_bom.api.storage.sql import SqlSession
from agent_bom.api.trace_collection.contracts import MAX_RECEIPTS, CollectionConflictError


def put_page(tx: SqlSession, tenant: str, connection: str, records: list[RuntimeObservationRecord]) -> int:
    added = 0
    for record in records:
        if record.tenant_id != tenant:
            raise CollectionConflictError("Observation tenant does not match collection.")
        data = json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(data.encode()).hexdigest()
        prior = tx.execute(
            "SELECT digest FROM trace_collection_receipts WHERE tenant_id=? AND connection_id=? AND observation_id=?",
            (tenant, connection, record.observation_id),
        ).fetchone()
        if prior:
            if prior[0] != digest:
                raise CollectionConflictError("Conflicting observation replay; checkpoint retained.")
            continue
        existing = tx.execute(
            "SELECT data FROM runtime_observations WHERE tenant_id=? AND observation_id=?", (tenant, record.observation_id)
        ).fetchone()
        if existing and json.loads(existing[0]) != record.to_dict():
            raise CollectionConflictError("Conflicting retained observation; checkpoint retained.")
        tx.execute(
            "INSERT INTO trace_collection_receipts VALUES (?, ?, ?, ?, ?)",
            (tenant, connection, record.observation_id, record.observed_at, digest),
        )
        if existing:
            continue
        tx.execute(
            "INSERT INTO runtime_observations (tenant_id,observation_id,session_id,observed_at,data) VALUES (?,?,?,?,?)",
            (tenant, record.observation_id, record.session_id, record.observed_at, data),
        )
        row = tx.execute("SELECT data FROM runtime_sessions WHERE tenant_id=? AND session_id=?", (tenant, record.session_id)).fetchone()
        session = _merge_session(_session_from_json(row[0]) if row else None, record)
        tx.execute(
            "INSERT INTO runtime_sessions(tenant_id,session_id,last_seen,data) VALUES(?,?,?,?) "
            "ON CONFLICT(tenant_id,session_id) DO UPDATE SET last_seen=excluded.last_seen,data=excluded.data",
            (tenant, session.session_id, session.last_seen, json.dumps(session.to_dict(), sort_keys=True)),
        )
        added += 1
    count = tx.execute(
        "SELECT COUNT(*) FROM trace_collection_receipts WHERE tenant_id=? AND connection_id=?", (tenant, connection)
    ).fetchone()[0]
    if count > MAX_RECEIPTS:
        raise CollectionConflictError("Collection replay capacity reached; checkpoint retained.")
    prune_runtime_observations_for_tenant(tx, tenant)
    tx.execute(
        "DELETE FROM runtime_sessions WHERE tenant_id=? AND session_id LIKE ? "
        "AND NOT EXISTS (SELECT 1 FROM runtime_observations o WHERE o.tenant_id=runtime_sessions.tenant_id "
        "AND o.session_id=runtime_sessions.session_id)",
        (tenant, "trace:%"),
    )
    return added
