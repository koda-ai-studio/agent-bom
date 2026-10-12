"""Content revisions for imported spans, in the runtime store transaction.

History is append-only. Collection time alone is not a revision; a previously
seen content digest is a replay and cannot roll the current projection back.
Without a provider revision clock, a new digest means newly collected content,
not proof that it is the provider's latest state. These collector-owned rows
are not independent or tamper-proof audit evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_bom.api.storage.runtime_records import RuntimeObservationRecord, RuntimeSessionRecord

REVISION_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS runtime_observation_revisions (
    tenant_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    revision INTEGER NOT NULL,
    content_hash TEXT NOT NULL,
    data TEXT NOT NULL,
    PRIMARY KEY (tenant_id, observation_id, revision),
    UNIQUE (tenant_id, observation_id, content_hash)
)
"""


@dataclass(frozen=True)
class TracePageCommit:
    inserted: int = 0
    updated: int = 0
    unchanged: int = 0


def content_hash(record: RuntimeObservationRecord) -> str:
    data = record.to_dict()
    data["metadata"].pop("collected_at", None)
    if data["metadata"].get("event_time_missing"):
        data.pop("observed_at", None)
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def revised_session(session: RuntimeSessionRecord, old: RuntimeObservationRecord, new: RuntimeObservationRecord) -> RuntimeSessionRecord:
    """Replace a span's contribution, preserving lifetime observation counts."""

    def counts(current: dict[str, int], before: str, after: str) -> dict[str, int]:
        result = dict(current)
        if before:
            result[before] = max(0, result.get(before, 0) - 1)
        if after:
            result[after] = result.get(after, 0) + 1
        return dict(sorted((key, value) for key, value in result.items() if value))

    return replace(
        session,
        verdicts=counts(session.verdicts, old.verdict, new.verdict),
        severities=counts(session.severities, old.severity, new.severity),
        event_types=counts(session.event_types, old.event_type, new.event_type),
        tools=sorted(set(session.tools) | ({new.tool_name} if new.tool_name else set()))[:100],
    )


def reconcile_sql(
    conn: Any, records: list[RuntimeObservationRecord], *, placeholder: str = "?"
) -> tuple[int, list[RuntimeObservationRecord]]:
    """Reconcile under the tenant write lock; return updates and first-seen rows.

    Retention of the current projection does not erase replay identity or reset
    lifetime session counts. History lookups are bounded and indexed.
    """
    from agent_bom.api.storage.runtime_records import _observation_from_json, _session_from_json

    if placeholder not in {"?", "%s"}:
        raise ValueError("Unsupported SQL placeholder")
    p = placeholder
    updated = 0
    first_seen = []
    for record in records:
        if record.surface != "imported_trace":
            first_seen.append(record)
            continue
        identity = (record.tenant_id, record.observation_id)
        row = conn.execute(
            f"SELECT data FROM runtime_observations WHERE tenant_id={p} AND observation_id={p}",  # nosec B608
            identity,
        ).fetchone()
        latest = conn.execute(
            f"SELECT revision,data FROM runtime_observation_revisions "  # nosec B608
            f"WHERE tenant_id={p} AND observation_id={p} ORDER BY revision DESC LIMIT 1",
            identity,
        ).fetchone()
        old = _observation_from_json(row[0]) if row else (_observation_from_json(latest[1]) if latest else None)
        revision = latest[0] if latest else 0
        if old and (old.surface != "imported_trace" or old.session_id != record.session_id):
            raise ValueError("Native span identity conflicts with retained evidence")

        def append(value: RuntimeObservationRecord) -> None:
            nonlocal revision
            revision += 1
            conn.execute(
                "INSERT INTO runtime_observation_revisions "  # nosec B608
                f"(tenant_id,observation_id,revision,content_hash,data) VALUES ({','.join([p] * 5)})",
                (*identity, revision, content_hash(value), json.dumps(value.to_dict(), sort_keys=True)),
            )

        if old and not latest:
            append(old)  # Backfill history for pre-revision databases.
        known = conn.execute(
            f"SELECT 1 FROM runtime_observation_revisions "  # nosec B608
            f"WHERE tenant_id={p} AND observation_id={p} AND content_hash={p}",
            (*identity, content_hash(record)),
        ).fetchone()
        if known:
            continue
        append(record)
        if old is None:
            first_seen.append(record)
            continue
        # A pruned projection stays pruned. Its new revision is retained and its
        # lifetime rollup updated without re-admitting it as a new observation.
        conn.execute(
            f"UPDATE runtime_observations SET data={p}, observed_at={p} "  # nosec B608
            f"WHERE tenant_id={p} AND observation_id={p}",
            (json.dumps(record.to_dict(), sort_keys=True), record.observed_at, *identity),
        )
        session_row = conn.execute(
            f"SELECT data FROM runtime_sessions WHERE tenant_id={p} AND session_id={p}",  # nosec B608
            (record.tenant_id, record.session_id),
        ).fetchone()
        if session_row:
            session = revised_session(_session_from_json(session_row[0]), old, record)
            conn.execute(
                f"UPDATE runtime_sessions SET data={p} WHERE tenant_id={p} AND session_id={p}",  # nosec B608
                (json.dumps(session.to_dict(), sort_keys=True), record.tenant_id, record.session_id),
            )
        updated += 1
    return updated, first_seen


def read_revisions(
    conn: Any, tenant_id: str, observation_id: str, *, limit: int = 100, offset: int = 0, placeholder: str = "?"
) -> list[RuntimeObservationRecord]:
    from agent_bom.api.storage.runtime_records import _observation_from_json

    if placeholder not in {"?", "%s"}:
        raise ValueError("Unsupported SQL placeholder")
    p = placeholder
    rows = conn.execute(
        f"SELECT data FROM runtime_observation_revisions WHERE tenant_id={p} AND observation_id={p} ORDER BY revision LIMIT {p} OFFSET {p}",  # nosec B608
        (tenant_id, observation_id, max(1, min(limit, 1000)), max(0, offset)),
    ).fetchall()
    return [_observation_from_json(row[0]) for row in rows]
