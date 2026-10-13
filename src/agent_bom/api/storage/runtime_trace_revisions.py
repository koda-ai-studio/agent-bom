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
    return _content_hash(record.to_dict())


def _content_hash(data: dict[str, Any]) -> str:
    # Own a detached payload; callers serialize the full revision before this
    # removes collection-only fields from the stable content identity.
    data["metadata"].pop("collected_at", None)
    if data["metadata"].get("event_time_missing"):
        data.pop("observed_at", None)
    return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _fresh_identities(conn: Any, records: list[RuntimeObservationRecord], p: str) -> set[tuple[str, str]]:
    identities = list(dict.fromkeys((record.tenant_id, record.observation_id) for record in records if record.surface == "imported_trace"))
    existing: set[tuple[str, str]] = set()
    for start in range(0, len(identities), 200):
        batch = identities[start : start + 200]
        pairs = ",".join(f"({p},{p})" for _ in batch)
        params = tuple(value for identity in batch for value in identity)
        for table in ("runtime_observations", "runtime_observation_revisions"):
            rows = conn.execute(
                f"SELECT tenant_id,observation_id FROM {table} "  # nosec B608 — fixed table names, bound identities
                f"WHERE (tenant_id,observation_id) IN ({pairs}) GROUP BY tenant_id,observation_id",
                params,
            ).fetchall()
            existing.update((row[0], row[1]) for row in rows)
    return set(identities) - existing


def _encode_revision(record: RuntimeObservationRecord) -> tuple[str, str]:
    payload = record.to_dict()
    encoded = json.dumps(payload, sort_keys=True)
    return _content_hash(payload), encoded


def _insert_fresh_revisions(conn: Any, records: list[RuntimeObservationRecord], fresh: set[tuple[str, str]], p: str) -> None:
    pending: dict[tuple[str, str], RuntimeObservationRecord] = {}
    for record in records:
        identity = (record.tenant_id, record.observation_id)
        if record.surface == "imported_trace" and identity in fresh:
            pending.setdefault(identity, record)
    entries = list(pending.items())
    for start in range(0, len(entries), 100):
        batch = entries[start : start + 100]
        values = ",".join(f"({','.join([p] * 5)})" for _ in batch)
        params = tuple(value for identity, record in batch for value in (*identity, 1, *_encode_revision(record)))
        conn.execute(
            "INSERT INTO runtime_observation_revisions "  # nosec B608 — bound values, fixed identifiers
            f"(tenant_id,observation_id,revision,content_hash,data) VALUES {values}",
            params,
        )


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


def _revise_session_sql(conn: Any, old: RuntimeObservationRecord, record: RuntimeObservationRecord, p: str) -> None:
    from agent_bom.api.storage.runtime_records import _session_from_json

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


def reconcile_sql(
    conn: Any, records: list[RuntimeObservationRecord], *, placeholder: str = "?"
) -> tuple[int, list[RuntimeObservationRecord]]:
    """Reconcile under the tenant write lock; return updates and first-seen rows.

    Retention of the current projection does not erase replay identity or reset
    lifetime session counts. History lookups are bounded and indexed.
    """
    from agent_bom.api.storage.runtime_records import _observation_from_json

    if placeholder not in {"?", "%s"}:
        raise ValueError("Unsupported SQL placeholder")
    p = placeholder
    updated = 0
    first_seen = []
    fresh = _fresh_identities(conn, records, p)
    _insert_fresh_revisions(conn, records, fresh, p)
    for record in records:
        if record.surface != "imported_trace":
            first_seen.append(record)
            continue
        identity = (record.tenant_id, record.observation_id)
        if identity in fresh:
            # A repeated identity later in this page must reconcile against the
            # revision just written, including conflicting session identities.
            fresh.remove(identity)
            first_seen.append(record)
            continue
        digest, encoded = _encode_revision(record)
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

        def append(value: RuntimeObservationRecord, *, prepared: tuple[str, str] | None = None) -> None:
            nonlocal revision
            revision += 1
            conn.execute(
                "INSERT INTO runtime_observation_revisions "  # nosec B608
                f"(tenant_id,observation_id,revision,content_hash,data) VALUES ({','.join([p] * 5)})",
                (*identity, revision, *(prepared or (content_hash(value), json.dumps(value.to_dict(), sort_keys=True)))),
            )

        if old and not latest:
            append(old)  # Backfill history for pre-revision databases.
        known = conn.execute(
            f"SELECT 1 FROM runtime_observation_revisions "  # nosec B608
            f"WHERE tenant_id={p} AND observation_id={p} AND content_hash={p}",
            (*identity, digest),
        ).fetchone()
        if known:
            continue
        append(record, prepared=(digest, encoded))
        if old is None:
            first_seen.append(record)
            continue
        # A pruned projection stays pruned. Its new revision is retained and its
        # lifetime rollup updated without re-admitting it as a new observation.
        conn.execute(
            f"UPDATE runtime_observations SET data={p}, observed_at={p} "  # nosec B608
            f"WHERE tenant_id={p} AND observation_id={p}",
            (encoded, record.observed_at, *identity),
        )
        _revise_session_sql(conn, old, record, p)
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


def _orphan_histories_sql(p: str, when: str) -> str:
    return (
        "SELECT r.observation_id, COUNT(*) FROM runtime_observation_revisions r "  # nosec B608 — fixed identifiers
        f"WHERE r.tenant_id={p} AND NOT EXISTS (SELECT 1 FROM runtime_observations o "
        "WHERE o.tenant_id=r.tenant_id AND o.observation_id=r.observation_id) "
        f"GROUP BY r.observation_id ORDER BY MIN({when}), r.observation_id LIMIT {p}"
    )


def _superseded_revisions_sql(p: str, when: str) -> str:
    return (
        "SELECT r.observation_id, r.revision FROM runtime_observation_revisions r "  # nosec B608 — fixed identifiers
        f"WHERE r.tenant_id={p} AND r.revision < (SELECT MAX(x.revision) FROM runtime_observation_revisions x "
        "WHERE x.tenant_id=r.tenant_id AND x.observation_id=r.observation_id) "
        f"ORDER BY {when}, r.observation_id, r.revision LIMIT {p}"
    )


def prune_revisions_for_tenant(
    conn: Any, tenant_id: str, *, placeholder: str = "?", dialect: str = "sqlite", max_rows: int | None = None
) -> int:
    """Bound one tenant's revision history after the projection write.

    Histories whose projection row was already pruned are dropped whole, oldest
    first; then superseded revisions of retained spans. The latest revision of
    any span is never dropped. A dropped history no longer suppresses a later
    replay of that span, matching projection retention.
    """
    from agent_bom.analytics_retention import analytics_max_trace_revisions

    if placeholder not in {"?", "%s"} or dialect not in {"sqlite", "postgres"}:
        raise ValueError("Unsupported SQL dialect")
    cap = analytics_max_trace_revisions() if max_rows is None else max_rows
    if cap <= 0:
        return 0
    p = placeholder
    total = conn.execute(f"SELECT COUNT(*) FROM runtime_observation_revisions WHERE tenant_id={p}", (tenant_id,)).fetchone()[0]  # nosec B608
    excess = int(total) - cap
    if excess <= 0:
        return 0
    when = "json_extract(r.data,'$.observed_at')" if dialect == "sqlite" else "(r.data::jsonb->>'observed_at')"
    removed = 0
    while excess > 0:
        histories = conn.execute(_orphan_histories_sql(p, when), (tenant_id, min(excess, 500))).fetchall()
        if not histories:
            break
        for observation_id, rows in histories:
            conn.execute(
                f"DELETE FROM runtime_observation_revisions WHERE tenant_id={p} AND observation_id={p}",  # nosec B608
                (tenant_id, observation_id),
            )
            excess -= int(rows)
            removed += int(rows)
            if excess <= 0:
                break
    while excess > 0:
        superseded = conn.execute(_superseded_revisions_sql(p, when), (tenant_id, min(excess, 500))).fetchall()
        if not superseded:
            break
        for observation_id, revision in superseded:
            conn.execute(
                f"DELETE FROM runtime_observation_revisions WHERE tenant_id={p} AND observation_id={p} AND revision={p}",  # nosec B608
                (tenant_id, observation_id, revision),
            )
        excess -= len(superseded)
        removed += len(superseded)
    return removed


def prune_revisions_in_memory(
    revisions: dict[tuple[str, str], list[RuntimeObservationRecord]],
    projection: dict[tuple[str, str], RuntimeObservationRecord],
    tenant_id: str,
    *,
    max_rows: int | None = None,
) -> int:
    """In-memory twin of :func:`prune_revisions_for_tenant`."""
    from agent_bom.analytics_retention import analytics_max_trace_revisions

    cap = analytics_max_trace_revisions() if max_rows is None else max_rows
    if cap <= 0:
        return 0
    keys = [key for key in revisions if key[0] == tenant_id]
    excess = sum(len(revisions[key]) for key in keys) - cap
    removed = 0

    def oldest(key: tuple[str, str]) -> tuple[str, str]:
        return min((record.observed_at for record in revisions[key]), default=""), key[1]

    orphans = sorted((key for key in keys if key not in projection), key=oldest)
    for key in orphans:
        if excess <= 0:
            break
        rows = len(revisions.pop(key))
        excess -= rows
        removed += rows
    if excess > 0:
        live = [key for key in keys if key in revisions]
        superseded = sorted((record.observed_at, key[1], index, key) for key in live for index, record in enumerate(revisions[key][:-1]))[
            :excess
        ]
        drop: dict[tuple[str, str], set[int]] = {}
        for _, _, index, key in superseded:
            drop.setdefault(key, set()).add(index)
        for key, indexes in drop.items():
            revisions[key] = [record for index, record in enumerate(revisions[key]) if index not in indexes]
            removed += len(indexes)
    return removed
