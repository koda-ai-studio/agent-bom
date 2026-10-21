"""Current-state observations and reconciliation within the caller's transaction."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from agent_bom.api.finding_lifecycle import observation_at_least, resolve_canonical_id
from agent_bom.api.hub_current_payload import current_state_overlay, resolve_ledger_finding_id
from agent_bom.api.hub_payload_codec import encode_hub_payload
from agent_bom.api.storage.finding_current import CURRENT_COLUMNS, LEDGER_ORDINAL_SENTINEL, hydrate_rows, keyed_rows, parse_row
from agent_bom.api.storage.hub_filters import _redact_finding
from agent_bom.api.storage.sql import Dialect, SqlSession, json_text, utc_timestamp
from agent_bom.core.tenancy import require_explicit_tenant_id


def current_upsert(dialect: Dialect, has_ledger: bool) -> str:
    fields = ["tenant_id", *CURRENT_COLUMNS, "origin", "scan_id"]
    if has_ledger:
        fields.extend(["ledger_finding_id", "ledger_ordinal"])
    values = ["CAST(? AS JSONB)" if field == "payload" and dialect == "postgres" else "?" for field in fields]
    # The caller holds the tenant write lock; the merge compares actual instants,
    # unlike lexical SQL comparisons of legacy offset/subsecond text timestamps.
    updates = [f"{field} = excluded.{field}" for field in fields if field not in {"tenant_id", "canonical_id"}]
    return (
        f"INSERT INTO hub_findings_current ({', '.join(fields)}) VALUES ({', '.join(values)}) "  # nosec B608
        f"ON CONFLICT (tenant_id, canonical_id) DO UPDATE SET {', '.join(updates)}"
    )


def _recorded_batch_ids(tx: SqlSession, tenant: str, batch_id: str, keys: Sequence[str]) -> set[str]:
    # Postgres partitions include observed_at in their physical uniqueness key;
    # a replay with a changed timestamp must still be one logical observation.
    replayed: set[str] = set()
    for start in range(0, len(keys), 500):
        batch = keys[start : start + 500]
        markers = ",".join("?" for _ in batch)
        replayed.update(
            str(row[0])
            for row in tx.execute(
                "SELECT canonical_id FROM hub_findings_current_observations WHERE tenant_id = ? AND scan_id = ? "
                f"AND canonical_id IN ({markers})",  # nosec B608
                (tenant, batch_id, *batch),
            ).fetchall()
        )
    return replayed


def current_ledger_candidates(
    tx: SqlSession, tenant_id: str, findings: Sequence[dict[str, Any]], *, observed_at: str, batch_id: str, source: str
) -> list[dict[str, Any]]:
    """Protect the payload behind current-state pointers before ledger writes.

    Older sightings still enter the observation log and update first_seen/count.
    A replay cannot replace its previously admitted payload. The caller holds
    the same write lock for this read, ledger write and current-state update.
    """
    tenant = require_explicit_tenant_id(tenant_id)
    by_id: dict[str, dict[str, Any]] = {}
    for payload in findings:
        by_id.setdefault(resolve_canonical_id(_redact_finding(payload), source=source), payload)
    keys = list(by_id)
    current: dict[str, str] = {}
    replayed = _recorded_batch_ids(tx, tenant, batch_id, keys)
    for start in range(0, len(keys), 500):
        batch = keys[start : start + 500]
        markers = ",".join("?" for _ in batch)
        current.update(
            tx.execute(
                f"SELECT canonical_id, last_seen FROM hub_findings_current WHERE tenant_id = ? AND canonical_id IN ({markers})",  # nosec B608
                (tenant, *batch),
            ).fetchall()
        )
    return [
        payload
        for key, payload in by_id.items()
        if key not in replayed and (key not in current or observation_at_least(observed_at, str(current[key])))
    ]


def write_current_batch(
    tx: SqlSession,
    dialect: Dialect,
    tenant_id: str,
    clean: Sequence[dict[str, Any]],
    *,
    observed_at: str,
    batch_id: str,
    source: str,
    has_ledger: bool,
) -> None:
    from agent_bom.api import finding_lifecycle

    tenant = require_explicit_tenant_id(tenant_id)
    if not clean:
        return
    # Keep the first payload per canonical, matching observation replay semantics.
    by_id: dict[str, dict[str, Any]] = {}
    for payload in clean:
        by_id.setdefault(finding_lifecycle.resolve_canonical_id(payload, source=source), payload)
    for key in _recorded_batch_ids(tx, tenant, batch_id, list(by_id)):
        by_id.pop(key, None)
    if not by_id:
        return
    observed = tx.executemany_returning(
        "INSERT INTO hub_findings_current_observations (tenant_id, canonical_id, scan_id, observed_at) "
        "VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING RETURNING canonical_id",
        [(tenant, canonical, batch_id, observed_at) for canonical in by_id],
    )
    inserted = {str(row[0]) for row in observed}
    if not inserted:
        return
    prior = keyed_rows(tx, tenant, list(inserted), ledger=False, has_ledger=has_ledger)
    existing = {row["canonical_id"]: row for row in hydrate_rows(tx, tenant, [parse_row(row, has_ledger_col=has_ledger) for row in prior])}
    ledger_ids = {key: resolve_ledger_finding_id(payload, canonical_id=key) or "" for key, payload in by_id.items() if key in inserted}
    ledger = keyed_rows(tx, tenant, list(ledger_ids.values()), ledger=True) if has_ledger else []
    ordinals = {str(row[0]): int(row[2]) for row in ledger}
    now = utc_timestamp()
    rows = []
    for canonical, payload in by_id.items():
        if canonical not in inserted:
            continue
        merged = finding_lifecycle.apply_observation_to_current(
            existing.get(canonical),
            canonical_id=canonical,
            observed_at=observed_at,
            metrics=finding_lifecycle.lifecycle_metrics(payload),
            payload=payload,
            updated_at=now,
        )
        pointer = ledger_ids[canonical]
        effective_payload = merged["payload"]
        merged["payload"] = encode_hub_payload(current_state_overlay(merged["payload"]) if pointer else merged["payload"])
        row = (
            tenant,
            *(merged[column] for column in CURRENT_COLUMNS),
            str(effective_payload.get("origin") or ""),
            str(effective_payload.get("batch_id") or effective_payload.get("scan_id") or ""),
        )
        if has_ledger:
            row += (pointer or None, ordinals.get(pointer, LEDGER_ORDINAL_SENTINEL))
        rows.append(row)
    tx.executemany(current_upsert(dialect, has_ledger), rows)


def reconcile_current(
    tx: SqlSession, dialect: Dialect, tenant_id: str, *, present_canonical_ids: set[str], observed_at: str, scope_source: str | None
) -> int:
    tenant = require_explicit_tenant_id(tenant_id)
    where = ["tenant_id = ?", "status IN ('open', 'reopened')"]
    params: list[Any] = [tenant]
    if scope_source is not None:
        where.append(f"COALESCE({json_text(dialect, 'payload', 'ingest_source')}, {json_text(dialect, 'payload', 'source')}) = ?")
        params.append(scope_source)
    predicate = " AND ".join(where)
    rows = tx.execute(f"SELECT canonical_id, last_seen FROM hub_findings_current WHERE {predicate}", params).fetchall()  # nosec B608
    absent = sorted({str(row[0]) for row in rows if observation_at_least(observed_at, str(row[1]))} - present_canonical_ids)
    total = 0
    now = utc_timestamp()
    for start in range(0, len(absent), 500):
        batch = absent[start : start + 500]
        placeholders = ",".join("?" for _ in batch)
        result = tx.execute(
            f"UPDATE hub_findings_current SET status = 'resolved', resolved_at = ?, updated_at = ? "  # nosec B608
            f"WHERE {predicate} AND canonical_id IN ({placeholders})",
            (observed_at, now, *params, *batch),
        )  # nosec B608
        total += int(result.rowcount or 0)
    return total
