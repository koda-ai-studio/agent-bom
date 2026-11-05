"""Hydrate finding references with bounded portable SQL in the caller's snapshot."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from agent_bom.api.hub_payload_codec import decode_hub_payload, encode_hub_payload
from agent_bom.api.hub_reference_payload import (
    cve_intel_blob,
    extract_reference_blobs,
    hydrate_reference_payload,
    hydration_reference_keys,
    merge_cve_intel,
    payload_is_kev,
    resolve_cve_id,
)
from agent_bom.api.storage.sql import Dialect, SqlSession, utc_timestamp


def _reference_rows(tx: SqlSession, tenant_id: str, keys: Sequence[str], *, frameworks: bool) -> dict[str, dict[str, Any]]:
    table, column = ("hub_framework_refs", "framework_ref") if frameworks else ("hub_cve_intel", "cve_id")
    found: dict[str, dict[str, Any]] = {}
    for start in range(0, len(keys), 500):
        batch = keys[start : start + 500]
        placeholders = ",".join("?" for _ in batch)
        rows = tx.execute(
            f"SELECT {column}, payload FROM {table} WHERE tenant_id = ? AND {column} IN ({placeholders})",  # nosec B608
            (tenant_id, *batch),
        ).fetchall()
        found.update((str(row[0]), decode_hub_payload(row[1])) for row in rows)
    return found


def hydrate_ledger_rows(tx: SqlSession, tenant_id: str, payloads: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    cve_ids, framework_refs = hydration_reference_keys(payloads)
    cve_map = _reference_rows(tx, tenant_id, sorted(cve_ids), frameworks=False)
    fw_map = _reference_rows(tx, tenant_id, sorted(framework_refs), frameworks=True)
    return [hydrate_reference_payload(item, cve_intel=cve_map, framework_refs=fw_map) for item in payloads]


def _encoder(dialect: Dialect) -> tuple[str, Callable[[dict[str, Any]], str]]:
    """The SQL value marker and encoder for a reference payload on this dialect."""
    if dialect == "postgres":
        return "CAST(? AS JSONB)", lambda blob: json.dumps(blob, sort_keys=True)
    return "?", encode_hub_payload


def _existing_cve_ids(tx: SqlSession, tenant: str, cve_ids: Sequence[str]) -> set[str]:
    found: set[str] = set()
    for start in range(0, len(cve_ids), 500):
        batch = cve_ids[start : start + 500]
        markers = ",".join("?" for _ in batch)
        rows = tx.execute(f"SELECT cve_id FROM hub_cve_intel WHERE tenant_id = ? AND cve_id IN ({markers})", (tenant, *batch)).fetchall()  # nosec B608
        found.update(str(row[0]) for row in rows)
    return found


def _locked_intel_rows(tx: SqlSession, dialect: Dialect, tenant: str, cve_ids: Sequence[str]) -> dict[str, tuple[dict[str, Any], bool]]:
    lock = " FOR UPDATE" if dialect == "postgres" else ""
    found: dict[str, tuple[dict[str, Any], bool]] = {}
    for start in range(0, len(cve_ids), 500):
        batch = cve_ids[start : start + 500]
        markers = ",".join("?" for _ in batch)
        rows = tx.execute(
            f"SELECT cve_id, payload, is_kev FROM hub_cve_intel WHERE tenant_id = ? AND cve_id IN ({markers}) ORDER BY cve_id{lock}",  # nosec B608
            (tenant, *batch),
        ).fetchall()
        found.update((str(row[0]), (decode_hub_payload(row[1]), bool(row[2]))) for row in rows)
    return found


def persist_cve_intel(tx: SqlSession, dialect: Dialect, tenant: str, payloads: Iterable[Mapping[str, Any]]) -> None:
    """Merge the CVE records a batch names into their rows, under row locks on Postgres.

    Every named CVE gets a row, so a finding's ``intel_ref`` always resolves and a
    catalog sync can reach it. Missing rows are inserted before anything is locked and
    both steps run in CVE order, so batches naming the same CVEs cannot deadlock. A lock
    wait is bounded by the session's ``lock_timeout``, and the error rolls the batch back.
    SQLite's write transaction already serializes this.
    """
    blobs: dict[str, list[dict[str, Any]]] = {}
    for payload in payloads:
        cve_id = resolve_cve_id(payload)
        if cve_id:
            blob = cve_intel_blob(payload)
            blobs.setdefault(cve_id, []).extend([blob] if blob else [])
    if not blobs:
        return
    value, encoded = _encoder(dialect)
    named = sorted(blobs)
    now = utc_timestamp()
    existing = _existing_cve_ids(tx, tenant, named)
    tx.executemany(
        f"INSERT INTO hub_cve_intel (tenant_id, cve_id, payload, updated_at, is_kev) VALUES (?, ?, {value}, ?, ?) "  # nosec B608
        "ON CONFLICT (tenant_id, cve_id) DO NOTHING",
        [(tenant, cve_id, encoded({}), now, False) for cve_id in named if cve_id not in existing],
    )
    carrying = [cve_id for cve_id in named if blobs[cve_id]]
    stored = _locked_intel_rows(tx, dialect, tenant, carrying)
    updates: list[tuple[Any, ...]] = []
    for cve_id, (current, column) in sorted(stored.items()):
        # The column survives a lost payload write, so it repairs the payload here.
        merged = {**current, "is_kev": True} if column else dict(current)
        for blob in blobs[cve_id]:
            merged = merge_cve_intel(merged, blob)
        kev = payload_is_kev(merged)
        if merged != current or kev != column:
            updates.append((encoded(merged), now, kev, tenant, cve_id))
    tx.executemany(f"UPDATE hub_cve_intel SET payload = {value}, updated_at = ?, is_kev = ? WHERE tenant_id = ? AND cve_id = ?", updates)  # nosec B608


def persist_batch_cve_intel(tx: SqlSession, dialect: Dialect, tenant: str, findings: Iterable[Any]) -> None:
    from agent_bom.api.hub_reference_store import HUB_REFERENCE_NORMALIZE

    if HUB_REFERENCE_NORMALIZE:
        persist_cve_intel(tx, dialect, tenant, [row for row in findings if isinstance(row, Mapping)])


def persist_references(
    tx: SqlSession, dialect: Dialect, tenant: str, payload: Mapping[str, Any], *, intel_persisted: bool = False
) -> dict[str, Any]:
    from agent_bom.api.hub_reference_store import HUB_REFERENCE_NORMALIZE

    if not HUB_REFERENCE_NORMALIZE:
        return dict(payload)
    slim, _intel, framework = extract_reference_blobs(payload)
    if not intel_persisted:
        persist_cve_intel(tx, dialect, tenant, [payload])
    value, encoded = _encoder(dialect)
    framework_ref = str(slim.get("framework_ref") or "")
    if framework and framework_ref:
        tx.execute(
            f"INSERT INTO hub_framework_refs (tenant_id, framework_ref, payload, updated_at) VALUES (?, ?, {value}, ?) "  # nosec B608
            "ON CONFLICT (tenant_id, framework_ref) DO UPDATE SET payload = excluded.payload, updated_at = excluded.updated_at",
            (tenant, framework_ref, encoded(framework), utc_timestamp()),
        )  # nosec B608
    return slim
