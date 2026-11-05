"""Bounded repair of tenant CVE records, and their sync with a trusted KEV catalog.

Everything here is a keyset walk that commits per batch, so it resumes from wherever
it stopped and is safe to rerun. Postgres skips rows a writer holds; that writer
reconciles the row itself, and the next pass sees what it left.

Each row is read and written under its own ``tenant_id``, and the catalog only
adjusts rows a tenant already has. It adds no CVE to a tenant and copies nothing
between tenants.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, NamedTuple

from agent_bom.api.hub_payload_codec import decode_hub_payload
from agent_bom.api.hub_reference_payload import payload_is_kev
from agent_bom.api.storage.finding_payloads import _encoder
from agent_bom.api.storage.sql import Dialect, SqlSession, utc_timestamp
from agent_bom.db.kev_catalog import KevCatalog

Cursor = tuple[str, str]
START: Cursor = ("", "")
_KEV_CLAIM_KEYS = ("cisa_kev", "kev_date", "kev_added_date", "kev_due_date")


class IntelPage(NamedTuple):
    next_after: Cursor | None
    seen: int
    changed: int
    tenants: frozenset[str]


def _claim_is_older_than(updated_at: Any, catalog: KevCatalog) -> bool:
    """A claim newer than the catalog may be a listing this copy has not seen yet."""
    try:
        stamp = datetime.fromisoformat(str(updated_at).replace("Z", "+00:00"))
    except ValueError:
        return False
    return (stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)) < catalog.synced_at


def reconcile_row(
    cve_id: str, payload: dict[str, Any], column: bool, updated_at: Any, catalog: KevCatalog | None
) -> tuple[dict[str, Any], bool]:
    """The agreed payload and column for one row.

    Without a catalog, either side claiming KEV wins: hiding a known-exploited CVE
    is the unsafe failure. A trusted catalog then decides both ways.
    """
    merged = dict(payload)
    claimed = column or payload_is_kev(payload)
    kev = claimed
    entry = catalog.entries.get(cve_id) if catalog else None
    if entry is not None:
        kev = True
        merged.update({key: value for key, value in (("kev_added_date", entry.date_added), ("kev_due_date", entry.due_date)) if value})
    elif catalog is not None and claimed and _claim_is_older_than(updated_at, catalog):
        kev = False
    if kev:
        merged["is_kev"] = True
    elif claimed:
        for key in _KEV_CLAIM_KEYS:
            merged.pop(key, None)
        merged["is_kev"] = False
    return merged, kev


def reconcile_intel_batch(
    tx: SqlSession,
    dialect: Dialect,
    *,
    after: Cursor,
    limit: int,
    catalog: KevCatalog | None,
    bump_revision: Callable[[SqlSession, str], None],
) -> IntelPage:
    lock = " FOR UPDATE SKIP LOCKED" if dialect == "postgres" else ""
    rows = tx.execute(
        "SELECT tenant_id, cve_id, payload, is_kev, updated_at FROM hub_cve_intel "  # nosec B608
        f"WHERE (tenant_id, cve_id) > (?, ?) ORDER BY tenant_id, cve_id LIMIT ?{lock}",
        (*after, int(limit)),
    ).fetchall()
    value, encoded = _encoder(dialect)
    now = utc_timestamp()
    updates: list[tuple[Any, ...]] = []
    tenants: set[str] = set()
    for tenant, cve_id, raw, column, updated_at in rows:
        current = decode_hub_payload(raw)
        merged, kev = reconcile_row(str(cve_id), current, bool(column), updated_at, catalog)
        if merged != current or kev != bool(column):
            updates.append((encoded(merged), now, kev, tenant, cve_id))
            tenants.add(str(tenant))
    tx.executemany(f"UPDATE hub_cve_intel SET payload = {value}, updated_at = ?, is_kev = ? WHERE tenant_id = ? AND cve_id = ?", updates)  # nosec B608
    for tenant in sorted(tenants):
        # Cached counts read the column these rows just changed.
        bump_revision(tx, tenant)
    # A short page can still have skipped rows, so only an empty one ends the walk.
    next_after = (str(rows[-1][0]), str(rows[-1][1])) if rows else None
    return IntelPage(next_after, len(rows), len(updates), frozenset(tenants))


def link_cve_rows_batch(tx: SqlSession, dialect: Dialect, *, after: Cursor, limit: int) -> tuple[Cursor | None, int]:
    """Give every CVE a tenant's current findings reference a record to link to."""
    refs = tx.execute(
        "SELECT DISTINCT tenant_id, intel_ref FROM hub_findings_current "
        "WHERE intel_ref <> '' AND (tenant_id, intel_ref) > (?, ?) ORDER BY tenant_id, intel_ref LIMIT ?",
        (*after, int(limit)),
    ).fetchall()
    value, encoded = _encoder(dialect)
    now = utc_timestamp()
    tx.executemany(
        f"INSERT INTO hub_cve_intel (tenant_id, cve_id, payload, updated_at, is_kev) VALUES (?, ?, {value}, ?, ?) "  # nosec B608
        "ON CONFLICT (tenant_id, cve_id) DO NOTHING",
        [(row[0], row[1], encoded({}), now, False) for row in refs],
    )
    return ((str(refs[-1][0]), str(refs[-1][1])) if refs else None), len(refs)


def mark_unlinked_rows_pending(tx: SqlSession, *, after: Cursor, limit: int) -> tuple[Cursor | None, int]:
    """Send rows with no CVE link back through the materialization backfill.

    SQL cannot tell a CVE row from a policy row while payloads are compressed, so
    every blank row is recomputed. Postgres only; SQLite does this in one upgrade step.
    """
    rows = tx.execute(
        "UPDATE hub_findings_current SET issue_group_id = NULL WHERE (tenant_id, canonical_id) IN ("
        "SELECT tenant_id, canonical_id FROM hub_findings_current "
        "WHERE (tenant_id, canonical_id) > (?, ?) AND intel_ref = '' AND issue_group_id IS NOT NULL "
        "ORDER BY tenant_id, canonical_id LIMIT ? FOR UPDATE SKIP LOCKED) RETURNING tenant_id, canonical_id",
        (*after, int(limit)),
    ).fetchall()
    if not rows:
        return None, 0
    return max((str(row[0]), str(row[1])) for row in rows), len(rows)
