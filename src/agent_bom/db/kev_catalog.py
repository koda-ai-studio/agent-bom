"""Read a CISA KEV catalog the control plane may treat as authoritative.

The catalog can clear a tenant's KEV flag, so a missing, stale, empty, truncated or
unverifiable one is never used: callers get ``None`` and keep the flags they have.
Nothing here touches the network. It reads what ``agent-bom db update`` and the scan
path's KEV join have already downloaded.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NamedTuple

from agent_bom.db.schema import DB_PATH, open_existing_db_readonly
from agent_bom.storage import state_home

_logger = logging.getLogger(__name__)

MAX_CATALOG_AGE = timedelta(days=7)
# The catalog has only grown since 2021 and held 1,768 entries on 2026-11-04.
MIN_TRUSTED_ENTRIES = 1000
# A complete-looking feed this much smaller than the last one is held back for review.
MAX_SHRINK_RATIO = 0.9
_MAX_CACHE_BYTES = 32 * 1024 * 1024
_CLOCK_SKEW = timedelta(minutes=5)


class KevEntry(NamedTuple):
    date_added: str
    due_date: str


@dataclass(frozen=True)
class KevCatalog:
    entries: Mapping[str, KevEntry]
    synced_at: datetime
    version: str
    source: str


def feed_metadata(data: Mapping[str, Any], entry_count: int) -> dict[str, Any]:
    """Describe a downloaded feed; ``complete`` means its declared count was all delivered."""
    declared = data.get("count")
    complete = isinstance(declared, int) and not isinstance(declared, bool) and declared == entry_count and entry_count > 0
    return {
        "complete": complete,
        "catalog_version": str(data.get("catalogVersion") or ""),
        "date_released": str(data.get("dateReleased") or ""),
    }


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _trusted(entries: dict[str, KevEntry], synced_at: datetime | None, metadata: Any, source: str, now: datetime) -> KevCatalog | None:
    if not isinstance(metadata, dict) or metadata.get("complete") is not True or synced_at is None:
        return None
    if len(entries) < MIN_TRUSTED_ENTRIES or not (now - MAX_CATALOG_AGE <= synced_at <= now + _CLOCK_SKEW):
        return None
    return KevCatalog(entries, synced_at, str(metadata.get("catalog_version") or ""), source)


def _from_vuln_db(path: Path, now: datetime) -> KevCatalog | None:
    if not path.exists():
        return None
    conn = open_existing_db_readonly(path)
    try:
        meta = conn.execute("SELECT last_synced, record_count, metadata_json FROM sync_meta WHERE source = 'kev'").fetchone()
        if meta is None:
            return None
        rows = conn.execute("SELECT cve_id, date_added, due_date FROM kev_entries").fetchall()
    finally:
        conn.close()
    entries = {str(row[0]).upper(): KevEntry(str(row[1] or ""), str(row[2] or "")) for row in rows if row[0]}
    if len(entries) != meta[1]:
        return None
    return _trusted(entries, _parse_time(meta[0]), json.loads(meta[2] or "{}"), "vuln_db", now)


def _from_scan_cache(path: Path, now: datetime) -> KevCatalog | None:
    if not path.exists() or path.stat().st_size > _MAX_CACHE_BYTES:
        return None
    raw = json.loads(path.read_text(encoding="utf-8"))
    data = raw.get("data") if isinstance(raw, dict) else None
    if not isinstance(data, dict):
        return None
    entries = {
        str(cve).upper(): KevEntry(str(item.get("date_added") or ""), str(item.get("due_date") or ""))
        for cve, item in data.items()
        if isinstance(item, dict)
    }
    cached_at = raw.get("_cached_at")
    synced_at = datetime.fromtimestamp(cached_at, tz=timezone.utc) if isinstance(cached_at, (int, float)) else None
    return _trusted(entries, synced_at, raw.get("catalog"), "scan_cache", now)


def scan_cache_path() -> Path:
    return state_home.state_dir() / "kev_cache.json"


def load_trusted_kev_catalog(
    *, db_path: Path | None = None, cache_path: Path | None = None, now: datetime | None = None
) -> KevCatalog | None:
    """The freshest catalog that passes every check, or ``None`` to keep existing flags."""
    moment = now or datetime.now(timezone.utc)
    found: list[KevCatalog] = []
    for reader, path in ((_from_vuln_db, db_path or DB_PATH), (_from_scan_cache, cache_path or scan_cache_path())):
        try:
            catalog = reader(path, moment)
        except (OSError, sqlite3.Error, ValueError, TypeError, KeyError, OverflowError) as exc:
            _logger.debug("KEV catalog source unreadable: %s", type(exc).__name__)
            continue
        if catalog is not None:
            found.append(catalog)
    return max(found, key=lambda catalog: catalog.synced_at, default=None)
