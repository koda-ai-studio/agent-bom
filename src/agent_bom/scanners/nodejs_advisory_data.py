"""The Node.js security working group core vulnerability index, live or as a dated snapshot.

Source: ``vuln/core/index.json`` in github.com/nodejs/security-wg (MIT), the
Node.js project's own record of Node.js core vulnerabilities. Each entry lists
CVE ids, the ``vulnerable`` and ``patched`` npm ranges, a severity and the
affected platforms. The index stops listing a release line once it reaches
end-of-life, so each copy also carries the end-of-life date of every line from
the Node.js Release working group's ``schedule.json`` (dates only).

Three copies can answer a scan, freshest first:

- ``live``: fetched for the scan when it is online (bounded size and timeout);
- ``synced_snapshot``: written next to the local vulnerability DB by
  ``agent-bom db update`` (source ``nodejs``), so air-gapped hosts that copy
  the DB directory carry it;
- ``bundled_snapshot``: shipped in the package and refreshed by
  ``scripts/refresh_nodejs_core_advisories.py``.

A snapshot older than the local DB staleness threshold
(``AGENT_BOM_DB_STALE_DAYS``, 14 days by default) is not used, so stale or
missing data leaves the runtime not assessed rather than clean.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

from agent_bom import http_client
from agent_bom.core.settings import env_opt
from agent_bom.db import schema
from agent_bom.http_client import fetch_bytes
from agent_bom.scanners.nodejs_semver import parse_range
from agent_bom.security import SecurityError
from agent_bom.vuln_freshness import db_stale_days_threshold

INDEX_URL = "https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json"
REPOSITORY = "https://github.com/nodejs/security-wg"
SCHEDULE_URL = "https://raw.githubusercontent.com/nodejs/Release/main/schedule.json"
SOURCE_ID = "nodejs-security-wg"
SNAPSHOT_FILENAME = "nodejs_core_vulns.json"
SCHEMA_VERSION = 1
MAX_INDEX_BYTES = 4_000_000
MAX_SCHEDULE_BYTES = 262_144
MAX_ENTRIES = 5_000
FETCH_TIMEOUT_SECONDS = 20.0

LIVE_FAILURES = (ValueError, OSError, httpx.HTTPError, http_client.OfflineModeError, SecurityError)

_ENTRY_ID = re.compile(r"[0-9]{1,6}")
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,7}")
_SCHEDULE_LINE = re.compile(r"v(0\.[0-9]{1,3}|[1-9][0-9]{0,3})")
_LINE = re.compile(r"0\.[0-9]{1,3}|[1-9][0-9]{0,3}")
_ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "unknown", "none"})


@dataclass(frozen=True)
class CoreIndex:
    entries: dict[str, dict[str, Any]]
    end_of_life: dict[str, str]
    fetched_at: datetime
    sha256: str
    origin: str


def _now() -> datetime:
    return datetime.now(timezone.utc)


def sidecar_dir() -> Path:
    """Where air-gap sidecar feeds live: ``AGENT_BOM_VULN_DB_BUNDLE_DIR``, else beside the DB file."""
    explicit = env_opt("AGENT_BOM_VULN_DB_BUNDLE_DIR")
    return Path(explicit).expanduser() if explicit else schema.DB_PATH.parent


def synced_snapshot_path() -> Path:
    return sidecar_dir() / SNAPSHOT_FILENAME


def bundled_snapshot_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / SNAPSHOT_FILENAME


def _string_list(value: Any, field: str, key: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Entry {key}: {field} is not a list of strings")
    return value


def validate_entries(entries: Any) -> dict[str, dict[str, Any]]:
    """Every entry must be fully understood; one unreadable entry rejects the whole index."""
    if not isinstance(entries, dict) or not entries or len(entries) > MAX_ENTRIES:
        raise ValueError("Node.js core index is empty, oversized or not an object")
    for key, entry in entries.items():
        if not _ENTRY_ID.fullmatch(str(key)) or not isinstance(entry, dict):
            raise ValueError(f"Malformed Node.js core index entry {key!r}")
        if not all(_CVE.fullmatch(cve) for cve in _string_list(entry.get("cve"), "cve", key)):
            raise ValueError(f"Entry {key}: malformed CVE id")
        if not _string_list(entry.get("affectedEnvironments"), "affectedEnvironments", key):
            raise ValueError(f"Entry {key}: no affected environments")
        for field in ("vulnerable", "patched"):
            if not isinstance(entry.get(field), str):
                raise ValueError(f"Entry {key}: {field} is not a string")
            parse_range(entry[field])
        if not entry["vulnerable"].strip():
            raise ValueError(f"Entry {key}: empty vulnerable range")
        if str(entry.get("severity", "unknown")).strip().lower() not in _SEVERITIES:
            raise ValueError(f"Entry {key}: unknown severity label")
    return entries


def parse_index(raw: bytes) -> dict[str, dict[str, Any]]:
    try:
        entries = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Node.js core index is not valid JSON") from exc
    return validate_entries(entries)


def validate_end_of_life(value: Any) -> dict[str, str]:
    """``{release line: ISO end date}``, such as ``{"18": "2025-04-30", "0.10": "2016-10-31"}``."""
    if not isinstance(value, dict) or not value:
        raise ValueError("Node.js release schedule is empty")
    for line, end in value.items():
        if not _LINE.fullmatch(str(line)) or not isinstance(end, str) or not _ISO_DATE.fullmatch(end):
            raise ValueError("Malformed Node.js release schedule entry")
        datetime.strptime(end, "%Y-%m-%d")
    return value


def parse_schedule(raw: bytes) -> dict[str, str]:
    """End-of-life date per release line from the Release working group's ``schedule.json``."""
    try:
        schedule = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Node.js release schedule is not valid JSON") from exc
    if not isinstance(schedule, dict):
        raise ValueError("Node.js release schedule is not an object")
    end_of_life: dict[str, str] = {}
    for key, line in schedule.items():
        match = _SCHEDULE_LINE.fullmatch(str(key))
        if match is None or not isinstance(line, dict) or not isinstance(line.get("end"), str):
            raise ValueError("Malformed Node.js release schedule entry")
        end_of_life[match[1]] = line["end"]
    return validate_end_of_life(end_of_life)


def snapshot_payload(raw: bytes, schedule_raw: bytes, *, fetched_at: datetime) -> dict[str, Any]:
    entries = parse_index(raw)
    return {
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE_ID,
        "source_url": INDEX_URL,
        "schedule_url": SCHEDULE_URL,
        "repository_url": REPOSITORY,
        "license": "MIT",
        "fetched_at": fetched_at.astimezone(timezone.utc).isoformat(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "entry_count": len(entries),
        "end_of_life": parse_schedule(schedule_raw),
        "entries": entries,
    }


def load_snapshot(path: Path, *, origin: str) -> CoreIndex:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Node.js core advisory snapshot unreadable ({origin})") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != SCHEMA_VERSION or payload.get("source_url") != INDEX_URL:
        raise ValueError(f"Node.js core advisory snapshot has an unknown format ({origin})")
    entries = validate_entries(payload.get("entries"))
    end_of_life = validate_end_of_life(payload.get("end_of_life"))
    if payload.get("entry_count") != len(entries):
        raise ValueError(f"Node.js core advisory snapshot is incomplete ({origin})")
    try:
        fetched_at = datetime.fromisoformat(str(payload.get("fetched_at")))
    except ValueError as exc:
        raise ValueError(f"Node.js core advisory snapshot has no valid date ({origin})") from exc
    if fetched_at.tzinfo is None or not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("sha256", ""))):
        raise ValueError(f"Node.js core advisory snapshot lacks provenance ({origin})")
    return CoreIndex(entries=entries, end_of_life=end_of_life, fetched_at=fetched_at, sha256=payload["sha256"], origin=origin)


def _fetch_raw() -> tuple[bytes, bytes]:
    http_client.check_offline()
    raw = fetch_bytes(INDEX_URL, timeout=FETCH_TIMEOUT_SECONDS, max_bytes=MAX_INDEX_BYTES)
    return raw, fetch_bytes(SCHEDULE_URL, timeout=FETCH_TIMEOUT_SECONDS, max_bytes=MAX_SCHEDULE_BYTES)


def fetch_index() -> CoreIndex:
    raw, schedule_raw = _fetch_raw()
    return CoreIndex(
        entries=parse_index(raw),
        end_of_life=parse_schedule(schedule_raw),
        fetched_at=_now(),
        sha256=hashlib.sha256(raw).hexdigest(),
        origin="live",
    )


def sync_snapshot(path: Path | None = None) -> int:
    """Fetch, validate and atomically replace the snapshot; a failure keeps the previous one."""
    target = path or synced_snapshot_path()
    raw, schedule_raw = _fetch_raw()
    payload = snapshot_payload(raw, schedule_raw, fetched_at=_now())
    target.parent.mkdir(parents=True, exist_ok=True)
    handle, temp = tempfile.mkstemp(prefix=".nodejs-core-", suffix=".json", dir=target.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=1, sort_keys=True)
            stream.write("\n")
        os.replace(temp, target)
    finally:
        Path(temp).unlink(missing_ok=True)  # no-op once replaced
    return int(payload["entry_count"])


def max_snapshot_age() -> timedelta:
    return timedelta(days=db_stale_days_threshold())


def select_index(*, offline: bool) -> CoreIndex:
    """The live index when reachable, else the freshest snapshot within the staleness threshold.

    Raises ``ValueError`` with a reason safe to show when nothing usable exists.
    """
    if not offline:
        try:
            return fetch_index()
        except LIVE_FAILURES:
            pass  # fall back to a dated snapshot; the caller records a gap if none is fresh
    snapshots: list[CoreIndex] = []
    for path, origin in ((synced_snapshot_path(), "synced_snapshot"), (bundled_snapshot_path(), "bundled_snapshot")):
        if path.is_file():
            try:
                snapshots.append(load_snapshot(path, origin=origin))
            except ValueError:
                continue
    if not snapshots:
        raise ValueError("no Node.js core advisory snapshot is available")
    freshest = max(snapshots, key=lambda snapshot: snapshot.fetched_at)
    if _now() - freshest.fetched_at > max_snapshot_age():
        raise ValueError(
            f"the newest Node.js core advisory snapshot is from {freshest.fetched_at.date().isoformat()}, "
            f"older than {max_snapshot_age().days} days"
        )
    return freshest
