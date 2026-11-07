"""Bounded OSV lookups of the CVEs that unrated distro advisories link to.

OSV has no batch endpoint that returns severity (``/v1/querybatch`` returns ids
only), so each distinct CVE costs one ``GET /v1/vulns/{id}``. The work is deduped
across findings, cached on disk, and limited by batch, concurrency, request and
wall-clock budgets. A failure is never cached as an answer: the CVE is reported
as unanswered and the caller keeps ``unknown``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import tempfile
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from agent_bom.core.errors import UpstreamError, UpstreamInvalidResponseError, UpstreamRateLimitedError
from agent_bom.http_client import OfflineModeError, create_client, is_offline, request_with_retry
from agent_bom.scanners.osv_details import OSV_API_URL
from agent_bom.scanners.risk import osv_severity_basis
from agent_bom.scanners.upstream import upstream_request
from agent_bom.storage import state_home
from agent_bom.vuln_freshness import offline_env

_logger = logging.getLogger(__name__)

BATCH_SIZE = 50
CONCURRENCY = 10
MAX_LOOKUPS = 1000
DEADLINE_SECONDS = 90.0

CACHE_FILENAME = "linked_cve_severity_cache.json"
RATED_TTL_SECONDS = 7 * 86400
UNRATED_TTL_SECONDS = 86400
_CACHE_VERSION = 1
_MAX_CACHE_ENTRIES = 20000
_MAX_CACHE_BYTES = 32 * 1024 * 1024

_CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")
_DISTRO_CVE_ID = re.compile(r"^(?:DEBIAN|UBUNTU|ALPINE)-CVE-\d{4}-\d{4,}$")

GAP_OFFLINE = "offline"
GAP_RATE_LIMITED = "rate_limited"
GAP_BUDGET = "budget"
GAP_FAILED = "failed"

RequestFn = Callable[..., Awaitable[Any]]


@dataclass(frozen=True)
class LinkedCveQuery:
    """One CVE to rate, with the distro-scoped record to read first when there is one."""

    cve_id: str
    scoped_id: str | None = None

    @property
    def cache_key(self) -> str:
        return self.scoped_id or self.cve_id


@dataclass(frozen=True)
class LinkedCveRecord:
    """What OSV says about one CVE. ``tracker`` is set only from a ``DEBIAN-CVE`` record."""

    cve_id: str
    label: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    tracker: Mapping[tuple[str, str], str] | None = None

    @property
    def rated(self) -> bool:
        return self.label is not None or self.cvss_score is not None


@dataclass
class LinkedCveLookup:
    records: dict[str, LinkedCveRecord] = field(default_factory=dict)
    unanswered: set[str] = field(default_factory=set)
    gap_reason: str | None = None
    requests: int = 0
    cache_hits: int = 0


def valid_cve_id(value: str) -> bool:
    return bool(_CVE_ID.fullmatch(value))


def valid_distro_cve_id(value: str) -> bool:
    return bool(_DISTRO_CVE_ID.fullmatch(value))


def _tracker_entries(record: dict) -> dict[tuple[str, str], str]:
    """Map ``(source package, OSV ecosystem)`` to its fixed version, ``""`` when still open."""
    entries: dict[tuple[str, str], str] = {}
    for affected in record.get("affected") or []:
        package = affected.get("package") if isinstance(affected, dict) else None
        if not isinstance(package, dict):
            continue
        name, ecosystem = package.get("name"), package.get("ecosystem")
        if not isinstance(name, str) or not isinstance(ecosystem, str):
            continue
        fixed = ""
        for version_range in affected.get("ranges") or []:
            for event in version_range.get("events") or [] if isinstance(version_range, dict) else []:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    fixed = event["fixed"]
        entries[(name, ecosystem)] = fixed
    return entries


def _parse_record(query: LinkedCveQuery, scoped: dict | None, cve: dict | None) -> LinkedCveRecord:
    label: str | None = None
    score: float | None = None
    vector: str | None = None
    for body in (scoped, cve):
        if not body:
            continue
        basis = osv_severity_basis(body, advisory_id_fallback=False)
        if basis.cvss_score is not None:
            score, vector, label = basis.cvss_score, basis.cvss_vector, basis.severity.value
            break
        if label is None and basis.severity_source is not None:
            label = basis.severity.value
    tracker = _tracker_entries(scoped) if scoped and (query.scoped_id or "").startswith("DEBIAN-") else None
    return LinkedCveRecord(query.cve_id, label, score, vector, tracker)


async def _get_record(client: Any, vuln_id: str, request_fn: RequestFn) -> dict | None:
    """Return the OSV record, or ``None`` when OSV has none (an answer); failures raise."""
    response = await upstream_request("osv", request_fn, client, "GET", f"{OSV_API_URL}/vulns/{vuln_id}", ok_statuses=frozenset({200, 404}))
    if response.status_code == 404:
        return None
    try:
        body = response.json()
    except ValueError as exc:
        raise UpstreamInvalidResponseError("osv", "advisory detail is not JSON") from exc
    if not isinstance(body, dict):
        raise UpstreamInvalidResponseError("osv", "advisory detail is not a JSON object")
    return body


@dataclass
class _Run:
    client: Any
    request_fn: RequestFn
    result: LinkedCveLookup
    semaphore: asyncio.Semaphore
    fresh: dict[str, LinkedCveRecord] = field(default_factory=dict)
    rate_limited: bool = False

    def spend(self) -> bool:
        if self.result.requests >= MAX_LOOKUPS:
            return False
        self.result.requests += 1
        return True


async def _lookup_one(run: _Run, query: LinkedCveQuery) -> None:
    async with run.semaphore:
        try:
            scoped = None
            if query.scoped_id:
                if not run.spend():
                    return
                scoped = await _get_record(run.client, query.scoped_id, run.request_fn)
            cve = None
            if not (scoped and osv_severity_basis(scoped, advisory_id_fallback=False).cvss_score is not None):
                if not run.spend():
                    return
                cve = await _get_record(run.client, query.cve_id, run.request_fn)
        except UpstreamRateLimitedError:
            run.rate_limited = True
            return
        except UpstreamError as failure:
            _logger.debug("Linked CVE lookup failed: %s", failure.detail)
            return
        record = _parse_record(query, scoped, cve)
        run.result.records[query.cve_id] = record
        run.result.unanswered.discard(query.cve_id)
        run.fresh[query.cache_key] = record


async def _run_batches(run: _Run, pending: list[LinkedCveQuery]) -> str | None:
    """Fetch batch by batch; return why it stopped early, or ``None`` when it finished."""
    deadline = time.monotonic() + DEADLINE_SECONDS
    for start in range(0, len(pending), BATCH_SIZE):
        batch = pending[start : start + BATCH_SIZE]
        remaining = deadline - time.monotonic()
        if remaining <= 0 or run.result.requests >= MAX_LOOKUPS:
            return GAP_BUDGET
        answered_before = len(run.fresh)
        tasks = [asyncio.ensure_future(_lookup_one(run, query)) for query in batch]
        try:
            await asyncio.wait_for(asyncio.gather(*tasks), timeout=remaining)
        except asyncio.TimeoutError:
            return GAP_BUDGET
        if run.rate_limited:
            return GAP_RATE_LIMITED
        if len(run.fresh) == answered_before:
            return GAP_BUDGET if run.result.requests >= MAX_LOOKUPS else GAP_FAILED
    if not run.result.unanswered:
        return None
    return GAP_BUDGET if run.result.requests >= MAX_LOOKUPS else GAP_FAILED


def _cache_path() -> Path:
    return state_home.state_dir() / CACHE_FILENAME


def _record_from_cache(cve_id: str, entry: Any, now: float) -> tuple[LinkedCveRecord, float] | None:
    """Parse one cache entry, or ``None`` when it is malformed or expired."""
    if not isinstance(entry, dict):
        return None
    fetched_at = entry.get("fetched_at")
    label, score, vector = entry.get("label"), entry.get("cvss_score"), entry.get("cvss_vector")
    tracker = entry.get("tracker")
    if not isinstance(fetched_at, (int, float)) or isinstance(fetched_at, bool):
        return None
    if label is not None and not isinstance(label, str):
        return None
    if score is not None and (isinstance(score, bool) or not isinstance(score, (int, float)) or not 0 <= score <= 10):
        return None
    if vector is not None and not isinstance(vector, str):
        return None
    parsed_tracker: dict[tuple[str, str], str] | None = None
    if tracker is not None:
        if not isinstance(tracker, list) or not all(
            isinstance(row, list) and len(row) == 3 and all(isinstance(item, str) for item in row) for row in tracker
        ):
            return None
        parsed_tracker = {(row[0], row[1]): row[2] for row in tracker}
    record = LinkedCveRecord(cve_id, label, float(score) if score is not None else None, vector, parsed_tracker)
    ttl = RATED_TTL_SECONDS if record.rated else UNRATED_TTL_SECONDS
    return (record, float(fetched_at)) if 0 <= now - fetched_at < ttl else None


def _load_cache() -> dict[str, Any]:
    path = _cache_path()
    try:
        if path.stat().st_size > _MAX_CACHE_BYTES:
            return {}
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(payload, dict) or payload.get("version") != _CACHE_VERSION or not isinstance(payload.get("entries"), dict):
        return {}
    return payload["entries"]


def _save_cache(entries: dict[str, Any], fresh: Mapping[str, LinkedCveRecord], now: float) -> None:
    """Temp file plus rename, so a concurrent scan reads a whole file; the last writer wins."""
    if not fresh:
        return
    for key, record in fresh.items():
        entries[key] = {
            "fetched_at": now,
            "label": record.label,
            "cvss_score": record.cvss_score,
            "cvss_vector": record.cvss_vector,
            "tracker": [[name, ecosystem, fixed] for (name, ecosystem), fixed in record.tracker.items()]
            if record.tracker is not None
            else None,
        }
    newest = sorted(entries.items(), key=lambda item: _entry_age_key(item[1]), reverse=True)[:_MAX_CACHE_ENTRIES]
    path = _cache_path()
    tmp_path: str | None = None
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump({"version": _CACHE_VERSION, "entries": dict(newest)}, handle)
        os.replace(tmp_path, path)
        tmp_path = None
    except OSError as exc:
        _logger.debug("Linked CVE cache not written: %s", type(exc).__name__)
    finally:
        if tmp_path is not None:
            try:
                os.unlink(tmp_path)
            except OSError as exc:
                _logger.debug("Linked CVE cache temp file not removed: %s", type(exc).__name__)


def _entry_age_key(entry: Any) -> float:
    fetched_at = entry.get("fetched_at") if isinstance(entry, dict) else None
    return float(fetched_at) if isinstance(fetched_at, (int, float)) and not isinstance(fetched_at, bool) else 0.0


def _split_cached(
    queries: Iterable[LinkedCveQuery], entries: Mapping[str, Any], now: float, result: LinkedCveLookup
) -> list[LinkedCveQuery]:
    pending: list[LinkedCveQuery] = []
    for query in queries:
        cached = _record_from_cache(query.cve_id, entries.get(query.cache_key), now)
        if cached is None:
            pending.append(query)
        else:
            result.records[query.cve_id] = cached[0]
            result.cache_hits += 1
    return pending


async def lookup_linked_cves(
    queries: list[LinkedCveQuery],
    *,
    offline: bool,
    request_fn: RequestFn = request_with_retry,
) -> LinkedCveLookup:
    """Answer ``queries`` from the cache, then OSV within budget, in the order given."""
    result = LinkedCveLookup()
    if not queries:
        return result
    now = time.time()
    entries = await asyncio.to_thread(_load_cache)
    pending = _split_cached(queries, entries, now, result)
    if not pending:
        return result
    result.unanswered = {query.cve_id for query in pending}
    if offline or is_offline() or offline_env():
        result.gap_reason = GAP_OFFLINE
        return result
    run: _Run | None = None
    try:
        async with create_client(timeout=20.0) as client:
            run = _Run(client, request_fn, result, asyncio.Semaphore(CONCURRENCY))
            result.gap_reason = await _run_batches(run, pending)
    except OfflineModeError:
        result.gap_reason = GAP_OFFLINE
    except (httpx.HTTPError, OSError) as exc:
        _logger.debug("Linked CVE lookup stopped: %s", type(exc).__name__)
        result.gap_reason = GAP_FAILED
    if run is not None:
        await asyncio.to_thread(_save_cache, entries, run.fresh, now)
    return result
