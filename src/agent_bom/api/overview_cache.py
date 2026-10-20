"""Bounded tenant overview caches and single-flight state."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from agent_bom.api.finding_suppression import suppression_revision
from agent_bom.core.settings import env_raw

_OVERVIEW_CACHE_TTL_SECONDS_DEFAULT = 15.0


_overview_cache: dict[str, tuple[float, str, dict[str, Any]]] = {}


_overview_cache_lock = threading.Lock()


_SCAN_AGGREGATE_MAX_BYTES = 256 * 1024


_SCAN_AGGREGATE_MAX_ENTRIES = 32


_SCAN_AGGREGATE_TTL = 300.0


_scan_aggregate_cache: dict[str, tuple[float, dict[str, Any], int]] = {}


def _scan_aggregate_get(key: str) -> dict[str, Any] | None:
    with _overview_cache_lock:
        entry = _scan_aggregate_cache.get(key)
        if entry is None or time.monotonic() >= entry[0]:
            _scan_aggregate_cache.pop(key, None)
            return None
        return entry[1]


def _scan_aggregate_put(key: str, value: dict[str, Any], jobs: list[Any]) -> None:
    from agent_bom.api.time_window import default_window_days

    size = len(json.dumps(value, separators=(",", ":")).encode())
    if size > _SCAN_AGGREGATE_MAX_BYTES:
        return
    ttl = _SCAN_AGGREGATE_TTL
    days = default_window_days()
    if days:
        now = datetime.now(timezone.utc)
        for job in jobs:
            try:
                stamp = datetime.fromisoformat(str(job.completed_at or job.created_at).replace("Z", "+00:00"))
                if stamp.tzinfo is None:
                    stamp = stamp.replace(tzinfo=timezone.utc)
                remaining = (stamp + timedelta(days=days) - now).total_seconds()
                if remaining > 0:
                    ttl = min(ttl, remaining)
            except (ValueError, TypeError, AttributeError):
                continue
    with _overview_cache_lock:
        now_mono = time.monotonic()
        for old_key, entry in list(_scan_aggregate_cache.items()):
            if entry[0] <= now_mono:
                del _scan_aggregate_cache[old_key]
        while _scan_aggregate_cache and (
            len(_scan_aggregate_cache) >= _SCAN_AGGREGATE_MAX_ENTRIES
            or sum(entry[2] for entry in _scan_aggregate_cache.values()) + size > _SCAN_AGGREGATE_MAX_BYTES
        ):
            del _scan_aggregate_cache[next(iter(_scan_aggregate_cache))]
        _scan_aggregate_cache[key] = (now_mono + ttl, value, size)


_OVERVIEW_SINGLEFLIGHT_TIMEOUT_SECONDS = 30.0


@dataclass
class _OverviewFlight:
    fingerprint: str
    event: threading.Event = field(default_factory=threading.Event)
    payload: dict[str, Any] | None = None


_overview_inflight: dict[str, _OverviewFlight] = {}


def _overview_cache_ttl() -> float:
    raw = env_raw("AGENT_BOM_OVERVIEW_CACHE_TTL_SECONDS")
    if raw is None:
        return _OVERVIEW_CACHE_TTL_SECONDS_DEFAULT
    try:
        return max(0.0, float(raw))
    except ValueError:
        return _OVERVIEW_CACHE_TTL_SECONDS_DEFAULT


def _overview_fingerprint(
    tenant_id: str,
    jobs: list[Any],
    hub_severity: dict[str, int],
    hub_failing_frameworks: set[str] | None = None,
    hub_evidence_version: int = 0,
) -> str:
    """Cheap change-detector over job metadata + hub current-state — no fold.

    Captures job identity, status and the freshest per-job timestamp so a new
    scan, a status transition, or a re-run all change the fingerprint. It also
    folds in the hub severity histogram (a cheap indexed GROUP BY) so findings
    ingested via ``POST /v1/findings/bulk`` — which never touch a scan job —
    still invalidate the cache. Neither input pays the O(estate) rollup cost, so
    the headline can never go stale relative to the reconciled spine. The
    tenant's suppression revision covers approvals and revokes, which change
    counts without touching a job or the hub.
    """
    parts = []
    for job in jobs:
        stamp = getattr(job, "completed_at", None) or getattr(job, "updated_at", None) or getattr(job, "created_at", None) or ""
        status = getattr(job, "status", "")
        raw_result = getattr(job, "result", None)
        result: dict[str, Any] = raw_result if isinstance(raw_result, dict) else {}
        raw_scan_run = result.get("scan_run")
        scan_run: dict[str, Any] = raw_scan_run if isinstance(raw_scan_run, dict) else {}
        evidence_identity = result.get("scan_id") or scan_run.get("scan_id") or getattr(job, "job_id", "")
        evidence_version = (
            result.get("generated_at") or result.get("scan_timestamp") or scan_run.get("generated_at") or result.get("schema_version") or ""
        )
        parts.append(
            f"{tenant_id}|{getattr(job, 'tenant_id', tenant_id)}|{getattr(job, 'job_id', '')}|"
            f"{getattr(status, 'value', status)}|{stamp}|{evidence_identity}|{evidence_version}"
        )
    parts.sort()
    hub_part = "|".join(f"{k}={int(hub_severity.get(k, 0) or 0)}" for k in sorted(hub_severity))
    framework_part = "|".join(sorted(hub_failing_frameworks or set())) + "\x1d" + suppression_revision(tenant_id)
    digest = hashlib.sha256(
        (tenant_id + "\x1f" + "\x1e".join(parts) + "\x1d" + hub_part + "\x1d" + framework_part + "\x1d" + str(hub_evidence_version)).encode(
            "utf-8"
        )
    ).hexdigest()
    return f"{len(jobs)}:{digest}"


def _overview_cache_get(tenant_id: str, fingerprint: str) -> dict[str, Any] | None:
    ttl = _overview_cache_ttl()
    if ttl <= 0:
        return None
    now = time.monotonic()
    with _overview_cache_lock:
        entry = _overview_cache.get(tenant_id)
        if entry is None:
            return None
        cached_at, cached_fp, payload = entry
        if cached_fp != fingerprint or (now - cached_at) > ttl:
            return None
        return payload


def _overview_cache_put(tenant_id: str, fingerprint: str, payload: dict[str, Any]) -> None:
    if _overview_cache_ttl() <= 0:
        return
    with _overview_cache_lock:
        _overview_cache[tenant_id] = (time.monotonic(), fingerprint, payload)


def _reset_overview_cache() -> None:
    """Test hook: drop all cached overview payloads and the shared posture-count blocks."""
    from agent_bom.api.posture_counts_cache import clear_posture_counts_cache

    clear_posture_counts_cache()
    with _overview_cache_lock:
        _overview_cache.clear()
        _scan_aggregate_cache.clear()
        for flight in _overview_inflight.values():
            flight.event.set()
        _overview_inflight.clear()


def _overview_singleflight_timeout() -> float:
    raw = env_raw("AGENT_BOM_OVERVIEW_SINGLEFLIGHT_TIMEOUT_SECONDS")
    if raw is None:
        return _OVERVIEW_SINGLEFLIGHT_TIMEOUT_SECONDS
    try:
        return max(0.0, float(raw))
    except ValueError:
        return _OVERVIEW_SINGLEFLIGHT_TIMEOUT_SECONDS
