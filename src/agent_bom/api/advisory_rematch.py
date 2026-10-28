"""Bounded daily re-match of stored inventory against newly updated advisories.

Each tenant keeps two cursors in the operator advisory store: the feed cursor
(the ``(modified, id)`` keyset of the last feed record processed, so records
sharing a timestamp across a batch boundary are never skipped) and the operator
cursor (the run start, compared with operator advisory ``updated_at``). A run
matches only advisories updated after those cursors against the tenant's
newest stored scan per target. Hosts are never rescanned.

Past ``MAX_TENANTS_PER_RUN`` tenants are served oldest attempt first
(``last_attempt_at`` in each tenant's state; never-attempted tenants lead), so
every tenant is reached within ``ceil(N / cap)`` runs instead of the same
alphabetical tail being skipped forever.

Fail closed: when the feed or the store is unreachable, or a version cannot
be ordered, the run is recorded ``incomplete`` and neither cursor moves, so
the next run retries the same window instead of reporting it clean.

Findings carry ``first_seen`` (first run that produced them; repeats keep it)
and ``new_since_published`` (the matched scan completed before the advisory
was published, so a scan-time match could not have reported it).
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from agent_bom.api import health_models
from agent_bom.api.advisory_affected_read import persist_tenant_advisories
from agent_bom.api.finding_job_metadata import FindingHistoryJob
from agent_bom.api.findings_current import current_scan_jobs
from agent_bom.api.models import JobStatus
from agent_bom.api.scan_finding_read import _completed_jobs_for_tenant
from agent_bom.api.storage.finding_history import HistoryUnavailableError, metadata_for_job
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_operator_advisory_store, _get_store
from agent_bom.api.tenant_worker import run_tenant_bound
from agent_bom.core.settings import env_bool, env_int
from agent_bom.core.timestamps import parse_timestamp
from agent_bom.db import schema as _schema
from agent_bom.db.operator_advisories import distro_verdicts
from agent_bom.db.schema import open_existing_db_readonly
from agent_bom.scanners.operator_advisory import AffectedProduct, FeedAffectedRange, OperatorAdvisory, match_advisories_against_reports

try:
    from psycopg import Error as _PsycopgError
except ImportError:  # psycopg ships only with the Postgres extra
    _PsycopgError = OSError  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)

DEFAULT_INTERVAL_SECONDS = 86_400
MIN_INTERVAL_SECONDS = 300
MAX_TENANTS_PER_RUN = 500
# Job summaries read to discover tenants; past it, unseen tenants may exist.
MAX_JOBS_SCANNED = MAX_TENANTS_PER_RUN * 20
MAX_FEED_ADVISORIES = 2_000
MAX_SEEN_FINDINGS = 5_000
MAX_RECENT_FINDINGS = 200
FIRST_RUN_LOOKBACK = timedelta(days=7)
FEED_PROVENANCE = "feed"


class FeedUnavailableError(RuntimeError):
    """The advisory feed could not be read; the run must not be reported clean."""


# Store, job-store and feed failures that make a run incomplete rather than clean.
_UNAVAILABLE: tuple[type[BaseException], ...] = (OSError, sqlite3.Error, RuntimeError, ValueError, KeyError, TypeError, _PsycopgError)
_FEED_UNAVAILABLE: tuple[type[BaseException], ...] = (FeedUnavailableError, *_UNAVAILABLE)


@dataclass(frozen=True)
class FeedBatch:
    advisories: list[OperatorAdvisory]
    newest_modified: str | None
    # Id of the last record read at ``newest_modified``; the keyset tiebreaker.
    newest_id: str | None = None


class FeedSource(Protocol):
    def __call__(self, cursor: str | None, after_id: str | None = None) -> FeedBatch: ...


def rematch_enabled() -> bool:
    return env_bool("AGENT_BOM_ADVISORY_REMATCH", False, on_invalid="default")


def rematch_interval_seconds() -> int:
    return max(MIN_INTERVAL_SECONDS, env_int("AGENT_BOM_ADVISORY_REMATCH_INTERVAL_SECONDS", DEFAULT_INTERVAL_SECONDS, on_invalid="default"))


def feed_advisory(
    *,
    advisory_id: str,
    aliases: list[str],
    summary: str,
    severity: str,
    published: str | None,
    affected: list[tuple[str, str, str | None, str | None, str | None, str | None]],
) -> OperatorAdvisory:
    """Feed record in the matcher's shape; feed data is trusted as stored, not re-validated."""
    products = [
        AffectedProduct.model_construct(
            ecosystem=ecosystem,
            name=name,
            cpe_product=None,
            versions=[],
            ranges=[
                FeedAffectedRange.model_construct(
                    introduced=introduced or None, fixed=fixed or None, last_affected=last or None, limit_version=limit
                )
            ],
        )
        for ecosystem, name, introduced, fixed, last, limit in affected
    ]
    return OperatorAdvisory.model_construct(
        id=advisory_id,
        aliases=aliases,
        summary=summary or "No description available",
        severity=(severity or "unknown").lower(),
        published_at=_parse(published),
        references=[],
        affected=products,
    )


def local_feed_advisories_since(cursor: str | None, after_id: str | None = None) -> FeedBatch:
    """Feed advisories after the ``(cursor, after_id)`` keyset in the local vulnerability DB (bounded).

    Without ``after_id`` (a first run or a pre-keyset cursor) records at exactly
    ``cursor`` are re-read; repeats are deduplicated by the ``seen`` map.
    """
    db_path = _schema.DB_PATH
    if not db_path.exists():
        raise FeedUnavailableError("local vulnerability DB is not present")
    since = cursor or (datetime.now(timezone.utc) - FIRST_RUN_LOOKBACK).isoformat()
    try:
        conn = open_existing_db_readonly(db_path)
        try:
            keys = conn.execute(
                "SELECT id, modified FROM vulns WHERE modified > ? OR (modified = ? AND id > ?) ORDER BY modified, id LIMIT ?",
                (since, since, after_id or "", MAX_FEED_ADVISORIES),
            ).fetchall()
            batch = _feed_batch(conn, [row[0] for row in keys])
            if not keys:
                return batch
            return FeedBatch(batch.advisories, str(keys[-1][1]), str(keys[-1][0]))
        finally:
            conn.close()
    except sqlite3.Error as exc:
        raise FeedUnavailableError("local vulnerability DB could not be read") from exc


def _limit_projection(conn: sqlite3.Connection) -> str:
    """A DB built before range limits were stored has lost them: NULL makes the verdict indeterminate."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(affected)").fetchall()}
    return "a.limit_version" if "limit_version" in columns else "NULL"


def _feed_batch(conn: sqlite3.Connection, ids: list[str]) -> FeedBatch:
    if not ids:
        return FeedBatch([], None)
    marks = ",".join("?" * len(ids))
    rows = conn.execute(
        "SELECT v.id, v.summary, v.severity, v.aliases, v.published, v.modified, a.ecosystem, a.package_name, a.introduced, a.fixed, "
        f"a.last_affected, {_limit_projection(conn)} FROM vulns v JOIN affected a ON a.vuln_id = v.id "
        f"WHERE v.id IN ({marks})",  # nosec B608 - fixed projection and placeholders only
        ids,
    ).fetchall()
    grouped: dict[str, dict[str, Any]] = {}
    for vid, summary, severity, aliases, published, modified, eco, name, introduced, fixed, last, limit in rows:
        entry = grouped.setdefault(vid, {"row": (summary, severity, aliases, published), "modified": modified, "affected": []})
        entry["affected"].append((eco, name, introduced, fixed, last, limit))
    advisories = [
        feed_advisory(
            advisory_id=vid,
            aliases=[a for a in str(entry["row"][2] or "").split(",") if a],
            summary=entry["row"][0],
            severity=entry["row"][1],
            published=entry["row"][3],
            affected=entry["affected"],
        )
        for vid, entry in grouped.items()
    ]
    newest = max((str(entry["modified"]) for entry in grouped.values() if entry["modified"]), default=None)
    return FeedBatch(advisories, newest)


def _parse(value: Any) -> datetime | None:
    return parse_timestamp(str(value)) if value else None


def _selection_metadata(store: Any, tenant_id: str) -> list[FindingHistoryJob] | None:
    """Scope and authority of every completed job without its result, or ``None`` when only the full rows can say.

    SQL stores keep the projection (``finding_history_jobs``) when scan
    snapshots are enabled; the in-memory store derives it from its resident
    rows, which costs no decode. Anything else falls back to the full fold.
    """
    read = getattr(store, "finding_history_read", None)
    if callable(read):
        try:
            with read(tenant_id) as reader:
                return list(reader.jobs())
        except HistoryUnavailableError:
            return None
    if isinstance(store, InMemoryJobStore):
        return [metadata_for_job(job) for job in store.list_all(tenant_id=tenant_id) if job.status == JobStatus.DONE and job.result]
    return None


def _current_jobs(tenant_id: str) -> list[Any]:
    """The newest completed job per scope, decoding only those winners.

    A winner that is gone or no longer complete by the time it is read means
    the store changed under the run; the caller records the run incomplete and
    retries next time rather than matching a partial estate.
    """
    store = _get_store()
    metadata = _selection_metadata(store, tenant_id)
    if metadata is None:
        return current_scan_jobs(_completed_jobs_for_tenant(tenant_id), since=None, scan_id=None)
    jobs = []
    for selected in current_scan_jobs(metadata, since=None, scan_id=None):
        job = store.get(selected.job_id, tenant_id)
        if job is None or job.status != JobStatus.DONE or not isinstance(job.result, dict):
            raise RuntimeError("a stored scan changed while it was being re-matched")
        jobs.append(job)
    return jobs


def _stored_reports(tenant_id: str) -> list[dict[str, Any]]:
    reports = []
    for job in _current_jobs(tenant_id):
        result = dict(job.result or {})
        result.setdefault("scan_id", job.job_id)
        result["scan_completed_at"] = job.completed_at or job.created_at
        reports.append(result)
    return reports


def _all_declared(store: Any, tenant_id: str) -> list[OperatorAdvisory]:
    """Every declaration is re-persisted each run, so a rescan that no longer matches retires its findings."""
    return [OperatorAdvisory.model_validate({k: v for k, v in row.items() if k != "updated_at"}) for row in store.list(tenant_id)]


def _stamp(findings: list[dict[str, Any]], seen: dict[str, str], now: datetime) -> list[dict[str, Any]]:
    fresh = []
    for finding in findings:
        first_seen = seen.get(finding["id"])
        if first_seen is None:
            first_seen = seen[finding["id"]] = now.isoformat()
            fresh.append(finding)
        observed, published = _parse(finding.get("scan_observed_at")), _parse(finding.get("published_at"))
        finding["first_seen"] = first_seen
        finding["new_since_published"] = bool(observed and published and observed < published)
    return fresh


def _record(store: Any, tenant_id: str, state: dict[str, Any], status: dict[str, Any]) -> dict[str, Any]:
    state["last_run"] = status
    try:
        store.put_rematch_state(tenant_id, state)
    except _UNAVAILABLE:
        logger.warning("Advisory re-match could not persist state for one tenant")
        status = {**status, "status": "incomplete", "reason": "store_unavailable"}
    return status


def run_tenant_rematch(
    tenant_id: str, *, feed_source: FeedSource = local_feed_advisories_since, now: datetime | None = None
) -> dict[str, Any]:
    """Re-match one tenant's stored inventory against advisories updated since its cursors."""
    now = now or datetime.now(timezone.utc)
    store = _get_operator_advisory_store()
    status: dict[str, Any] = {"at": now.isoformat(), "status": "incomplete", "reason": None, "new_findings": 0}
    try:
        state = store.get_rematch_state(tenant_id) or {}
    except _UNAVAILABLE:
        return {**status, "reason": "store_unavailable"}
    state["last_attempt_at"] = now.isoformat()
    try:
        batch = feed_source(state.get("feed_cursor"), state.get("feed_cursor_id"))
    except _FEED_UNAVAILABLE:
        return _record(store, tenant_id, state, {**status, "reason": "feed_unavailable"})
    try:
        operator_cursor = _parse(state.get("operator_cursor"))
        declared = [
            row for row in store.list(tenant_id) if operator_cursor is None or (_parse(row.get("updated_at")) or now) > operator_cursor
        ]
        operator = [OperatorAdvisory.model_validate({k: v for k, v in row.items() if k != "updated_at"}) for row in declared]
        reports = _stored_reports(tenant_id)
    except _UNAVAILABLE:
        return _record(store, tenant_id, state, {**status, "reason": "store_unavailable"})
    with distro_verdicts() as verdict:
        results = [
            match_advisories_against_reports(operator, reports, distro_verdict=verdict),
            match_advisories_against_reports(batch.advisories, reports, provenance=FEED_PROVENANCE, distro_verdict=verdict),
        ]
        # A distro package awaiting its distro record stays indeterminate until the
        # distro feed updates; reporting it must not freeze the cursors forever.
        if any(result.blocking_indeterminate for result in results) and reports:
            return _record(store, tenant_id, state, {**status, "reason": "version_incomparable"})
        try:
            state["persisted_feed_ids"] = persist_tenant_advisories(
                tenant_id,
                _all_declared(store, tenant_id),
                batch.advisories,
                reports,
                distro_verdict=verdict,
                prior_feed_ids=list(state.get("persisted_feed_ids") or []),
                observed_at=now.isoformat(),
            )
        except _UNAVAILABLE:
            return _record(store, tenant_id, state, {**status, "reason": "finding_store_unavailable"})
    seen: dict[str, str] = dict(state.get("seen") or {})
    findings = [finding for result in results for finding in result.findings]
    fresh = _stamp(findings, seen, now)
    state["seen"] = dict(sorted(seen.items(), key=lambda item: item[1])[-MAX_SEEN_FINDINGS:])
    state["recent_findings"] = (fresh + list(state.get("recent_findings") or []))[:MAX_RECENT_FINDINGS]
    state["operator_cursor"] = now.isoformat()
    if batch.newest_modified:
        state["feed_cursor"], state["feed_cursor_id"] = batch.newest_modified, batch.newest_id
    complete = {
        **status,
        "status": "complete",
        "new_findings": len(fresh),
        "findings_total": len(findings),
        "reports_examined": len(reports),
        "indeterminate_distro": sum(len(result.indeterminate) - len(result.blocking_indeterminate) for result in results),
    }
    return _record(store, tenant_id, state, complete)


@dataclass(frozen=True)
class _TenantSelection:
    tenants: list[str]
    skipped: list[str]
    job_cap_reached: bool


def _rematch_tenants() -> _TenantSelection:
    """Tenants with stored scans, bounded; what the bounds left out is reported, never dropped silently."""
    rows = _get_store().list_summary(all_tenants=True, status=JobStatus.DONE, limit=MAX_JOBS_SCANNED + 1)
    job_cap_reached = len(rows) > MAX_JOBS_SCANNED
    tenants = sorted({str(row["tenant_id"]) for row in rows[:MAX_JOBS_SCANNED] if row.get("tenant_id")})
    if len(tenants) > MAX_TENANTS_PER_RUN:
        attempts = {tenant: run_tenant_bound(tenant, _last_attempt, tenant) for tenant in tenants}
        tenants.sort(key=lambda tenant: (attempts[tenant], tenant))
    return _TenantSelection(tenants[:MAX_TENANTS_PER_RUN], tenants[MAX_TENANTS_PER_RUN:], job_cap_reached)


_NEVER = datetime.min.replace(tzinfo=timezone.utc)


def _last_attempt(tenant_id: str) -> datetime:
    """When this tenant was last re-matched (any outcome); never or unreadable sorts first."""
    try:
        state = _get_operator_advisory_store().get_rematch_state(tenant_id) or {}
    except _UNAVAILABLE:
        return _NEVER
    return _parse(state.get("last_attempt_at")) or _NEVER


def _record_skipped(tenant_id: str, now: datetime) -> None:
    """Leave the skipped tenant's cursors alone; its listing says this run did not reach it."""
    store = _get_operator_advisory_store()
    try:
        state = store.get_rematch_state(tenant_id) or {}
    except _UNAVAILABLE:
        return
    _record(store, tenant_id, state, {"at": now.isoformat(), "status": "incomplete", "reason": "tenant_cap", "new_findings": 0})


def run_rematch_once(*, feed_source: FeedSource = local_feed_advisories_since, now: datetime | None = None) -> dict[str, Any]:
    """One bounded pass over tenants with stored scans; updates this replica's status."""
    now = now or datetime.now(timezone.utc)
    selection = _rematch_tenants()
    statuses = [run_tenant_bound(tenant, run_tenant_rematch, tenant, feed_source=feed_source, now=now) for tenant in selection.tenants]
    for tenant in selection.skipped:
        run_tenant_bound(tenant, _record_skipped, tenant, now)
    incomplete = sum(1 for status in statuses if status["status"] != "complete")
    truncated = bool(selection.skipped) or selection.job_cap_reached
    if truncated:
        logger.warning(
            "Advisory re-match reached its bounds: %d tenant(s) skipped, job cap reached: %s",
            len(selection.skipped),
            selection.job_cap_reached,
        )
    summary = {
        "last_run_at": now.isoformat(),
        "last_run_status": "incomplete" if incomplete or truncated else "complete",
        "tenants_examined": len(statuses),
        "incomplete_tenants": incomplete,
        "tenants_skipped": len(selection.skipped),
        "job_cap_reached": selection.job_cap_reached,
        "truncated": truncated,
        "new_findings": sum(int(status.get("new_findings") or 0) for status in statuses),
    }
    health_models.ADVISORY_REMATCH_LAST_RUN.clear()
    health_models.ADVISORY_REMATCH_LAST_RUN.update(summary)
    return {**summary, "status": summary["last_run_status"]}


def process_status() -> dict[str, Any]:
    """Tenant-free summary of this replica's last run, safe for the public health payload."""
    return health_models.advisory_rematch_health().model_dump()


def reset_process_status() -> None:
    health_models.ADVISORY_REMATCH_LAST_RUN.clear()


def start_advisory_rematch_task() -> asyncio.Task[None] | None:
    """Start the API-lifespan loop when enabled; default off."""
    if not rematch_enabled():
        return None
    logger.info("Advisory re-match scheduler enabled")
    return asyncio.create_task(advisory_rematch_loop())


async def advisory_rematch_loop(*, feed_source: FeedSource = local_feed_advisories_since) -> None:
    """API-lifespan loop; off unless ``AGENT_BOM_ADVISORY_REMATCH`` is set."""
    interval = rematch_interval_seconds()
    while True:
        try:
            summary = await asyncio.to_thread(run_rematch_once, feed_source=feed_source)
            logger.info("Advisory re-match %s across %d tenant(s)", summary["status"], summary["tenants_examined"])
        except asyncio.CancelledError:
            raise
        except Exception:  # broad-except: the loop must survive and report the failed run
            health_models.ADVISORY_REMATCH_LAST_RUN.update(
                {"last_run_at": datetime.now(timezone.utc).isoformat(), "last_run_status": "incomplete"}
            )
            logger.error("Advisory re-match run failed; cursors unchanged")
        await asyncio.sleep(interval)
