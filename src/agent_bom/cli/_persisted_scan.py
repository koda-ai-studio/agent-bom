"""Read and write the local control-plane job store the CLI persists scans into."""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any

from agent_bom.api.store import SQLiteJobStore
from agent_bom.cli._tenant import resolve_cli_tenant_id
from agent_bom.core.settings import env_raw
from agent_bom.history import latest_report
from agent_bom.security import sanitize_error, sanitize_text
from agent_bom.storage import state_home

_logger = logging.getLogger(__name__)
_RECENT_JOBS = 20


def open_local_job_store(database: Path) -> SQLiteJobStore:
    """The SQLite job store at ``database`` (the one ``serve --persist`` and the dashboard read)."""
    return SQLiteJobStore(str(database))


def local_control_plane_db() -> Path | None:
    """The SQLite control plane this CLI writes (``AGENT_BOM_DB`` or the state dir default), when it is a local file."""
    raw = (env_raw("AGENT_BOM_DB") or "").strip()
    if raw == ":memory:" or "://" in raw:
        return None
    path = Path(raw).expanduser() if raw else state_home.state_path("control-plane.db")
    return path if path.is_file() else None


def latest_persisted_scan_report() -> dict[str, Any] | None:
    """The result of the newest completed scan job for the CLI tenant, or None when there is none."""
    database = local_control_plane_db()
    if database is None:
        return None
    try:
        tenant = resolve_cli_tenant_id()
        store = open_local_job_store(database)
        for summary in store.list_summary(tenant, limit=_RECENT_JOBS):
            if summary.get("status") != "done":
                continue
            job = store.get(str(summary["job_id"]), tenant_id=tenant)
            if job is not None and isinstance(job.result, dict) and job.result.get("agents"):
                return job.result
    except (sqlite3.Error, OSError, ValueError) as exc:
        _logger.warning("Could not read the last persisted scan: %s", sanitize_text(sanitize_error(exc)))
    return None


def fallback_scan_reports(explicit_reports: tuple[Path, ...] | list[Path]) -> list[dict[str, Any]] | None:
    """The last persisted scan, when no report was named and no saved history report exists."""
    if explicit_reports or latest_report() is not None:
        return None
    persisted = latest_persisted_scan_report()
    return [persisted] if persisted is not None else None


__all__ = ["fallback_scan_reports", "latest_persisted_scan_report", "local_control_plane_db", "open_local_job_store"]
