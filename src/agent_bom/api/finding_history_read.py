"""Opt-in current findings with projected retained history and safe fallback."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any

from agent_bom.api.storage.finding_history import HistoryUnavailableError
from agent_bom.api.storage.jobs import get_job
from agent_bom.core.settings import env_flag

_logger = logging.getLogger(__name__)


def current_findings_with_history(
    store: Any,
    tenant_id: str,
    since: str | None,
    scan_id: str | None,
    iter_findings: Callable[[Any], list[dict[str, Any]]],
    legacy: Callable[[], list[dict[str, Any]]],
    *,
    fold: Callable[..., list[dict[str, Any]]],
    select_jobs: Callable[..., tuple[list[Any], Any]],
) -> list[dict[str, Any]]:
    """Hydrate selected reports only; fall back for missing/old projections.

    Qualification compares complete folds, including dates and reconfirmation.
    Both modes remain opt-in. Unsupported stores keep their existing behavior.
    """
    qualify = env_flag("AGENT_BOM_SCAN_SNAPSHOT_READS")
    fast = env_flag("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS")
    read = getattr(store, "finding_history_read", None)
    if not (qualify or fast) or not callable(read):
        return legacy()
    expected = legacy() if qualify else None
    try:
        with read(tenant_id) as reader:
            revision = reader.revision()
            jobs = reader.jobs()
            selected = {}
            # Share canonical selection without running the findings fold or
            # enriching while holding a pool connection.
            metadata_jobs, _ = select_jobs(jobs, since=since, scan_id=scan_id)
            for metadata in metadata_jobs:
                job = get_job(reader.session, reader.dialect, metadata.job_id, tenant_id)
                if job is None:
                    raise HistoryUnavailableError("selected retained job is missing")
                selected[job.job_id] = job
        rows = {job_id: iter_findings(job) for job_id, job in selected.items()}
        with read(tenant_id) as reader:
            if reader.revision() != revision:
                raise HistoryUnavailableError("retained jobs changed during enrichment")
            reader.require_complete()
            candidate = fold(
                jobs,
                since=since,
                scan_id=scan_id,
                iter_findings=lambda metadata: rows[metadata.job_id],
                history_lookup=lambda wanted, authoritative: reader.history(jobs, wanted, authoritative),
            )
        if not qualify:
            return candidate
        if json.dumps(candidate, sort_keys=True, allow_nan=False) == json.dumps(expected, sort_keys=True, allow_nan=False):
            _logger.debug("finding_history_read outcome=match")
            return candidate
        _logger.warning("finding_history_read outcome=mismatch; using retained jobs")
    except HistoryUnavailableError:
        _logger.debug("finding_history_read outcome=incomplete; using retained jobs")
    except Exception:  # broad-except: optional derived data; authoritative fallback exceptions propagate below
        _logger.warning("finding_history_read outcome=unavailable; using retained jobs")
    return expected if expected is not None else legacy()
