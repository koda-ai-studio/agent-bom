"""Reading a job row through a brief store outage."""

from __future__ import annotations

import logging
import time
from typing import Any

from agent_bom.api.models import ScanJob
from agent_bom.security import sanitize_error, sanitize_text

_logger = logging.getLogger(__name__)

READ_RETRY_DELAYS = (0.2, 1.0)


def read_job_riding_out_blips(store: Any, job: ScanJob) -> ScanJob | None:
    """Past a brief retry the error propagates: the report is good, so its job must stay retryable."""
    for delay in READ_RETRY_DELAYS:
        try:
            return store.get(job.job_id, tenant_id=job.tenant_id)
        except Exception as exc:  # broad-except: a store error of any kind says nothing about the report being read
            _logger.warning("Could not read job=%s: %s", job.job_id, sanitize_text(sanitize_error(exc, generic=True)))
            time.sleep(delay)
    return store.get(job.job_id, tenant_id=job.tenant_id)
