"""An in-memory job store that reports committed row versions, like PostgreSQL.

Runs the current-findings fold through per-version digests without a database.
A version is the job's serialized content, so any change to a stored job, even
an in-place edit of a retained object, is a new version.
"""

from __future__ import annotations

import hashlib

from agent_bom.api.models import JobStatus
from agent_bom.api.store import InMemoryJobStore


def _version(job) -> str:
    return hashlib.sha256(job.model_dump_json().encode()).hexdigest()


class VersionedInMemoryJobStore(InMemoryJobStore):
    def __init__(self) -> None:
        super().__init__()
        self.loaded: list[list[str]] = []

    def _tenant_jobs(self, tenant_id: str):
        # Not list_all: tests count the fold's full-history reads through it.
        with self._lock:
            return [job for (tenant, _), job in self._jobs.items() if tenant == tenant_id]

    def done_job_versions(self, tenant_id: str) -> list[tuple[str, str]]:
        jobs = [job for job in self._tenant_jobs(tenant_id) if job.status == JobStatus.DONE]
        return [(job.job_id, _version(job)) for job in sorted(jobs, key=lambda job: str(job.created_at), reverse=True)]

    def jobs_with_versions(self, tenant_id: str, job_ids: list[str]):
        self.loaded.append(list(job_ids))
        wanted = set(job_ids)
        return [(_version(job), job.model_copy(deep=True)) for job in self._tenant_jobs(tenant_id) if job.job_id in wanted]
