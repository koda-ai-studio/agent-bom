"""Persistence contract every scan job store implements."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

from agent_bom.config import API_JOB_TTL_SECONDS as _JOB_TTL_SECONDS

if TYPE_CHECKING:
    from agent_bom.api.models import JobStatus, ScanJob


class JobStore(Protocol):
    """Protocol for scan job persistence."""

    def put(self, job: ScanJob) -> None:
        """Create or replace a scan job."""

    def put_many_atomic(self, jobs: list[ScanJob]) -> None:
        """Create or replace several jobs in one transaction."""

    def put_many_if_absent_atomic(self, jobs: list[ScanJob]) -> list[str]:
        """Insert the jobs that do not exist yet in one transaction; return the ids inserted."""

    def get(self, job_id: str, tenant_id: str | None = None, *, all_tenants: bool = False) -> ScanJob | None:
        """Return one job, if any."""

    def get_status_view(self, job_id: str, tenant_id: str | None = None) -> dict[str, Any] | None:
        """Read progress without loading the result; concrete stores must implement this projection."""
        raise NotImplementedError

    def delete(self, job_id: str, tenant_id: str | None = None, *, all_tenants: bool = False) -> bool:
        """Delete one job; return whether it existed."""

    def list_all(self, tenant_id: str | None = None, *, all_tenants: bool = False) -> list[ScanJob]:
        """Return every job in scope."""

    def list_summary(
        self,
        tenant_id: str | None = None,
        *,
        all_tenants: bool = False,
        limit: int | None = None,
        offset: int = 0,
        query: str | None = None,
        status: JobStatus | None = None,
    ) -> list[dict]:
        """Return one page of job summary rows, newest first."""

    def count_summary(
        self,
        tenant_id: str | None = None,
        *,
        query: str | None = None,
        status: JobStatus | None = None,
    ) -> int:
        """Count the jobs ``list_summary`` would return without paging."""

    def count_summary_by_status(
        self,
        tenant_id: str | None = None,
        *,
        query: str | None = None,
    ) -> dict[str, int]:
        """Count matching jobs per status."""

    def count_active(
        self,
        tenant_id: str | None = None,
        *,
        all_tenants: bool = False,
    ) -> int:
        """Count pending and running jobs."""

    def cleanup_expired(self, ttl_seconds: int = _JOB_TTL_SECONDS) -> int:
        """Delete finished jobs older than ``ttl_seconds``; return the count removed."""
