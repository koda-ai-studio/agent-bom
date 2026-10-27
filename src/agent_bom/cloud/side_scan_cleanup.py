"""Durable cleanup claims and ownership checks shared by provider adapters."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable

from agent_bom.security import sanitize_text

from .side_scan_lifecycle import (
    CleanupStatus,
    ExecutionStatus,
    SideScanExecutionRecord,
    SideScanStateConflictError,
    SideScanStateStore,
    SideScanTemporaryResource,
    TemporaryResourceStatus,
)
from .side_scan_targets import CloudSideScanTarget


class SideScanPermissionDeniedError(RuntimeError):
    """Provider denied a scoped lifecycle operation."""


class SideScanLifecycleTimeoutError(RuntimeError):
    """A provider operation did not finish inside the configured poll bound."""


class SideScanOwnershipError(RuntimeError):
    """A deterministic provider resource exists but is not owned by this run."""


@dataclass(frozen=True)
class _WaitPolicy:
    max_attempts: int
    interval_seconds: float
    sleep: Callable[[float], None]

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_wait_attempts must be at least 1")
        if self.interval_seconds < 0:
            raise ValueError("wait_interval_seconds cannot be negative")


class _PersistedLifecycleAdapter:
    provider: str

    def __init__(
        self,
        *,
        execution: SideScanExecutionRecord | None,
        state_store: SideScanStateStore,
        max_wait_attempts: int,
        wait_interval_seconds: float,
        sleep: Callable[[float], None],
    ) -> None:
        if execution is None:
            raise ValueError("persisted side-scan execution is required")
        if execution.provider != self.provider:
            raise ValueError("side-scan execution provider does not match adapter")
        self.execution = execution
        self._store = state_store
        self._wait_policy = _WaitPolicy(max_wait_attempts, wait_interval_seconds, sleep)
        self.last_operation: Any | None = None
        self.owner_instance_id = ""
        self.owner_instance_name = ""

    def _validate_target(self, target: CloudSideScanTarget) -> None:
        if (
            target.provider != self.execution.provider
            or target.account_id != self.execution.account_id
            or target.target_id != self.execution.target_id
        ):
            raise ValueError("side-scan target is outside the persisted execution scope")

    def _save(self, record: SideScanExecutionRecord) -> None:
        if record == self.execution:
            return
        self._store.save(record, expected_version=self.execution.state_version)
        self.execution = record

    def _ensure_running(self, phase: str) -> None:
        if self.execution.status is ExecutionStatus.QUEUED:
            self._save(self.execution.transition(status=ExecutionStatus.RUNNING, phase=phase))
        elif self.execution.status is ExecutionStatus.RUNNING:
            self._save(self.execution.transition(phase=phase))
        else:
            raise ValueError(f"side-scan execution is not runnable: {self.execution.status.value}")

    def _begin_mutation(self) -> None:
        """Persist uncertainty before dispatch, including provider success with failed readback."""
        if "provider_mutation_unreconciled" in self.execution.warning_codes:
            raise SideScanStateConflictError("previous provider mutation requires reconciliation")
        self._save(
            self.execution.transition(
                cleanup_status=CleanupStatus.PENDING,
                warning_codes=(*self.execution.warning_codes, "provider_mutation_unreconciled"),
            )
        )

    def _register(self, kind: str, resource_id: str) -> None:
        resource = SideScanTemporaryResource(
            kind=kind,
            resource_id=resource_id,
            status=TemporaryResourceStatus.CREATED,
            ownership_tags=self.execution.cleanup_ownership.required_tags(),
        )
        self._save(self.execution.register_resource(resource))
        if "provider_mutation_unreconciled" in self.execution.warning_codes:
            self._save(
                self.execution.transition(
                    warning_codes=tuple(code for code in self.execution.warning_codes if code != "provider_mutation_unreconciled")
                )
            )

    def _wait(self, operation: Any) -> Any:
        self.last_operation = operation
        done = getattr(operation, "done", None)
        result = getattr(operation, "result", None)
        if not callable(done) or not callable(result):
            raise TypeError("provider operation must expose done() and result()")
        for attempt in range(self._wait_policy.max_attempts):
            if done():
                return result()
            if attempt + 1 < self._wait_policy.max_attempts:
                self._wait_policy.sleep(self._wait_policy.interval_seconds)
        raise SideScanLifecycleTimeoutError("provider operation exceeded bounded wait")

    def _persist_failure(self, exc: Exception) -> None:
        denied = _is_denied(exc)
        cleanup = (
            CleanupStatus.PENDING
            if isinstance(exc, SideScanLifecycleTimeoutError)
            or self.execution.resources
            or "provider_mutation_unreconciled" in self.execution.warning_codes
            else CleanupStatus.COMPLETE
        )
        status = ExecutionStatus.DENIED if denied else ExecutionStatus.FAILED
        if denied:
            code = "permission_denied"
        elif isinstance(exc, SideScanLifecycleTimeoutError):
            code = "operation_timeout"
        else:
            code = "provider_operation_failed"
        self._save(
            self.execution.transition(
                status=status,
                phase="cleanup" if cleanup is CleanupStatus.PENDING else "finished",
                cleanup_status=cleanup,
                failure_code=code,
            )
        )

    def _raise_provider_error(self, exc: Exception) -> None:
        self._persist_failure(exc)
        if _is_denied(exc):
            raise SideScanPermissionDeniedError("provider denied the scoped side-scan lifecycle operation") from exc
        if isinstance(exc, SideScanLifecycleTimeoutError):
            raise exc
        raise RuntimeError("provider side-scan lifecycle operation failed") from exc

    def mark_scan_complete(
        self,
        *,
        package_count: int = 0,
        vulnerability_count: int = 0,
        secret_count: int = 0,
        config_finding_count: int = 0,
        ioc_finding_count: int = 0,
    ) -> SideScanExecutionRecord:
        """Persist metadata-only scan counts and queue mandatory cleanup."""
        self._save(
            self.execution.transition(
                status=ExecutionStatus.SCAN_COMPLETE,
                phase="cleanup",
                cleanup_status=CleanupStatus.PENDING,
                package_count=package_count,
                vulnerability_count=vulnerability_count,
                secret_count=secret_count,
                config_finding_count=config_finding_count,
                ioc_finding_count=ioc_finding_count,
            )
        )
        return self.execution

    def mark_scan_failed(self, *, failure_code: str = "scan_failed") -> SideScanExecutionRecord:
        """Persist a fail-closed scan outcome before mandatory cleanup."""
        if self.execution.status in {ExecutionStatus.QUEUED, ExecutionStatus.RUNNING}:
            self._save(
                self.execution.transition(
                    status=ExecutionStatus.FAILED,
                    phase="cleanup",
                    cleanup_status=CleanupStatus.PENDING,
                    failure_code=failure_code,
                )
            )
        return self.execution

    def mark_collector_cleanup_failed(self) -> None:
        """Carry the local failure into the next atomic durable cleanup transition."""
        if "collector_unmount_failed" not in self.execution.warning_codes:
            self.execution = replace(self.execution, warning_codes=(*self.execution.warning_codes, "collector_unmount_failed"))

    def cleanup(self, target: CloudSideScanTarget, collector_id: str) -> SideScanExecutionRecord:
        """Retry teardown from persisted resources; every step is idempotent."""
        self._validate_target(target)
        if collector_id != self.execution.collector_id:
            raise SideScanOwnershipError("cleanup collector differs from the execution")
        if self.execution.cleanup_status is CleanupStatus.COMPLETE:
            return self.execution
        if (
            self.execution.status in {ExecutionStatus.QUEUED, ExecutionStatus.RUNNING}
            or self.execution.cleanup_status is CleanupStatus.IN_PROGRESS
        ):
            raise SideScanStateConflictError("cleanup cannot take over an active or uncertain execution")
        if self.execution.failure_code == "operation_timeout" or "provider_mutation_unreconciled" in self.execution.warning_codes:
            raise SideScanStateConflictError("timed-out provider operations require reconciliation before cleanup")
        self._save(self.execution.transition(phase="cleanup", cleanup_status=CleanupStatus.IN_PROGRESS))
        warning_codes = list(self.execution.warning_codes)
        if "collector_unmount_failed" in warning_codes:
            # Keep every owned dependency: no provider-wide assumption that a
            # snapshot is safe to delete while its clone remains mounted.
            self._save(self.execution.transition(cleanup_status=CleanupStatus.PARTIAL))
            return self.execution
        order = {"attachment": 0, "scan_disk": 1, "snapshot": 2}
        resources = sorted(self.execution.cleanup_candidates(), key=lambda resource: order.get(resource.kind, 99))
        for resource in resources:
            try:
                if resource.kind == "attachment":
                    scan_disk_id = resource.resource_id.split("|", 1)[-1]
                    self.detach_scan_disk(target, scan_disk_id, collector_id)
                elif resource.kind == "scan_disk":
                    self.delete_scan_disk(target, resource.resource_id)
                elif resource.kind == "snapshot":
                    self.delete_snapshot(target, resource.resource_id)
                else:
                    raise ValueError(f"unknown temporary resource kind: {resource.kind}")
            except Exception as exc:  # noqa: BLE001 - cleanup continues and persists a safe code
                if _is_not_found(exc):
                    self._save(
                        self.execution.mark_resource_cleanup(
                            resource.resource_id,
                            status=TemporaryResourceStatus.DELETED,
                        )
                    )
                    continue
                code = f"cleanup_{resource.kind}_failed"
                if code not in warning_codes:
                    warning_codes.append(code)
                self._save(
                    self.execution.mark_resource_cleanup(
                        resource.resource_id,
                        status=TemporaryResourceStatus.CLEANUP_FAILED,
                    )
                )
                break
            self._save(
                self.execution.mark_resource_cleanup(
                    resource.resource_id,
                    status=TemporaryResourceStatus.DELETED,
                )
            )
        if self.execution.cleanup_candidates():
            self._save(
                self.execution.transition(
                    cleanup_status=CleanupStatus.PARTIAL,
                    warning_codes=tuple(warning_codes),
                )
            )
        else:
            self._save(
                self.execution.transition(
                    phase="finished",
                    cleanup_status=CleanupStatus.COMPLETE,
                    warning_codes=tuple(warning_codes),
                )
            )
        return self.execution

    def _require_registered(self, target: CloudSideScanTarget, resource_id: str, kind: str) -> None:
        """Tags alone never authorize mutation of an arbitrary provider object."""
        self._validate_target(target)
        if resource_id == target.target_id or not any(
            resource.kind == kind and resource.resource_id == resource_id for resource in self.execution.cleanup_candidates()
        ):
            raise SideScanOwnershipError("cleanup resource is not owned by this execution ledger")

    def sweep_orphans(self, *, active_execution_ids: set[str]) -> list[str]:
        """Retry only this adapter's recorded terminal execution; never enumerate provider resources."""
        record = self._store.get(tenant_id=self.execution.tenant_id, execution_id=self.execution.execution_id)
        if (
            record is None
            or record.execution_id in active_execution_ids
            or record.state_version != self.execution.state_version
            or record.status in {ExecutionStatus.QUEUED, ExecutionStatus.RUNNING}
            or record.cleanup_status not in {CleanupStatus.PENDING, CleanupStatus.PARTIAL}
            or record.failure_code == "operation_timeout"
            or "provider_mutation_unreconciled" in record.warning_codes
            or not record.cleanup_candidates()
        ):
            return []
        target = CloudSideScanTarget(
            provider=record.provider,
            target_type="managed_disk" if record.provider == "azure" else "persistent_disk",
            target_id=record.target_id,
            name=record.target_id.rsplit("/", 1)[-1],
            account_id=record.account_id,
            location=getattr(self, "_collector_zone", ""),
            size_gb=None,
            encryption="unknown",
        )
        pending = {resource.resource_id for resource in record.cleanup_candidates() if resource.kind != "attachment"}
        try:
            result = self.cleanup(target, record.collector_id)
        except SideScanStateConflictError:
            return []
        return [
            resource.resource_id.rsplit("/", 1)[-1]
            for resource in result.resources
            if resource.resource_id in pending and resource.status is TemporaryResourceStatus.DELETED
        ]

    def detach_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str, collector_id: str) -> None:
        raise NotImplementedError

    def delete_scan_disk(self, target: CloudSideScanTarget, scan_disk_id: str) -> None:
        raise NotImplementedError

    def delete_snapshot(self, target: CloudSideScanTarget, snapshot_id: str) -> None:
        raise NotImplementedError


def _status_code(exc: Exception) -> int | None:
    raw = getattr(exc, "status_code", None)
    if isinstance(raw, int):
        return raw
    code = getattr(exc, "code", None)
    if callable(code):
        code = code()
    if isinstance(code, int):
        return code
    value = getattr(code, "value", None)
    return int(value) if isinstance(value, int) else None


def _is_denied(exc: Exception) -> bool:
    return _status_code(exc) in {401, 403}


def _is_not_found(exc: Exception) -> bool:
    return _status_code(exc) == 404


def _is_conflict(exc: Exception) -> bool:
    return _status_code(exc) in {409, 412}


def sanitized_provider_error(exc: Exception) -> str:
    """Expose a sanitized diagnostic for logs without changing state codes."""
    return sanitize_text(exc)
