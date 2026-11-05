"""A job store with no durable table folds retained scans with the same rules."""

from __future__ import annotations

from typing import Any

from agent_bom.api.finding_lifecycle_fold import FindingState, replay_lifecycle
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from tests.api.test_finding_durable_lifecycle import ACCOUNT, INSTANCE, _cloud_finding, _inventory
from tests.api.test_finding_lifecycle_sequences import VULN, T, _finding, _scope_for


def _job(job_id: str, at: str, rows: list[dict[str, Any]], project: str | None = "project-a", **extra: Any) -> ScanJob:
    result: dict[str, Any] = {
        "pushed": True,
        "generated_at": at,
        "findings": rows,
        "agents": [],
        "scan_run": {"outcome": "complete"},
        **extra,
    }
    if project:
        result["target_scope"] = _scope_for(project)
    return ScanJob(
        job_id=job_id,
        tenant_id="tenant-a",
        source_id="ci",
        status=JobStatus.DONE,
        created_at=at,
        completed_at=at,
        request=ScanRequest(),
        result=result,
    )


def _states(*jobs: ScanJob) -> list[FindingState]:
    return replay_lifecycle(list(jobs), lambda job: [])


def test_reopen_after_patch_keeps_first_seen_and_earlier_fix() -> None:
    row = _finding("host", *VULN)
    states = _states(_job("a", T[1], [row]), _job("b", T[2], []), _job("c", T[3], [row]))
    assert len(states) == 1
    state = states[0]
    assert state.status == "reopened"
    assert state.first_seen.startswith("2026-10-01")
    assert state.resolved_at and state.resolved_at.startswith("2026-10-02")
    assert state.reopened_at and state.reopened_at.startswith("2026-10-03")


def test_two_projects_stay_two_findings() -> None:
    row = _finding("host", *VULN)
    states = _states(_job("a", T[1], [row], project="project-a"), _job("b", T[1], [row], project="project-b"))
    assert len({state.canonical_id for state in states}) == 2


def test_asset_deleted_needs_a_complete_inventory() -> None:
    finding = _cloud_finding(INSTANCE)
    kept = _states(
        _job("a", T[1], [finding], cloud_inventory=_inventory(instances=(INSTANCE,))),
        _job("b", T[2], [], cloud_inventory=_inventory(permissions=("s3:ListAllMyBuckets",))),
    )
    assert kept[0].status == "open"
    gone = _states(
        _job("a", T[1], [finding], cloud_inventory=_inventory(instances=(INSTANCE,))), _job("b", T[2], [], cloud_inventory=_inventory())
    )
    assert gone[0].status == "resolved"
    assert gone[0].resolution_reason == "asset_deleted"
    assert ACCOUNT in INSTANCE


def test_memory_store_read_does_not_project_every_retained_scan(monkeypatch) -> None:
    """A report with no finding stream folds through collection once per job, never the enriched projection."""
    from agent_bom.api import scan_finding_read, stores
    from agent_bom.api.store import InMemoryJobStore

    def calls_with(retained: int) -> int:
        store = InMemoryJobStore()
        monkeypatch.setattr(stores, "_store", store)
        blast = {"vulnerability_id": VULN[0], "package": "urllib3@1.26.4", "severity": "high", "canonical_id": "occurrence-1"}
        for index in range(retained):
            job = _job(f"job-{index}", f"2026-10-{1 + index % 27:02d}T{index % 24:02d}:00:00+00:00", [], blast_radius=[blast])
            store.put(job)
        calls: list[str] = []
        original = scan_finding_read._iter_scan_findings
        monkeypatch.setattr(scan_finding_read, "_iter_scan_findings", lambda item: calls.append(item.job_id) or original(item))
        rows = scan_finding_read.current_scan_rows_with_lifecycle("tenant-a", None, None)
        monkeypatch.setattr(scan_finding_read, "_iter_scan_findings", original)
        assert len(rows) == 1
        return len(calls)

    assert calls_with(2) == calls_with(40)
