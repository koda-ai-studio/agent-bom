"""Cleanup requires durable ownership and fresh provider evidence, never tags alone."""

from dataclasses import replace

import pytest

from agent_bom.cloud.side_scan_lifecycle import CleanupStatus, ExecutionStatus, SideScanStateConflictError
from agent_bom.cloud.side_scan_provider_adapters import SideScanOwnershipError
from tests.cloud.test_side_scan_provider_adapters import FakeSdkError, _azure_adapter, _gcp_adapter, _target


@pytest.fixture(params=["azure", "gcp"])
def lifecycle(request, tmp_path):
    provider = request.param
    adapter, store, snapshots, disks, collector = (_azure_adapter if provider == "azure" else _gcp_adapter)(tmp_path)
    target = _target(provider)
    snapshot_id = adapter.create_snapshot(target)
    disk_id = adapter.create_scan_disk(target, snapshot_id)
    adapter.attach_scan_disk(target, disk_id, "collector-1")
    return adapter, store, snapshots, disks, collector, target, snapshot_id, disk_id


def test_sweep_never_reaps_a_running_execution_even_when_caller_omits_it(lifecycle):
    adapter, _, snapshots, disks, _, _, _, _ = lifecycle
    assert adapter.sweep_orphans(active_execution_ids=set()) == []
    assert snapshots.delete_calls == disks.delete_calls == []
    assert snapshots.resources and disks.resources


def test_unknown_tagged_resources_without_ledger_are_preserved(lifecycle):
    adapter, _, snapshots, disks, _, _, _, _ = lifecycle
    # The resources really exist and have matching tags, but an absent ledger is
    # insufficient proof of ownership for automatic deletion.
    adapter._save(
        replace(
            adapter.execution,
            resources=(),
            status=ExecutionStatus.FAILED,
            cleanup_status=CleanupStatus.PENDING,
            state_version=adapter.execution.state_version + 1,
        )
    )
    assert adapter.sweep_orphans(active_execution_ids=set()) == []
    assert snapshots.delete_calls == disks.delete_calls == []


def test_cleanup_preserves_dependencies_after_disk_delete_failure(lifecycle):
    adapter, _, snapshots, disks, _, target, _, disk_id = lifecycle
    adapter.mark_scan_complete()
    disks.delete_failures.add(disk_id.rsplit("/", 1)[-1])
    result = adapter.cleanup(target, "collector-1")
    assert result.cleanup_status is CleanupStatus.PARTIAL
    assert snapshots.delete_calls == []
    assert snapshots.resources


def test_replaced_disk_ownership_is_checked_before_detach_or_delete(lifecycle):
    adapter, _, snapshots, disks, collector, target, _, _ = lifecycle
    adapter.mark_scan_complete()
    for resource in disks.resources.values():
        if isinstance(resource, dict):
            resource["labels"] = {"agent-bom-sidescan": "true"}
        else:
            resource.tags = {"agent-bom-sidescan": "true"}
    before = list(collector.update_calls if adapter.provider == "azure" else collector.detach_calls)
    result = adapter.cleanup(target, "collector-1")
    assert result.cleanup_status is CleanupStatus.PARTIAL
    assert snapshots.delete_calls == disks.delete_calls == []
    assert (collector.update_calls if adapter.provider == "azure" else collector.detach_calls) == before


def test_direct_delete_cannot_target_an_unregistered_source(lifecycle):
    adapter, _, _, disks, _, target, _, _ = lifecycle
    with pytest.raises(SideScanOwnershipError):
        adapter.delete_scan_disk(target, target.target_id)
    assert disks.delete_calls == []


def test_cleanup_does_not_take_over_an_existing_claim(lifecycle):
    adapter, store, snapshots, disks, _, target, _, _ = lifecycle
    adapter.mark_scan_complete()
    claimed = adapter.execution.transition(phase="cleanup", cleanup_status=CleanupStatus.IN_PROGRESS)
    store.save(claimed, expected_version=adapter.execution.state_version)
    adapter.execution = claimed
    with pytest.raises(SideScanStateConflictError):
        adapter.cleanup(target, "collector-1")
    assert snapshots.delete_calls == disks.delete_calls == []


def test_detach_failure_keeps_disk_and_snapshot(lifecycle, monkeypatch):
    adapter, _, snapshots, disks, _, target, _, _ = lifecycle
    adapter.mark_scan_complete()

    def denied(*args, **kwargs):
        raise FakeSdkError("denied", 403)

    monkeypatch.setattr(adapter, "detach_scan_disk", denied)
    result = adapter.cleanup(target, "collector-1")
    assert result.cleanup_status is CleanupStatus.PARTIAL
    assert snapshots.delete_calls == disks.delete_calls == []


def test_terminal_execution_sweep_uses_ledger_without_provider_enumeration(lifecycle, monkeypatch):
    adapter, _, snapshots, disks, _, _, snapshot_id, disk_id = lifecycle
    adapter.mark_scan_complete()

    def forbidden(*args, **kwargs):
        raise AssertionError("provider-wide enumeration is not cleanup authority")

    monkeypatch.setattr(snapshots, "list", forbidden)
    monkeypatch.setattr(disks, "list", forbidden)
    swept = adapter.sweep_orphans(active_execution_ids=set())
    assert set(swept) == {snapshot_id.rsplit("/", 1)[-1], disk_id.rsplit("/", 1)[-1]}
    assert adapter.execution.cleanup_status is CleanupStatus.COMPLETE
    assert not snapshots.resources and not disks.resources


def test_stale_worker_cannot_claim_cleanup(lifecycle):
    adapter, store, snapshots, disks, _, target, _, _ = lifecycle
    adapter.mark_scan_complete()
    claimed = adapter.execution.transition(phase="cleanup", cleanup_status=CleanupStatus.IN_PROGRESS)
    store.save(claimed, expected_version=adapter.execution.state_version)
    with pytest.raises(SideScanStateConflictError):
        adapter.cleanup(target, "collector-1")
    assert snapshots.delete_calls == disks.delete_calls == []
