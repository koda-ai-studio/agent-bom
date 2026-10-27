"""AWS cleanup preserves dependencies and never infers ownership from generic tags."""

import pytest

from agent_bom.cloud.side_scan import AwsEbsSideScanner, _LifecycleState
from tests.test_side_scan import FakeEc2Client


def test_tagged_snapshots_are_not_automatically_deleted_after_restart(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_SIDESCAN", "1")
    ec2 = FakeEc2Client(orphan_snapshots=[{"SnapshotId": "snap-active-other-worker"}])
    assert AwsEbsSideScanner(ec2_client=ec2).sweep_orphan_snapshots() == []
    assert ec2.calls == []


@pytest.mark.parametrize("failure", ["detach_volume", "delete_volume", "wait"])
def test_failed_prerequisite_preserves_dependent_resources(monkeypatch, failure):
    monkeypatch.setenv("AGENT_BOM_SIDESCAN", "1")
    ec2 = FakeEc2Client()

    def fail(**kwargs):
        raise RuntimeError("provider failure")

    if failure == "wait":

        class Waiter:
            wait = staticmethod(fail)

        ec2.get_waiter = lambda name: Waiter()
    else:
        monkeypatch.setattr(ec2, failure, fail)
    scanner = AwsEbsSideScanner(ec2_client=ec2)
    warnings = scanner._cleanup(_LifecycleState(snapshot_id="snap-owned", volume_id="vol-owned", attached_device="/dev/xvdf"))
    assert warnings
    assert "delete_snapshot" not in ec2.names()
    if failure != "delete_volume":
        assert "delete_volume" not in ec2.names()
