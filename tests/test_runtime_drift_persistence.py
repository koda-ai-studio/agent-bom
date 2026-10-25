"""Tool baselines never cross server identities or trust an unscoped file."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from agent_bom.runtime.detectors import ToolDriftDetector
from agent_bom.shield import Shield


@pytest.fixture
def state_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    return tmp_path


def test_unidentified_shields_do_not_restore_each_others_tools(state_dir):
    first = Shield(deep=True)
    assert first.check_drift(["read_a"]) == []
    second = Shield(deep=True)
    assert second.check_drift(["read_b"]) == []
    assert first.check_drift(["read_a", "new_tool"])[0]["detector"] == "tool_drift"
    assert not list(state_dir.glob("*baseline*"))


def test_scoped_shields_restore_only_their_own_baseline(state_dir):
    for server, tools in [("tenant-a/server", ["read_a"]), ("tenant-b/server", ["read_b", "new_tool"])]:
        assert Shield(deep=True, server_id=server).check_drift(tools) == []

    first = Shield(deep=True, server_id="tenant-a/server")
    second = Shield(deep=True, server_id="tenant-b/server")
    assert first.check_drift(["read_a"]) == []
    assert second.check_drift(["read_b", "new_tool"]) == []
    alerts = first.check_drift(["read_a", "new_tool"])
    assert alerts[0]["details"]["new_tools"] == ["new_tool"]


@pytest.mark.parametrize("server_id", [None, "", "   ", "server-a"])
def test_legacy_baseline_is_ignored_and_preserved(state_dir, server_id):
    legacy = state_dir / "drift_baseline.json"
    legacy.write_text('["unattributed_tool"]')
    detector = ToolDriftDetector(restore=True, server_id=server_id)
    assert detector.baseline is None
    assert detector.check(["own_tool"]) == []
    assert legacy.read_text() == '["unattributed_tool"]'


def test_identity_is_hashed_and_concurrent_servers_keep_separate_files(state_dir):
    identities = [f"https://server.invalid/{i}?token=fixture-secret" for i in range(8)]

    def establish(identity):
        ToolDriftDetector(server_id=identity).set_baseline(["read"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(establish, identities))
    files = list((state_dir / "drift_baselines").iterdir())
    assert len(files) == len(identities)
    for path in files:
        assert "fixture-secret" not in path.name + path.read_text()
        assert path.stat().st_mode & 0o077 == 0
    for identity in identities:
        assert ToolDriftDetector(restore=True, server_id=identity).baseline == {"read"}


@pytest.mark.parametrize("contents", ["{", "[{}]", "[1]", '"read"', '{"tools": ["read"]}'])
def test_invalid_scoped_baseline_is_ignored(state_dir, contents):
    ToolDriftDetector(server_id="server-a").set_baseline(["read"])
    path = next((state_dir / "drift_baselines").glob("*.json"))
    path.write_text(contents)
    detector = ToolDriftDetector(restore=True, server_id="server-a")
    assert detector.baseline is None
    assert detector.check(["own_tool"]) == []


def test_unavailable_persistence_keeps_in_memory_drift_detection(state_dir):
    (state_dir / "drift_baselines").write_text("not a directory")
    detector = ToolDriftDetector(restore=True, server_id="server-a")
    assert detector.check(["read"]) == []
    assert detector.check(["read", "new_tool"])[0].details["new_tools"] == ["new_tool"]


def test_same_identity_concurrent_writes_leave_one_complete_baseline(state_dir):
    catalogs = [[f"tool_{i}"] for i in range(20)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda tools: ToolDriftDetector(server_id="same-server").set_baseline(tools), catalogs))
    files = list((state_dir / "drift_baselines").iterdir())
    assert len(files) == 1
    assert json.loads(files[0].read_text()) in catalogs
