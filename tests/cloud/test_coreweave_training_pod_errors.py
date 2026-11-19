"""Training inventory survives malformed independent pods without duplicates."""

from unittest.mock import MagicMock

import pytest

from agent_bom.cloud import coreweave


def pod(name, quantity="2"):
    return {
        "metadata": {"name": name, "namespace": "training"},
        "spec": {
            "containers": [
                {"name": "worker", "image": "fixture/trainer:1", "resources": {"limits": {"rdma/ib": "1", "nvidia.com/gpu": quantity}}}
            ]
        },
    }


@pytest.mark.parametrize("bad", [None, "private-marker", {"metadata": None}, {"spec": None}, pod("bad", "private-marker")])
def test_bad_training_pod_preserves_neighbors(monkeypatch, bad):
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": [pod("first"), bad, pod("last")]}))
    agents, warnings = coreweave._discover_infiniband_jobs("fixture-cluster", "training")
    assert [a.metadata["cloud_origin"]["resource_id"] for a in agents] == ["training/first", "training/last"]
    assert all(a.metadata["gpu_count"] == 2 and a.metadata["infiniband"] for a in agents)
    assert all("fixture-cluster" in a.config_path for a in agents)
    assert len(warnings) == 1
    assert "Assessment incomplete" in warnings[0]
    assert "private-marker" not in warnings[0]


def test_training_pods_remain_deduplicated(monkeypatch):
    item = pod("multi")
    second = pod("second")["spec"]["containers"][0]
    second["name"] = "worker2"
    item["spec"]["containers"].append(second)
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": [item, item, pod("other")]}))
    agents, warnings = coreweave._discover_infiniband_jobs(None, None)
    assert [a.metadata["cloud_origin"]["resource_id"] for a in agents] == ["training/multi", "training/other"]
    assert warnings == []


def test_all_invalid_training_pods_are_incomplete(monkeypatch):
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": [pod("bad", "invalid")]}))
    agents, warnings = coreweave._discover_infiniband_jobs(None, None)
    assert agents == []
    assert len(warnings) == 1
    assert "Assessment incomplete" in warnings[0]


def test_empty_training_pods_are_complete(monkeypatch):
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": []}))
    assert coreweave._discover_infiniband_jobs(None, None) == ([], [])


def test_programming_errors_propagate(monkeypatch):
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": [pod("first")]}))
    monkeypatch.setattr(coreweave, "build_training_agent", MagicMock(side_effect=RuntimeError("implementation defect")))
    with pytest.raises(RuntimeError, match="implementation defect"):
        coreweave._discover_infiniband_jobs(None, None)


def test_failed_record_does_not_reserve_identity(monkeypatch):
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": [pod("same", "invalid"), pod("same")]}))
    agents, warnings = coreweave._discover_infiniband_jobs(None, None)
    assert len(agents) == 1
    assert agents[0].metadata["gpu_count"] == 2
    assert len(warnings) == 1
