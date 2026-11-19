"""Malformed GPU pods must not erase independent workload inventory."""

from unittest.mock import MagicMock

import pytest

from agent_bom.cloud import coreweave


def pod(name, quantity="2", image="nvcr.io/nim/fixture/model:1"):
    return {
        "metadata": {"name": name, "namespace": "inference"},
        "spec": {"containers": [{"name": "model", "image": image, "resources": {"limits": {"nvidia.com/gpu": quantity}}}]},
    }


@pytest.mark.parametrize("bad", [None, "private-marker", {"metadata": None}, {"spec": None}, pod("bad", "private-marker")])
def test_bad_pod_preserves_neighbors(monkeypatch, bad):
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": [pod("first"), bad, pod("last")]}))
    agents, warnings = coreweave._discover_gpu_pods("fixture-cluster", "inference")
    assert [a.metadata["cloud_origin"]["resource_id"] for a in agents] == ["inference/first", "inference/last"]
    assert all(a.metadata["gpu_count"] == 2 and a.metadata["is_nim"] for a in agents)
    assert all("fixture-cluster" in a.config_path for a in agents)
    assert len(warnings) == 1
    assert "Assessment incomplete" in warnings[0]
    assert "private-marker" not in warnings[0]


def test_valid_containers_before_failure_are_retained(monkeypatch):
    partial = pod("partial")
    partial["spec"]["containers"].append(None)
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": [partial, pod("next")]}))
    agents, warnings = coreweave._discover_gpu_pods(None, None)
    assert [a.metadata["gpu_count"] for a in agents] == [2, 2]
    assert len(warnings) == 1


def test_multiple_containers_remain_one_pod(monkeypatch):
    item = pod("multi")
    worker = pod("second", "3", "fixture/worker:1")["spec"]["containers"][0]
    worker["name"] = "worker"
    item["spec"]["containers"].append(worker)
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": [item]}))
    agents, warnings = coreweave._discover_gpu_pods(None, None)
    assert len(agents) == 1
    assert agents[0].metadata["gpu_count"] == 5
    assert len(agents[0].mcp_servers) == 2
    assert warnings == []


def test_empty_gpu_pods_are_complete(monkeypatch):
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": []}))
    assert coreweave._discover_gpu_pods(None, None) == ([], [])


def test_programming_error_is_not_swallowed(monkeypatch):
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": [pod("first")]}))
    monkeypatch.setattr(coreweave, "iter_gpu_containers", MagicMock(side_effect=RuntimeError("implementation defect")))
    with pytest.raises(RuntimeError, match="implementation defect"):
        coreweave._discover_gpu_pods(None, None)
