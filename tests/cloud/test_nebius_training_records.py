"""Nebius training inventory survives malformed independent pod records."""

import json
from types import SimpleNamespace

import pytest

from agent_bom.cloud import nebius


def pod(name, quantity="2"):
    return {
        "metadata": {"name": name, "namespace": "training"},
        "spec": {
            "containers": [
                {"name": "worker", "image": "fixture/train:1", "resources": {"limits": {"rdma/ib": "1", "nvidia.com/gpu": quantity}}}
            ]
        },
    }


def discover(monkeypatch, pods):
    monkeypatch.setattr(nebius.shutil, "which", lambda *a: "/fixture/kubectl")
    monkeypatch.setattr(nebius, "_kubectl_get_all_pods", lambda *a: SimpleNamespace(returncode=0, stdout=json.dumps({"items": pods})))
    return nebius._discover_infiniband_jobs("fixture", "fixture-project")


@pytest.mark.parametrize("bad", [{"metadata": None}, {"spec": None}, pod("bad", "private-marker")])
@pytest.mark.parametrize("position", [0, 1])
def test_invalid_training_pod_keeps_valid_neighbors(monkeypatch, bad, position):
    pods = [pod("first"), pod("last")]
    pods.insert(position, bad)
    agents, warnings = discover(monkeypatch, pods)
    assert [a.name for a in agents] == ["nebius-training:training/first", "nebius-training:training/last"]
    assert all(a.metadata["gpu_count"] == 2 for a in agents)
    assert len(warnings) == 1
    assert warnings[0].startswith("nebius:infiniband-jobs:unavailable:")
    assert "Assessment incomplete" in warnings[0]
    assert "private-marker" not in warnings[0]


def test_failed_identity_can_be_collected_from_later_valid_record(monkeypatch):
    agents, warnings = discover(monkeypatch, [pod("same", "invalid"), pod("same"), pod("same")])
    assert len(agents) == 1
    assert agents[0].metadata["gpu_count"] == 2
    assert len(warnings) == 1


def test_repeated_valid_pod_stays_deduplicated(monkeypatch):
    agents, warnings = discover(monkeypatch, [pod("same"), pod("same")])
    assert len(agents) == 1
    assert warnings == []


def test_empty_training_inventory_is_complete(monkeypatch):
    assert discover(monkeypatch, []) == ([], [])
