"""Malformed VirtualServers must not discard neighboring GPU inventory."""

from unittest.mock import MagicMock

import pytest

from agent_bom.cloud import coreweave


def vm(name):
    return {"metadata": {"name": name, "namespace": "training"}, "spec": {"resources": {"gpu": {"type": "fixture-gpu", "count": 2}}}}


@pytest.mark.parametrize(
    "bad",
    [None, "private-marker", {"metadata": None}, {"spec": None}, {"spec": {"resources": None}}, {"spec": {"resources": {"gpu": None}}}],
)
def test_invalid_vm_preserves_neighbors(monkeypatch, bad):
    monkeypatch.setattr(coreweave.shutil, "which", lambda _: "/fixture/kubectl")

    def read(args, **kwargs):
        return {"items": [vm("first"), bad, vm("last")]} if coreweave._CRD_VIRTUALSERVER in args else {"items": []}

    monkeypatch.setattr(coreweave, "_kubectl", read)
    agents, warnings = coreweave.discover(context="fixture-cluster", namespace="training")
    assert [a.metadata["cloud_origin"]["resource_id"] for a in agents] == ["training/first", "training/last"]
    assert all(a.source == "coreweave-gpu" and a.metadata["gpu_count"] == 2 for a in agents)
    assert all("fixture-cluster" in a.config_path for a in agents)
    assert len(warnings) == 1
    assert "VirtualServer" in warnings[0] and "Assessment incomplete" in warnings[0]
    assert "private-marker" not in warnings[0]


def test_all_invalid_vms_are_not_successful_empty(monkeypatch):
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": [None]}))
    agents, warnings = coreweave._discover_virtual_servers(None, None)
    assert agents == []
    assert len(warnings) == 1
    assert "Assessment incomplete" in warnings[0]


def test_valid_empty_vms_remain_complete(monkeypatch):
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": []}))
    assert coreweave._discover_virtual_servers(None, None) == ([], [])


def test_vm_boundary_does_not_swallow_programming_errors(monkeypatch):
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": [vm("first")]}))
    monkeypatch.setattr(coreweave, "_virtual_server_agent", MagicMock(side_effect=RuntimeError("implementation defect")))
    with pytest.raises(RuntimeError, match="implementation defect"):
        coreweave._discover_virtual_servers(None, None)
