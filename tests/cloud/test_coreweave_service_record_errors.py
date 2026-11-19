"""One malformed InferenceService must not erase independent inventory."""

from unittest.mock import MagicMock

import pytest

from agent_bom.cloud import coreweave


def service(name):
    return {"metadata": {"name": name, "namespace": "inference"}, "spec": {}, "status": {}}


@pytest.mark.parametrize(
    "bad",
    [None, "private-marker", {"metadata": None}, {"spec": None}, {"spec": {"predictor": {"containers": [None]}}}, {"status": 42}],
)
def test_bad_record_keeps_neighboring_services(monkeypatch, bad):
    monkeypatch.setattr(coreweave.shutil, "which", lambda _: "/fixture/kubectl")

    def read(args, **kwargs):
        if coreweave._CRD_INFERENCESERVICE in args:
            return {"items": [service("first"), bad, service("last")]}
        return {"items": []}

    monkeypatch.setattr(coreweave, "_kubectl", read)
    agents, warnings = coreweave.discover(context="fixture-cluster", namespace="inference")
    assert len(agents) == 2
    assert [a.metadata["cloud_origin"]["resource_id"] for a in agents] == ["inference/first", "inference/last"]
    assert all("fixture-cluster" in a.config_path for a in agents)
    assert len(warnings) == 1
    assert "InferenceService" in warnings[0]
    assert "Assessment incomplete" in warnings[0]
    assert "private-marker" not in warnings[0]


def test_all_invalid_records_are_not_empty_success(monkeypatch):
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": [None]}))
    agents, warnings = coreweave._discover_inference_services(None, None)
    assert agents == []
    assert len(warnings) == 1
    assert "Assessment incomplete" in warnings[0]


def test_valid_empty_services_remain_complete(monkeypatch):
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": []}))
    assert coreweave._discover_inference_services(None, None) == ([], [])


def test_record_boundary_does_not_swallow_programming_errors(monkeypatch):
    monkeypatch.setattr(coreweave, "_kubectl", MagicMock(return_value={"items": [service("first")]}))
    monkeypatch.setattr(coreweave, "_inference_service_agent", MagicMock(side_effect=RuntimeError("implementation defect")))
    with pytest.raises(RuntimeError, match="implementation defect"):
        coreweave._discover_inference_services(None, None)
