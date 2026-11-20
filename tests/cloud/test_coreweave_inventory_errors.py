"""A malformed kubectl list is a read failure, never empty inventory."""

import json
import subprocess
from unittest.mock import MagicMock

import pytest

from agent_bom.cloud import coreweave
from agent_bom.cloud.base import CloudDiscoveryError


@pytest.fixture
def kubectl(monkeypatch):
    run = MagicMock()
    monkeypatch.setattr(coreweave.shutil, "which", lambda _: "/fixture/kubectl")
    monkeypatch.setattr(coreweave.subprocess, "run", run)
    return run


def response(payload):
    return subprocess.CompletedProcess([], 0, stdout=json.dumps(payload), stderr="")


@pytest.mark.parametrize(
    "payload",
    [{}, {"status": "Failure", "message": "private-marker"}, {"items": None}, {"items": {}}, {"items": "private-marker"}, [], None],
)
def test_invalid_envelope_is_rejected(kubectl, payload):
    kubectl.return_value = response(payload)
    with pytest.raises(CloudDiscoveryError, match="Invalid inventory response"):
        coreweave._kubectl(["get", "pods"])


@pytest.mark.parametrize("payload", [{}, {"items": {}}, {"items": None}])
def test_invalid_reads_are_incomplete_in_every_pass(kubectl, payload):
    kubectl.return_value = response(payload)
    agents, warnings = coreweave.discover()
    assert agents == []
    assert len(warnings) == 4
    assert all("Assessment incomplete" in warning for warning in warnings)
    assert kubectl.call_count == 3  # GPU and InfiniBand passes share one pod read


def test_valid_empty_lists_are_complete(kubectl):
    kubectl.return_value = response({"items": []})
    assert coreweave.discover() == ([], [])


def test_invalid_first_pass_does_not_hide_later_inventory(kubectl):
    service = {"metadata": {"name": "model", "namespace": "inference"}, "spec": {}, "status": {}}
    kubectl.side_effect = [response({}), response({"items": [service]}), response({"items": []}), response({"items": []})]
    agents, warnings = coreweave.discover()
    assert len(agents) == 1
    assert agents[0].source == "coreweave-inference"
    assert len(warnings) == 1
    assert "Assessment incomplete" in warnings[0]


def test_invalid_json_has_fixed_diagnostic(kubectl):
    kubectl.return_value = subprocess.CompletedProcess([], 0, stdout='{"private-marker":', stderr="")
    with pytest.raises(CloudDiscoveryError) as caught:
        coreweave._kubectl(["get", "pods"])
    assert "private-marker" not in str(caught.value)
    assert "Assessment incomplete" in str(caught.value)


@pytest.mark.parametrize(
    "stderr,code", [("Forbidden private-marker", "permission_denied"), ("TooManyRequests private-marker", "throttled")]
)
def test_read_failure_classification_remains_intact(kubectl, stderr, code):
    kubectl.return_value = subprocess.CompletedProcess([], 1, stdout="", stderr=stderr)
    agents, warnings = coreweave.discover()
    assert agents == []
    assert len(warnings) == 4
    assert all(code in warning for warning in warnings)
    assert "private-marker" not in str(warnings)
