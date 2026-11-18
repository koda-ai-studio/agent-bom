"""SDK wrapper failures preserve read status and independent inventory."""

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent_bom.cloud import wandb_provider as provider


class CommError(Exception):
    def __init__(self, message, exc=None):
        self.exc = exc
        super().__init__(message)


class AuthenticationError(CommError):
    pass


@pytest.fixture
def api(monkeypatch):
    api = MagicMock()
    api.runs.return_value = []
    api.artifact_types.return_value = []
    sdk = ModuleType("wandb")
    sdk.Api = MagicMock(return_value=api)
    errors = ModuleType("wandb.errors")
    errors.CommError = CommError
    errors.AuthenticationError = AuthenticationError
    monkeypatch.setitem(sys.modules, "wandb", sdk)
    monkeypatch.setitem(sys.modules, "wandb.errors", errors)
    return api


def wrapped(code):
    cause = OSError("private response")
    cause.response = SimpleNamespace(status_code=code)
    return CommError("private SDK message", cause)


@pytest.mark.parametrize("surface", ["runs", "artifact_types"])
@pytest.mark.parametrize("code,status", [(401, "denied"), (403, "denied"), (429, "throttled"), (503, "unavailable")])
def test_wrapped_http_errors(api, surface, code, status):
    getattr(api, surface).side_effect = wrapped(code)
    agents, warnings = provider.discover(api_key="fixture", entity="team", project="p")
    assert agents == []
    assert len(warnings) == 1
    assert f":{status}:" in warnings[0]
    assert "private" not in warnings[0]


def test_auth_error_without_http_response(api):
    api.runs.side_effect = AuthenticationError("private credentials")
    assert ":denied:" in provider.discover(api_key="fixture", entity="team", project="p")[1][0]


@pytest.mark.parametrize("surface", ["runs", "artifact_types"])
def test_programming_errors_are_not_inventory_warnings(api, surface):
    getattr(api, surface).side_effect = RuntimeError("implementation defect")
    with pytest.raises(RuntimeError, match="implementation defect"):
        provider.discover(api_key="fixture", entity="team", project="p")


def test_wrapped_later_page_keeps_first_run(api):
    def pages():
        yield SimpleNamespace(id="first", name="first", config={}, metadata={})
        raise wrapped(429)

    api.runs.return_value = pages()
    agents, warnings = provider.discover(api_key="fixture", entity="team", project="p")
    assert [a.name for a in agents] == ["wandb-run:first"]
    assert ":throttled:" in warnings[0]


def test_lazy_run_failure_keeps_next_run(api):
    class DeniedRun:
        @property
        def metadata(self):
            raise wrapped(403)

    api.runs.return_value = [DeniedRun(), SimpleNamespace(id="next", name="next", config={}, metadata={})]
    agents, warnings = provider.discover(api_key="fixture", entity="team", project="p")
    assert [a.name for a in agents] == ["wandb-run:next"]
    assert ":denied:" in warnings[0]


def test_lazy_artifact_failure_keeps_next_artifact(api):
    class DeniedArtifact:
        name = "denied:v1"
        version = "v1"

        @property
        def metadata(self):
            raise wrapped(403)

    good = SimpleNamespace(name="next:v1", version="v1", metadata={})
    collection = SimpleNamespace(artifacts=lambda: [DeniedArtifact(), good])
    api.artifact_types.return_value = [SimpleNamespace(name="model", collections=lambda: [collection])]
    agents, warnings = provider.discover(api_key="fixture", entity="team", project="p")
    assert [a.name for a in agents] == ["wandb-model:next:v1"]
    assert ":denied:" in warnings[0]


def test_cyclic_sdk_cause_is_bounded(api):
    error = CommError("private")
    error.exc = error
    api.runs.side_effect = error
    assert ":unavailable:" in provider.discover(api_key="fixture", entity="team", project="p")[1][0]
