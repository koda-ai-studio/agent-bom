"""Run discovery retains independent evidence across lazy SDK failures."""

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent_bom.cloud import wandb_provider as provider


class ProviderError(Exception):
    def __init__(self, status):
        self.response = SimpleNamespace(status_code=status)
        super().__init__("private-provider-marker")


def run(name, config=None):
    return SimpleNamespace(id=name, name=name, config=config or {}, metadata={})


def interrupted(values, status=403):
    yield from values
    raise ProviderError(status)


@pytest.fixture
def api(monkeypatch):
    api = MagicMock()
    api.artifact_types.return_value = []
    monkeypatch.setitem(sys.modules, "wandb", SimpleNamespace(Api=lambda **kwargs: api))
    return api


@pytest.mark.parametrize("status,outcome", [(403, "denied"), (429, "throttled"), (503, "unavailable")])
def test_later_run_page_failure_retains_runs(api, status, outcome):
    api.runs.return_value = interrupted([run("first")], status)
    agents, warnings = provider.discover(api_key="fixture", entity="team", project="training")
    assert [a.name for a in agents] == ["wandb-run:first"]
    assert warnings[0].startswith(f"wandb:runs:{outcome}:")
    assert "private-provider-marker" not in str(warnings)


def test_failed_project_does_not_hide_following_project(api):
    api.projects.return_value = [SimpleNamespace(name="denied"), SimpleNamespace(name="visible")]
    api.runs.side_effect = [ProviderError(403), [run("visible-run")]]
    agents, warnings = provider.discover(api_key="fixture", entity="team")
    assert [a.name for a in agents] == ["wandb-run:visible-run"]
    assert warnings[0].startswith("wandb:runs:denied:")
    assert api.runs.call_count == 2


def test_later_project_page_failure_retains_runs(api):
    api.projects.return_value = interrupted([SimpleNamespace(name="visible")])
    api.runs.return_value = [run("visible-run")]
    agents, warnings = provider.discover(api_key="fixture", entity="team")
    assert [a.name for a in agents] == ["wandb-run:visible-run"]
    assert warnings[0].startswith("wandb:projects:denied:")


def test_malformed_run_does_not_hide_following_runs(api):
    api.runs.return_value = [run("bad", {"_wandb": "malformed"}), run("good")]
    agents, warnings = provider.discover(api_key="fixture", entity="team", project="training")
    assert [a.name for a in agents] == ["wandb-run:good"]
    assert warnings[0].startswith("wandb:runs:unavailable:")


def test_successful_empty_runs_have_no_warning(api):
    api.runs.return_value = []
    agents, warnings = provider.discover(api_key="fixture", entity="team", project="training")
    assert agents == []
    assert warnings == []


def test_invalid_project_record_does_not_hide_following_project(api):
    api.projects.return_value = [SimpleNamespace(name=None), SimpleNamespace(name="visible")]
    api.runs.return_value = [run("good")]
    agents, warnings = provider.discover(api_key="fixture", entity="team")
    assert [a.name for a in agents] == ["wandb-run:good"]
    assert warnings[0].startswith("wandb:projects:unavailable:")


def test_project_listing_failure_has_fixed_diagnostics(api):
    api.projects.side_effect = ProviderError(403)
    agents, warnings = provider.discover(api_key="fixture", entity="team")
    assert agents == []
    assert warnings[0].startswith("wandb:projects:denied:")
    assert "private-provider-marker" not in str(warnings)


def test_empty_project_listing_is_complete(api):
    api.projects.return_value = []
    agents, warnings = provider.discover(api_key="fixture", entity="team")
    assert agents == []
    assert warnings == []
    api.runs.assert_not_called()
