"""Exercise the documented type -> collection -> artifact read contract."""

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent_bom.cloud import wandb_provider as provider


class ProviderError(Exception):
    def __init__(self, status):
        self.response = SimpleNamespace(status_code=status)
        super().__init__("private-provider-marker")


def interrupted(values, status=403):
    yield from values
    raise ProviderError(status)


def artifact(name="model:v1", metadata=None):
    return SimpleNamespace(name=name, version="v1", metadata=metadata or {})


def collection(values):
    return SimpleNamespace(artifacts=MagicMock(return_value=values))


def kind(name, collections):
    return SimpleNamespace(name=name, collections=MagicMock(return_value=collections))


@pytest.fixture
def api(monkeypatch):
    api = SimpleNamespace(artifact_types=MagicMock(return_value=[]), runs=MagicMock(return_value=[]))
    monkeypatch.setitem(sys.modules, "wandb", SimpleNamespace(Api=lambda **kwargs: api))
    return api


def discover():
    return provider.discover(api_key="fixture", entity="team", project="training")


def test_uses_project_types_and_named_collections(api):
    model = collection([artifact(metadata={"_wandb": {"requirements": ["numpy==1.26.4"]}})])
    dataset = collection([artifact("data:v1")])
    types = [kind("model", [model]), kind("dataset", [dataset])]
    api.artifact_types.return_value = types
    agents, warnings = discover()
    assert [a.name for a in agents] == ["wandb-model:model:v1", "wandb-dataset:data:v1"]
    assert warnings == []
    assert [(p.name, p.version) for p in agents[0].mcp_servers[0].packages] == [("numpy", "1.26.4")]
    api.artifact_types.assert_called_once_with("team/training")
    for item in types:
        item.collections.assert_called_once_with()
    model.artifacts.assert_called_once_with()
    dataset.artifacts.assert_called_once_with()


@pytest.mark.parametrize("status,outcome", [(403, "denied"), (429, "throttled"), (503, "unavailable")])
def test_later_version_failure_retains_artifacts_and_next_collection(api, status, outcome):
    api.artifact_types.return_value = [
        kind("model", [collection(interrupted([artifact("first:v1")], status)), collection([artifact("next:v1")])])
    ]
    agents, warnings = discover()
    assert [a.name for a in agents] == ["wandb-model:first:v1", "wandb-model:next:v1"]
    assert warnings[0].startswith(f"wandb:artifacts:{outcome}:")
    assert "private-provider-marker" not in str(warnings)


def test_failed_collections_preserve_next_type(api):
    api.artifact_types.return_value = [
        kind("model", interrupted([collection([artifact()])])),
        kind("dataset", [collection([artifact("data:v1")])]),
    ]
    agents, warnings = discover()
    assert len(agents) == 2
    assert warnings[0].startswith("wandb:artifact-collections:denied:")


def test_failed_type_page_preserves_completed_types(api):
    api.artifact_types.return_value = interrupted([kind("model", [collection([artifact()])])])
    agents, warnings = discover()
    assert len(agents) == 1
    assert warnings[0].startswith("wandb:artifact-types:denied:")


def test_malformed_artifact_does_not_hide_following_artifact(api):
    api.artifact_types.return_value = [kind("model", [collection([artifact("bad:v1", {"_wandb": "bad"}), artifact("good:v1")])])]
    agents, warnings = discover()
    assert [a.name for a in agents] == ["wandb-model:good:v1"]
    assert warnings[0].startswith("wandb:artifacts:unavailable:")


def test_empty_types_are_successful_empty(api):
    agents, warnings = discover()
    assert agents == []
    assert warnings == []


def test_unrelated_artifact_types_are_not_scanned(api):
    unrelated = kind("table", [])
    api.artifact_types.return_value = [unrelated]
    agents, warnings = discover()
    assert agents == []
    assert warnings == []
    unrelated.collections.assert_not_called()


def test_type_request_denial_is_not_empty_success(api):
    api.artifact_types.side_effect = ProviderError(403)
    agents, warnings = discover()
    assert agents == []
    assert warnings[0].startswith("wandb:artifact-types:denied:")
    assert "private-provider-marker" not in str(warnings)


def test_invalid_type_does_not_hide_next_type(api):
    api.artifact_types.return_value = [SimpleNamespace(name=None), kind("dataset", [collection([artifact("data:v1")])])]
    agents, warnings = discover()
    assert [a.name for a in agents] == ["wandb-dataset:data:v1"]
    assert warnings[0].startswith("wandb:artifact-types:unavailable:")


def test_empty_collections_and_versions_are_successful_empty(api):
    api.artifact_types.return_value = [kind("model", []), kind("dataset", [collection([])])]
    agents, warnings = discover()
    assert agents == []
    assert warnings == []


def test_sdk_initialization_failure_does_not_leak_exception(monkeypatch):
    monkeypatch.setitem(sys.modules, "wandb", SimpleNamespace(Api=MagicMock(side_effect=ProviderError(403))))
    agents, warnings = discover()
    assert agents == []
    assert len(warnings) == 2
    assert all(":denied:" in warning for warning in warnings)
    assert "private-provider-marker" not in str(warnings)


def test_minimum_sdk_collection_versions_method_is_supported(api):
    legacy = SimpleNamespace(versions=MagicMock(return_value=[artifact()]))
    api.artifact_types.return_value = [kind("model", [legacy])]
    agents, warnings = discover()
    assert [a.name for a in agents] == ["wandb-model:model:v1"]
    assert warnings == []
    legacy.versions.assert_called_once_with()
