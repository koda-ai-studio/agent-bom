"""MLflow partial pagination must retain evidence and report coverage gaps."""

import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent_bom.cloud import mlflow_provider as provider


class Page(list):
    def __init__(self, values=(), token=None):
        super().__init__(values)
        self.token = token


class DeniedError(Exception):
    error_code = "PERMISSION_DENIED"


@pytest.fixture
def client(monkeypatch):
    client = MagicMock()
    client.search_registered_models.return_value = Page()
    client.search_experiments.return_value = Page()
    client.search_runs.return_value = []
    monkeypatch.setitem(sys.modules, "mlflow", SimpleNamespace(MlflowClient=lambda **kwargs: client))
    return client


def record(resource, index):
    if resource == "models":
        return SimpleNamespace(name=f"model-{index}", latest_versions=[], description="")
    return SimpleNamespace(experiment_id=str(index), name=f"experiment-{index}")


def search(client, resource):
    return client.search_registered_models if resource == "models" else client.search_experiments


@pytest.mark.parametrize("resource", ["models", "experiments"])
def test_later_page_failure_retains_collected_inventory(client, resource):
    method = search(client, resource)
    method.side_effect = [Page([record(resource, 1)], "next"), DeniedError("private-provider-marker")]
    agents, warnings = provider.discover("https://tracking.example.test")
    assert len(agents) == 1
    assert warnings and warnings[0].startswith(f"mlflow:{resource}:denied:")
    assert "private-provider-marker" not in str(warnings)
    assert method.call_args_list[1].kwargs["page_token"] == "next"


@pytest.mark.parametrize("resource", ["models", "experiments"])
def test_page_limit_is_incomplete(client, resource):
    method = search(client, resource)
    method.side_effect = [Page([record(resource, i)], f"page-{i + 1}") for i in range(100)]
    agents, warnings = provider.discover("https://tracking.example.test")
    assert len(agents) == 100
    assert method.call_count == 100
    assert warnings and "page limit" in warnings[0]
    assert "Assessment incomplete" in warnings[0]


@pytest.mark.parametrize("resource", ["models", "experiments"])
def test_repeated_token_stops_without_claiming_complete(client, resource):
    method = search(client, resource)
    method.side_effect = [Page([record(resource, 1)], "same"), Page([record(resource, 2)], "same")]
    agents, warnings = provider.discover("https://tracking.example.test")
    assert len(agents) == 2
    assert method.call_count == 2
    assert warnings and "repeated page token" in warnings[0]


@pytest.mark.parametrize("resource", ["models", "experiments"])
def test_final_page_at_limit_is_complete(client, resource):
    method = search(client, resource)
    method.side_effect = [Page([record(resource, i)], str(i + 1) if i < 99 else None) for i in range(100)]
    agents, warnings = provider.discover("https://tracking.example.test")
    assert len(agents) == 100
    assert warnings == []
