"""Discovery failures remain distinct from successful empty Hub inventories."""

import sys
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

from agent_bom.cloud.huggingface import discover


@pytest.fixture
def hub(monkeypatch):
    api = Mock()
    for method in ("list_models", "list_spaces", "list_inference_endpoints"):
        getattr(api, method).return_value = []
    monkeypatch.setitem(sys.modules, "huggingface_hub", SimpleNamespace(HfApi=Mock(return_value=api)))
    monkeypatch.delenv("HF_TOKEN", raising=False)
    return api


@pytest.mark.parametrize(
    "method,resource",
    [
        ("list_models", "models"),
        ("list_spaces", "spaces"),
        ("list_inference_endpoints", "inference-endpoints"),
    ],
)
@pytest.mark.parametrize("code,state", [(401, "denied"), (403, "denied"), (429, "throttled"), (503, "unavailable")])
def test_http_outcomes(hub, method, resource, code, state):
    response = httpx.Response(code, request=httpx.Request("GET", "https://example.invalid/private"))
    getattr(hub, method).side_effect = httpx.HTTPStatusError("private diagnostic", request=response.request, response=response)
    agents, warnings = discover(token="test-token", username="fixture")
    assert agents == []
    assert len(warnings) == 1
    assert f"huggingface:{resource}:{state}" in warnings[0]
    assert "private diagnostic" not in warnings[0]
    assert "https://" not in warnings[0]
    assert all(getattr(hub, name).called for name in ("list_models", "list_spaces", "list_inference_endpoints"))


def test_successful_empty_is_not_a_failure(hub):
    assert discover(token="test-token", username="fixture") == ([], [])


def test_failed_pagination_is_not_empty(hub):
    def pages():
        yield SimpleNamespace(id="fixture/model")
        raise httpx.ConnectError("private diagnostic")

    hub.list_models.return_value = pages()
    agents, warnings = discover(token="test-token", username="fixture")
    assert agents == []
    assert len(warnings) == 1
    assert "huggingface:models:unavailable" in warnings[0]
    assert "private diagnostic" not in warnings[0]


def test_failed_models_preserve_successful_spaces(hub):
    hub.list_models.side_effect = RuntimeError("private diagnostic")
    hub.list_spaces.return_value = [SimpleNamespace(id="fixture/space", sdk="gradio")]
    agents, warnings = discover(token="test-token", username="fixture")
    assert [a.name for a in agents] == ["hf-space:fixture/space"]
    assert len(warnings) == 1
    assert "huggingface:models:unavailable" in warnings[0]
    assert "private diagnostic" not in warnings[0]


def test_collection_outcome_is_typed_for_empty_and_denied(hub):
    from agent_bom.cloud.huggingface import HubCollectionStatus, _collect, _discover_models

    assert _collect("models", lambda: _discover_models("test-token", "fixture"))[2] is HubCollectionStatus.EMPTY
    response = httpx.Response(403, request=httpx.Request("GET", "https://example.invalid"))
    hub.list_models.side_effect = httpx.HTTPStatusError("denied", request=response.request, response=response)
    assert _collect("models", lambda: _discover_models("test-token", "fixture"))[2] is HubCollectionStatus.DENIED
