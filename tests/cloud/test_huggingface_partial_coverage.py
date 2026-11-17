"""Lazy Hub failures retain prior inventory and independent records."""

import sys
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

from agent_bom.cloud.huggingface import discover


@pytest.fixture
def hub(monkeypatch):
    api = Mock()
    for name in ("list_models", "list_spaces", "list_inference_endpoints"):
        getattr(api, name).return_value = []
    monkeypatch.setitem(sys.modules, "huggingface_hub", SimpleNamespace(HfApi=Mock(return_value=api)))
    return api


@pytest.mark.parametrize(
    "method,resource,record,expected",
    [
        ("list_models", "models", SimpleNamespace(id="fixture/model"), "hf-model:fixture/model"),
        ("list_spaces", "spaces", SimpleNamespace(id="fixture/space", sdk="gradio"), "hf-space:fixture/space"),
        ("list_inference_endpoints", "inference-endpoints", SimpleNamespace(name="endpoint", framework="pytorch"), "hf-endpoint:endpoint"),
    ],
)
@pytest.mark.parametrize("code,status", [(403, "denied"), (429, "throttled"), (503, "unavailable")])
def test_later_page_failure_preserves_inventory(hub, method, resource, record, expected, code, status):
    def pages():
        yield record
        response = httpx.Response(code, request=httpx.Request("GET", "https://example.invalid/private"))
        raise httpx.HTTPStatusError("private-marker", request=response.request, response=response)

    getattr(hub, method).return_value = pages()
    agents, warnings = discover(token="fixture-token", username="fixture")
    assert [a.name for a in agents] == [expected]
    assert len(warnings) == 1
    assert warnings[0].startswith(f"huggingface:{resource}:{status}:")
    assert "private-marker" not in str(warnings)


def test_malformed_record_does_not_hide_later_model(hub):
    hub.list_models.return_value = [SimpleNamespace(id="bad", library_name=123), SimpleNamespace(id="good")]
    agents, warnings = discover(token="fixture-token", username="fixture")
    assert [a.name for a in agents] == ["hf-model:good"]
    assert warnings[0].startswith("huggingface:models:unavailable:")
