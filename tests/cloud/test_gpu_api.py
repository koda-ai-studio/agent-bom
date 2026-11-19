"""Shared bearer-token REST helpers used by the GPU cloud connectors."""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from agent_bom.cloud.base import CloudDiscoveryError
from agent_bom.cloud.gpu_api import bearer_json_get, collect_gpu_inventory, missing_api_key_warning
from agent_bom.models import Agent, AgentType


def _response(status: int, payload: object) -> httpx.Response:
    return httpx.Response(status, json=payload, request=httpx.Request("GET", "https://example.test"))


def test_bearer_json_get_sends_bearer_and_extra_headers():
    with patch("agent_bom.cloud.gpu_api.http_client.sync_get", return_value=_response(200, {"items": []})) as mock_get:
        result = bearer_json_get(
            "https://api.example.test/v1", "/vms", "k", label="Example", timeout=7, extra_headers={"Accept": "application/json"}
        )
    assert result == {"items": []}
    mock_get.assert_called_once_with(
        "https://api.example.test/v1/vms",
        timeout=7,
        headers={"Authorization": "Bearer k", "Accept": "application/json"},
    )


def test_bearer_json_get_raises_labelled_error_when_retries_exhausted():
    with patch("agent_bom.cloud.gpu_api.http_client.sync_get", return_value=None):
        with pytest.raises(CloudDiscoveryError, match="^Example: request failed after retries$"):
            bearer_json_get("https://api.example.test", "/x", "k", label="Example")


def test_bearer_json_get_raises_http_status():
    with patch("agent_bom.cloud.gpu_api.http_client.sync_get", return_value=_response(403, {})):
        with pytest.raises(httpx.HTTPStatusError):
            bearer_json_get("https://api.example.test", "/x", "k", label="Example")


def _agent(record: dict) -> Agent:
    return Agent(name=record["name"], agent_type=AgentType.CUSTOM, config_path=f"x://{record['name']}")


def test_collect_gpu_inventory_keeps_records_before_a_malformed_one():
    agents, warnings = collect_gpu_inventory("example", lambda: [{"name": "a"}, None, {"name": "c"}], _agent)
    assert [a.name for a in agents] == ["a"]
    assert warnings == [
        "example:instances:unavailable: Provider read failed or returned invalid data; retry or check availability. Assessment incomplete."
    ]


def test_collect_gpu_inventory_classifies_fetch_failures():
    def fetch() -> list:
        raise httpx.HTTPStatusError("x", request=httpx.Request("GET", "https://e.test"), response=_response(429, {}))

    agents, warnings = collect_gpu_inventory("example", fetch, _agent)
    assert agents == []
    assert warnings[0].startswith("example:instances:throttled:")


def test_collect_gpu_inventory_does_not_swallow_programming_errors():
    def fetch() -> list:
        raise RuntimeError("bug")

    with pytest.raises(RuntimeError):
        collect_gpu_inventory("example", fetch, _agent)


def test_collect_gpu_inventory_empty_is_clean():
    assert collect_gpu_inventory("example", lambda: [], _agent) == ([], [])


def test_missing_api_key_warning_text():
    assert missing_api_key_warning("CRUSOE_API_KEY", "--crusoe-api-key") == (
        "CRUSOE_API_KEY not set. Provide --crusoe-api-key or set the CRUSOE_API_KEY env var."
    )
