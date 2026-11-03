"""Gateway API-key verification (scrypt + key-store reads) never runs on the event loop."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamRegistry


def _on_event_loop() -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return False
    return True


@pytest.mark.parametrize(
    ("method", "path"),
    [("get", "/metrics"), ("post", "/v1/firewall/check"), ("post", "/mcp/upstream")],
)
def test_gateway_key_store_calls_run_in_a_worker_thread(monkeypatch, method, path):
    calls: list[tuple[str, bool]] = []

    def has_keys() -> bool:
        calls.append(("has_keys", _on_event_loop()))
        return True

    def verify(_raw: str) -> None:
        calls.append(("verify", _on_event_loop()))
        return None

    store = SimpleNamespace(has_keys=has_keys, verify=verify)
    monkeypatch.setattr("agent_bom.api.gateway_auth.get_key_store", lambda: store)
    client = TestClient(create_gateway_app(GatewaySettings(registry=UpstreamRegistry([]), policy={})))
    kwargs = {"json": {}} if method == "post" else {}
    response = getattr(client, method)(path, headers={"x-api-key": "synthetic"}, **kwargs)
    assert response.status_code == 401
    assert ("verify", False) in calls
    assert not [name for name, on_loop in calls if on_loop], calls
