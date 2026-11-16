"""REST inventory failures must not be confused with an authorized empty account."""

import httpx
import pytest

from agent_bom.cloud import crusoe, lambda_labs, vastai

PROVIDERS = [(lambda_labs, "lambda", {"data": []}), (vastai, "vastai", {"instances": []}), (crusoe, "crusoe", {"items": []})]


@pytest.mark.parametrize("module,provider,empty", PROVIDERS)
@pytest.mark.parametrize("status,code", [(401, "denied"), (403, "denied"), (429, "throttled"), (503, "unavailable")])
def test_http_failure_has_fixed_typed_warning(monkeypatch, module, provider, empty, status, code):
    response = httpx.Response(
        status, json={"error": "private-diagnostic-marker"}, request=httpx.Request("GET", "https://example.test/private-diagnostic-marker")
    )
    monkeypatch.setattr(module.http_client, "sync_get", lambda *a, **kw: response)
    agents, warnings = module.discover(api_key="fixture")
    assert agents == []
    assert len(warnings) == 1
    assert warnings[0].startswith(f"{provider}:instances:{code}:")
    assert "Assessment incomplete" in warnings[0]
    assert "private-diagnostic-marker" not in warnings[0]


@pytest.mark.parametrize("module,provider,empty", PROVIDERS)
def test_authorized_empty_inventory_has_no_warning(monkeypatch, module, provider, empty):
    response = httpx.Response(200, json=empty, request=httpx.Request("GET", "https://example.test"))
    monkeypatch.setattr(module.http_client, "sync_get", lambda *a, **kw: response)
    assert module.discover(api_key="fixture") == ([], [])


@pytest.mark.parametrize("module,provider,empty", PROVIDERS)
@pytest.mark.parametrize("payload", [{}, {"error": "private-diagnostic-marker"}, None, {"data": None, "instances": None, "items": None}])
def test_invalid_inventory_is_incomplete(monkeypatch, module, provider, empty, payload):
    response = httpx.Response(200, json=payload, request=httpx.Request("GET", "https://example.test"))
    monkeypatch.setattr(module.http_client, "sync_get", lambda *a, **kw: response)
    agents, warnings = module.discover(api_key="fixture")
    assert agents == []
    assert len(warnings) == 1
    assert warnings[0].startswith(f"{provider}:instances:unavailable:")
    assert "private-diagnostic-marker" not in warnings[0]


@pytest.mark.parametrize("module,provider,empty", PROVIDERS)
def test_exhausted_transport_is_incomplete(monkeypatch, module, provider, empty):
    monkeypatch.setattr(module.http_client, "sync_get", lambda *a, **kw: None)
    agents, warnings = module.discover(api_key="fixture")
    assert agents == []
    assert warnings[0].startswith(f"{provider}:instances:unavailable:")


@pytest.mark.parametrize("module,provider,empty", PROVIDERS)
def test_valid_inventory_survives_later_malformed_record(monkeypatch, module, provider, empty):
    key = next(iter(empty))
    payload = {key: [{"id": "fixture-id", "name": "fixture-instance"}, None]}
    response = httpx.Response(200, json=payload, request=httpx.Request("GET", "https://example.test"))
    monkeypatch.setattr(module.http_client, "sync_get", lambda *a, **kw: response)
    agents, warnings = module.discover(api_key="fixture")
    assert len(agents) == 1
    assert "fixture-id" in agents[0].config_path
    assert warnings[0].startswith(f"{provider}:instances:unavailable:")
    assert "Assessment incomplete" in warnings[0]
