"""Managed trace connections never delegate secret or endpoint selection to readers."""

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from agent_bom.api.routes import observability as routes


@pytest.fixture
def configured(monkeypatch, tmp_path):
    config = {
        "production": {
            "tenant_id": "tenant-a",
            "provider": "langfuse",
            "display_name": "Production traces",
            "endpoint": "https://cloud.langfuse.com",
            "credentials_env": "TRACE_TEST_CREDENTIALS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        }
    }
    path = tmp_path / "bindings.json"
    secret = tmp_path / "credentials.json"
    secret.write_text(json.dumps({"public_key": "fixture-public", "secret_key": "fixture-secret"}))
    monkeypatch.setenv("AGENT_BOM_TRACE_CONNECTIONS_FILE", str(path))
    monkeypatch.setenv("TRACE_TEST_CREDENTIALS_FILE", str(secret))
    monkeypatch.setattr(routes, "_blast_radius_views_for_tenant", lambda tenant: [])
    monkeypatch.setattr(routes, "_nhi_by_credential_for_tenant", lambda tenant: {})
    path.write_text(json.dumps(config))
    return config, path, secret


def request(tenant="tenant-a"):
    return SimpleNamespace(state=SimpleNamespace(tenant_id=tenant, api_key_name="operator"))


def test_catalog_hides_secrets_and_other_tenants(configured):
    result = routes.list_trace_connectors_route(request())
    assert result["connections"] == [{"id": "production", "provider": "langfuse", "display_name": "Production traces"}]
    assert routes.list_trace_connectors_route(request("tenant-b"))["connections"] == []
    assert "fixture-secret" not in json.dumps(result)
    assert "TRACE_TEST_CREDENTIALS" not in json.dumps(result)


def test_managed_pull_resolves_rotated_secret_on_each_use(configured, monkeypatch):
    calls = []
    from agent_bom.trace_connectors import NativeTracePage

    monkeypatch.setattr("agent_bom.trace_connectors.resolve_trace_project", lambda *a, **kw: "project-id")
    monkeypatch.setattr(
        "agent_bom.trace_connectors.fetch_trace_page",
        lambda provider, credentials, **kw: calls.append(credentials) or NativeTracePage({"spans": []}, None, 0),
    )
    body = {"connection_id": "production", "screen_content": False}
    routes.pull_trace_connector(request(), "langfuse", body)
    configured[2].write_text(json.dumps({"public_key": "fixture-public", "secret_key": "rotated-fixture"}))
    routes.pull_trace_connector(request(), "langfuse", body)
    assert calls[0] == {
        "host": "https://cloud.langfuse.com",
        "project": "",
        "public_key": "fixture-public",
        "secret_key": "fixture-secret",
    }
    assert calls[1]["secret_key"] == "rotated-fixture"


@pytest.mark.parametrize("case", ["tenant", "provider", "disabled", "expired", "unknown", "override", "secret_missing", "malformed"])
def test_managed_connection_fails_closed(configured, monkeypatch, case):
    config, path, secret = configured
    tenant, provider = "tenant-a", "langfuse"
    body = {"connection_id": "production", "screen_content": False}
    if case == "tenant":
        tenant = "tenant-b"
    if case == "provider":
        provider = "langsmith"
    if case == "disabled":
        config["production"]["enabled"] = False
    if case == "expired":
        config["production"]["expires_at"] = "2000-01-01T00:00:00Z"
    if case == "unknown":
        body["connection_id"] = "unknown"
    if case == "override":
        body["credentials"] = {"host": "https://attacker.example"}
    if case == "secret_missing":
        secret.unlink()
    path.write_text("{" if case == "malformed" else json.dumps(config))
    monkeypatch.setattr("agent_bom.trace_connectors.fetch_traces", lambda *a, **kw: pytest.fail("must not contact provider"))
    with pytest.raises(HTTPException) as caught:
        routes.pull_trace_connector(request(tenant), provider, body)
    assert caught.value.status_code in {400, 404, 503}
    assert "fixture-secret" not in caught.value.detail
    assert str(secret) not in caught.value.detail


def test_managed_connection_http_auth_and_tenant_boundary(configured, monkeypatch):
    from starlette.testclient import TestClient

    from agent_bom.api.server import app, configure_api
    from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

    calls = []
    from agent_bom.trace_connectors import NativeTracePage

    monkeypatch.setattr("agent_bom.trace_connectors.resolve_trace_project", lambda *a, **kw: "project-id")
    monkeypatch.setattr(
        "agent_bom.trace_connectors.fetch_trace_page",
        lambda *a, **kw: calls.append(a) or NativeTracePage({"spans": []}, None, 0),
    )
    enable_trusted_proxy_env()
    configure_api(api_key="fixture-api-auth-required")
    try:
        client = TestClient(app)
        endpoint = "/v1/traces/connectors/langfuse/pull"
        body = {"connection_id": "production", "screen_content": False}
        assert client.post(endpoint, json=body).status_code in {401, 403}
        assert client.post(endpoint, json=body, headers=proxy_headers(role="viewer", tenant="tenant-a")).status_code == 403
        assert client.post(endpoint, json=body, headers=proxy_headers(role="admin", tenant="tenant-b")).status_code == 404
        response = client.post(endpoint, json=body, headers=proxy_headers(role="admin", tenant="tenant-a"))
        assert response.status_code == 200, response.text
        assert "fixture-secret" not in response.text
        assert len(calls) == 1
    finally:
        disable_trusted_proxy_env()


def test_langsmith_project_scope_is_operator_bound(configured, monkeypatch):
    config, path, secret = configured
    config["production"].update(provider="langsmith", endpoint="https://api.smith.langchain.com", project="production")
    path.write_text(json.dumps(config))
    secret.write_text(json.dumps({"api_key": "fixture-secret"}))
    calls = []
    from agent_bom.trace_connectors import NativeTracePage

    monkeypatch.setattr("agent_bom.trace_connectors.resolve_trace_project", lambda *a, **kw: "project-id")
    monkeypatch.setattr(
        "agent_bom.trace_connectors.fetch_trace_page",
        lambda provider, credentials, **kw: calls.append(credentials) or NativeTracePage({"spans": []}, None, 0),
    )
    routes.pull_trace_connector(request(), "langsmith", {"connection_id": "production", "screen_content": False})
    assert calls == [{"api_url": "https://api.smith.langchain.com", "project": "production", "api_key": "fixture-secret"}]


def test_managed_use_audit_contains_identity_not_secrets(configured, monkeypatch):
    audit = []
    from agent_bom.trace_connectors import NativeTracePage

    monkeypatch.setattr("agent_bom.trace_connectors.resolve_trace_project", lambda *a, **kw: "project-id")
    monkeypatch.setattr(
        "agent_bom.trace_connectors.fetch_trace_page", lambda *a, **kw: NativeTracePage({"spans": []}, None, 0)
    )
    monkeypatch.setattr("agent_bom.api.trace_connection_broker.log_action", lambda action, **kwargs: audit.append((action, kwargs)))
    monkeypatch.setattr("agent_bom.api.audit_log.log_action", lambda action, **kwargs: audit.append((action, kwargs)))
    routes.pull_trace_connector(request(), "langfuse", {"connection_id": "production", "screen_content": False})
    assert [event for event, _ in audit] == ["trace_connection.use", "trace_import.pull"]
    assert audit[-1][1]["outcome"] == "complete"
    assert "fixture-secret" not in json.dumps(audit)
