"""The HTTP contract rejects anonymous, wrong-tenant and override requests."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from agent_bom.api.runtime_event_store import SQLiteRuntimeEventStore, set_runtime_event_store
from agent_bom.api.server import app, configure_api
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


@pytest.fixture
def client(monkeypatch, tmp_path):
    config = {
        "production": {
            "tenant_id": "tenant-a",
            "provider": "langfuse",
            "display_name": "Production",
            "endpoint": "https://cloud.langfuse.com",
            "credentials_env": "TRACE_TEST_CREDENTIALS",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        }
    }
    monkeypatch.setenv("AGENT_BOM_TRACE_CONNECTIONS", json.dumps(config))
    monkeypatch.setenv("TRACE_TEST_CREDENTIALS", json.dumps({"public_key": "test-public", "secret_key": "test-secret"}))
    set_runtime_event_store(SQLiteRuntimeEventStore(str(tmp_path / "runtime.db")))
    enable_trusted_proxy_env()
    configure_api(api_key="fixture-auth-required")
    try:
        yield TestClient(app)
    finally:
        disable_trusted_proxy_env()
        set_runtime_event_store(None)


URL = "/v1/traces/connectors/langfuse/collect"
STATUS = "/v1/traces/connectors/langfuse/collection?connection_id=production"


def test_auth_and_strict_body(client, monkeypatch):
    monkeypatch.setattr("agent_bom.api.trace_collection.service.fetch_page", lambda *a: pytest.fail("must not call provider"))
    assert client.post(URL, json={"connection_id": "production"}).status_code in {401, 403}
    assert (
        client.post(URL, json={"connection_id": "production"}, headers=proxy_headers(role="viewer", tenant="tenant-a")).status_code == 403
    )
    assert client.post(URL, json={"connection_id": "production"}, headers=proxy_headers(role="admin", tenant="tenant-b")).status_code == 404
    assert (
        client.post(
            URL, json={"connection_id": "production", "cursor": "injected"}, headers=proxy_headers(role="admin", tenant="tenant-a")
        ).status_code
        == 422
    )


def test_persisted_status_and_no_internal_checkpoint_exposure(client, monkeypatch):
    monkeypatch.setattr("agent_bom.api.trace_collection.service.fetch_page", lambda *a: ([], "provider-cursor-private"))
    headers = proxy_headers(role="admin", tenant="tenant-a")
    response = client.post(URL, json={"connection_id": "production"}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "partial"
    status = client.get(STATUS, headers=headers)
    assert status.status_code == 200, status.text
    assert status.json()["pages"] == 1
    assert not any(secret in status.text for secret in ("provider-cursor-private", "test-secret", "scope_digest", "owner"))


def test_rate_limit_receipt_preserves_progress_and_backoff(client, monkeypatch):
    from agent_bom.api.trace_collection.langfuse import ProviderFailureError

    def fail(*args):
        raise ProviderFailureError("rate_limited", retry_after=900)

    monkeypatch.setattr("agent_bom.api.trace_collection.service.fetch_page", fail)
    headers = proxy_headers(role="admin", tenant="tenant-a")
    response = client.post(URL, json={"connection_id": "production"}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "failed"
    assert response.json()["retry_after_seconds"] >= 899
    assert response.json()["last_error"] == "rate_limited"
    assert client.post(URL, json={"connection_id": "production"}, headers=headers).status_code == 409


def test_revocation_during_fetch_prevents_commit(client, monkeypatch):
    from fastapi import HTTPException

    from agent_bom.api.trace_collection import service

    credentials = service.pull_credentials
    calls = 0

    def resolve(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise HTTPException(status_code=404, detail="Connection revoked")
        return credentials(*args, **kwargs)

    monkeypatch.setattr(service, "pull_credentials", resolve)
    monkeypatch.setattr(service, "fetch_page", lambda *a: ([], "new-cursor"))
    response = client.post(URL, json={"connection_id": "production"}, headers=proxy_headers(role="admin", tenant="tenant-a"))
    assert response.status_code == 200
    assert response.json()["status"] == "failed"
    assert response.json()["pages"] == 0
