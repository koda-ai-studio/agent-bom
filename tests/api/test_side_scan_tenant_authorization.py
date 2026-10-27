"""A tenant administrator must not select disks through ambient cloud credentials."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.routes import cloud
from agent_bom.api.server import app, configure_api


@pytest.mark.parametrize("connection_id", [None, "another-tenants-connection"])
def test_side_scan_without_tenant_owned_connection_never_calls_provider(monkeypatch, connection_id):
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", "test-only-proxy-secret-longer-than-32")
    monkeypatch.setenv("AGENT_BOM_SIDESCAN", "1")
    configure_api(api_key=None)
    calls = []
    monkeypatch.setattr(cloud, "_run_provider_side_scan_sync", lambda **kw: calls.append(kw) or [])
    body = {
        "provider": "gcp",
        "account_id": "other-project",
        "target_id": "projects/other-project/zones/us-central1-a/disks/os",
        "location": "us-central1-a",
        "collector_id": "collector",
    }
    if connection_id is not None:
        body["connection_id"] = connection_id
    with TestClient(app) as client:
        response = client.post(
            "/v1/cloud/side-scan",
            json=body,
            headers={
                "X-Agent-Bom-Role": "admin",
                "X-Agent-Bom-Tenant-ID": "tenant-a",
                "X-Agent-Bom-Proxy-Secret": "test-only-proxy-secret-longer-than-32",
            },
        )
    assert calls == []
    assert response.status_code in {403, 404, 422}
