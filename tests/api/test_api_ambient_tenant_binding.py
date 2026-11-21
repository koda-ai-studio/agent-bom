"""``AGENT_BOM_AMBIENT_CREDENTIALS_TENANT`` confines every ambient surface to one tenant.

A multi-tenant operator binds the control plane's own identity to the tenant
that owns it; admins of any other tenant are refused, whatever their role.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_TENANT = "AGENT_BOM_AMBIENT_CREDENTIALS_TENANT"
OWNER = proxy_headers(role="admin", tenant="tenant-alpha")
OTHER = proxy_headers(role="admin", tenant="tenant-beta")


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv(_TENANT, "tenant-alpha")
    set_job_store(InMemoryJobStore())
    enable_trusted_proxy_env()
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        disable_trusted_proxy_env()


def test_cis_benchmark_is_bound_to_the_owning_tenant(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_CLOUD_CIS_BENCHMARK", "1")
    with patch("agent_bom.api.routes.cloud._run_cis_benchmark", return_value={"status": "ok"}) as runner:
        assert client.get("/v1/cloud/aws/cis-benchmark", headers=OTHER).status_code == 403
        runner.assert_not_called()
        assert client.get("/v1/cloud/aws/cis-benchmark", headers=OWNER).status_code == 200


def test_idp_discovery_is_bound_to_the_owning_tenant(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []
    monkeypatch.setattr("agent_bom.identity.discover_okta_non_human_identities", lambda: calls.append("okta") or {"identities": []})
    monkeypatch.setattr("agent_bom.identity.discover_entra_non_human_identities", lambda: calls.append("entra") or {"identities": []})

    assert client.post("/v1/identities/discover", json={}, headers=OTHER).status_code == 403
    assert client.post("/v1/identities/access-reviews", json={"name": "q4"}, headers=OTHER).status_code == 403
    assert calls == []


def test_credential_expiry_skips_idp_discovery_for_other_tenants(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr("agent_bom.api.routes.enterprise_routes.trials._discover_nhi_credentials", lambda: calls.append("nhi") or [])

    assert client.get("/v1/auth/secrets/credential-expiry", headers=OTHER).status_code == 200
    assert calls == []
    client.get("/v1/auth/secrets/credential-expiry", headers=OWNER)
    assert calls == ["nhi"]
