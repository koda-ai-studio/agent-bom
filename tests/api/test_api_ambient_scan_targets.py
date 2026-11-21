"""Scan targets that spend the API server's own credentials are opt-in and admin-only.

``k8s: true`` reads the cluster with the server's service account or
kubeconfig; ``connectors`` call Jira / ServiceNow / Slack with tokens from the
server environment. Neither belongs to the tenant sending the request, so every
entry point (POST /v1/scan, sources, schedules) requires an operator flag, the
``cloud_ambient`` permission, and the bound tenant when one is configured, and
queued or scheduled work rechecks the flag before it runs.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException
from starlette.testclient import TestClient

from agent_bom.api import stores as _stores
from agent_bom.api.credential_store import InMemoryCredentialRefStore
from agent_bom.api.idempotency_store import InMemoryIdempotencyStore
from agent_bom.api.models import SourceKind, SourceRecord
from agent_bom.api.schedule_store import InMemoryScheduleStore
from agent_bom.api.server import app, configure_api
from agent_bom.api.source_store import InMemorySourceStore
from agent_bom.api.store import InMemoryJobStore
from tests.auth_helpers import PROXY_SECRET, proxy_headers

_K8S = "AGENT_BOM_API_K8S_SCANS"
_CONNECTORS = "AGENT_BOM_API_CONNECTOR_SCANS"
_TENANT = "AGENT_BOM_AMBIENT_CREDENTIALS_TENANT"

ADMIN = proxy_headers(role="admin", tenant="tenant-alpha")
ANALYST = proxy_headers(role="analyst", tenant="tenant-alpha")
OTHER_ADMIN = proxy_headers(role="admin", tenant="tenant-beta")

AMBIENT_BODIES = (
    pytest.param({"k8s": True}, _K8S, id="k8s"),
    pytest.param({"connectors": ["jira"]}, _CONNECTORS, id="connectors"),
)


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    old = (_stores._source_store, _stores._credential_ref_store, _stores._store, _stores._idempotency_store, _stores._schedule_store)
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    for name in (_K8S, _CONNECTORS, _TENANT):
        monkeypatch.delenv(name, raising=False)
    configure_api(api_key=None)
    _stores.set_source_store(InMemorySourceStore())
    _stores.set_credential_ref_store(InMemoryCredentialRefStore())
    _stores.set_job_store(InMemoryJobStore())
    _stores.set_idempotency_store(InMemoryIdempotencyStore())
    _stores.set_schedule_store(InMemoryScheduleStore())
    queued: list[Any] = []
    monkeypatch.setattr("agent_bom.api.scan_job_dispatch.submit_scan_job", queued.append)
    try:
        with TestClient(app) as test_client:
            test_client.queued = queued  # type: ignore[attr-defined]
            yield test_client
    finally:
        monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH", raising=False)
        configure_api(api_key=None)
        (_stores._source_store, _stores._credential_ref_store, _stores._store, _stores._idempotency_store, _stores._schedule_store) = old


@pytest.mark.parametrize(("body", "flag"), AMBIENT_BODIES)
def test_analyst_cannot_scan_with_server_credentials(client: TestClient, monkeypatch: pytest.MonkeyPatch, body: dict, flag: str) -> None:
    monkeypatch.setenv(flag, "1")

    response = client.post("/v1/scan", json=body, headers=ANALYST)

    assert response.status_code == 403
    assert "admins" in response.json()["detail"]
    assert client.queued == []  # type: ignore[attr-defined]


@pytest.mark.parametrize(("body", "flag"), AMBIENT_BODIES)
def test_admin_needs_the_operator_flag(client: TestClient, body: dict, flag: str) -> None:
    response = client.post("/v1/scan", json=body, headers=ADMIN)

    assert response.status_code == 403
    assert flag in response.json()["detail"]
    assert client.queued == []  # type: ignore[attr-defined]


@pytest.mark.parametrize(("body", "flag"), AMBIENT_BODIES)
def test_admin_with_flag_can_scan(client: TestClient, monkeypatch: pytest.MonkeyPatch, body: dict, flag: str) -> None:
    monkeypatch.setenv(flag, "1")

    response = client.post("/v1/scan", json=body, headers=ADMIN)

    assert response.status_code == 202, response.text


@pytest.mark.parametrize(("body", "flag"), AMBIENT_BODIES)
def test_tenant_binding_refuses_admins_of_other_tenants(client: TestClient, monkeypatch: pytest.MonkeyPatch, body: dict, flag: str) -> None:
    monkeypatch.setenv(flag, "1")
    monkeypatch.setenv(_TENANT, "tenant-alpha")

    assert client.post("/v1/scan", json=body, headers=OTHER_ADMIN).status_code == 403
    assert client.post("/v1/scan", json=body, headers=ADMIN).status_code == 202


def test_ordinary_scans_are_unaffected(client: TestClient) -> None:
    response = client.post("/v1/scan", json={"images": ["alpine:3.20"]}, headers=ANALYST)

    assert response.status_code == 202, response.text


def _connector_source_body() -> dict[str, Any]:
    return {
        "display_name": "Jira",
        "kind": "connector.cloud_read_only",
        "owner": "platform-security",
        "connector_name": "jira",
        "credential_mode": "none",
    }


def test_analyst_cannot_store_a_connector_source(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_CONNECTORS, "1")

    assert client.post("/v1/sources", json=_connector_source_body(), headers=ANALYST).status_code == 403
    assert client.post("/v1/sources", json=_connector_source_body(), headers=ADMIN).status_code == 201


def _store_source(**config: Any) -> SourceRecord:
    source = SourceRecord(
        source_id="ambient-src",
        tenant_id="tenant-alpha",
        display_name="Ambient",
        kind=SourceKind.SCAN_IAC,
        config={"scan_request": config},
    )
    _stores._get_source_store().put(source, tenant_id="tenant-alpha")
    return source


def test_stored_k8s_source_cannot_be_run_or_tested_by_an_analyst(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_K8S, "1")
    _store_source(k8s=True)

    assert client.post("/v1/sources/ambient-src/run", headers=ANALYST).status_code == 403
    assert client.post("/v1/sources/ambient-src/test", headers=ANALYST).status_code == 403
    assert client.queued == []  # type: ignore[attr-defined]
    assert client.post("/v1/sources/ambient-src/run", headers=ADMIN).status_code == 202


def test_connector_source_test_does_not_reach_the_service_for_analysts(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_CONNECTORS, "1")
    calls: list[str] = []
    monkeypatch.setattr("agent_bom.connectors.check_connector_health", lambda name: calls.append(name))
    source = SourceRecord(
        source_id="jira-src",
        tenant_id="tenant-alpha",
        display_name="Jira",
        kind=SourceKind.CONNECTOR_CLOUD_READ_ONLY,
        connector_name="jira",
    )
    _stores._get_source_store().put(source, tenant_id="tenant-alpha")

    assert client.post("/v1/sources/jira-src/test", headers=ANALYST).status_code == 403
    assert calls == []


def test_inline_schedule_with_k8s_needs_an_ambient_caller(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.routes.schedules import _validate_enabled_source_schedule

    monkeypatch.setenv(_K8S, "1")
    with pytest.raises(HTTPException) as rejected:
        _validate_enabled_source_schedule("tenant-alpha", {"k8s": True}, ambient_caller=False)
    assert rejected.value.status_code == 403
    _validate_enabled_source_schedule("tenant-alpha", {"k8s": True}, ambient_caller=True)


@pytest.mark.parametrize(("config", "flag"), [({"k8s": True}, _K8S), ({"connectors": ["slack"]}, _CONNECTORS)])
def test_scheduled_scan_rechecks_the_flag_before_queueing(monkeypatch: pytest.MonkeyPatch, config: dict, flag: str) -> None:
    from agent_bom.api.server import _enqueue_scheduled_scan
    from agent_bom.security import SecurityError

    monkeypatch.delenv(flag, raising=False)
    queued: list[Any] = []
    monkeypatch.setattr("agent_bom.api.scan_job_submission.enqueue_scan_job", lambda **kw: queued.append(kw) or SimpleNamespace(job_id="x"))

    with pytest.raises(SecurityError, match=flag):
        _enqueue_scheduled_scan(config, tenant_id="tenant-alpha")
    assert queued == []


def test_queued_job_rechecks_the_flag_before_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.models import ScanRequest
    from agent_bom.api.scan_discovery_stages import prepare_request

    monkeypatch.delenv(_K8S, raising=False)
    ctx = SimpleNamespace(req=ScanRequest(k8s=True), job=SimpleNamespace(tenant_id="tenant-alpha", job_id="j1"))

    with pytest.raises(RuntimeError, match=_K8S):
        prepare_request(ctx)  # type: ignore[arg-type]
