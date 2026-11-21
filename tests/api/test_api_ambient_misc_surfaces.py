"""KSPM live posture, connector health and model provenance use server credentials only on opt-in.

* ``POST /v1/kspm/clusters/posture`` reads the cluster with the API server's
  service account or kubeconfig; a caller may choose only an operator-listed
  kubeconfig context.
* ``GET /v1/connectors/{name}/health`` would call Jira / ServiceNow / Slack
  with server tokens; other callers get a ``disabled`` state without any call.
* ``POST /v1/scan/model-provenance`` would send the server's ``HF_TOKEN`` and
  probe its Ollama host; other callers get anonymous Hub reads and no Ollama.
"""

from __future__ import annotations

import sys
import types
from collections.abc import Iterator
from types import SimpleNamespace
from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_K8S = "AGENT_BOM_API_K8S_SCANS"
_CONTEXTS = "AGENT_BOM_API_K8S_CONTEXTS"
_CONNECTORS = "AGENT_BOM_API_CONNECTOR_SCANS"
_MODEL_HUB = "AGENT_BOM_API_MODEL_HUB_CREDENTIALS"
_TENANT = "AGENT_BOM_AMBIENT_CREDENTIALS_TENANT"

ADMIN = proxy_headers(role="admin", tenant="tenant-alpha")
ANALYST = proxy_headers(role="analyst", tenant="tenant-alpha")
VIEWER = proxy_headers(role="viewer", tenant="tenant-beta")
OTHER_ADMIN = proxy_headers(role="admin", tenant="tenant-beta")


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    for name in (_K8S, _CONTEXTS, _CONNECTORS, _MODEL_HUB, _TENANT):
        monkeypatch.delenv(name, raising=False)
    set_job_store(InMemoryJobStore())
    enable_trusted_proxy_env()
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        disable_trusted_proxy_env()


@pytest.fixture
def posture_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    from agent_bom.api.routes import kspm

    calls: list[dict[str, Any]] = []

    def _collect(**kwargs: Any) -> Any:
        calls.append(kwargs)
        raise RuntimeError("stop after admission")

    monkeypatch.setattr(kspm, "_collect_posture", _collect)
    return calls


# ── KSPM ──────────────────────────────────────────────────────────────────────


def test_kspm_analyst_is_refused(client: TestClient, posture_calls: list, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_K8S, "1")

    assert client.post("/v1/kspm/clusters/posture", json={}, headers=ANALYST).status_code == 403
    assert posture_calls == []


def test_kspm_admin_without_opt_in_is_disabled(client: TestClient, posture_calls: list) -> None:
    response = client.post("/v1/kspm/clusters/posture", json={}, headers=ADMIN)

    assert response.status_code == 404
    assert _K8S in response.json()["detail"]
    assert posture_calls == []


def test_kspm_tenant_binding(client: TestClient, posture_calls: list, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_K8S, "1")
    monkeypatch.setenv(_TENANT, "tenant-alpha")

    assert client.post("/v1/kspm/clusters/posture", json={}, headers=OTHER_ADMIN).status_code == 403
    assert posture_calls == []


def test_kspm_rejects_contexts_outside_the_operator_list(client: TestClient, posture_calls: list, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_K8S, "1")

    unlisted = client.post("/v1/kspm/clusters/posture", json={"context": "prod-admin"}, headers=ADMIN)
    assert unlisted.status_code == 400
    assert _CONTEXTS in unlisted.json()["detail"]

    monkeypatch.setenv(_CONTEXTS, "staging, dev")
    assert client.post("/v1/kspm/clusters/posture", json={"context": "prod-admin"}, headers=ADMIN).status_code == 400
    assert posture_calls == []

    allowed = client.post("/v1/kspm/clusters/posture", json={"context": "staging"}, headers=ADMIN)
    assert allowed.status_code == 500  # reached the stubbed collector
    assert posture_calls[-1]["context"] == "staging"


def test_kspm_default_context_runs_for_opted_in_admin(client: TestClient, posture_calls: list, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_K8S, "1")

    client.post("/v1/kspm/clusters/posture", json={}, headers=ADMIN)

    assert posture_calls and posture_calls[-1]["context"] is None


def test_kspm_latest_posture_read_stays_a_viewer_read(client: TestClient) -> None:
    assert client.get("/v1/kspm/clusters/posture", headers=VIEWER).status_code == 200


# ── Connector health ──────────────────────────────────────────────────────────


@pytest.fixture
def health_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    from agent_bom.connectors.base import ConnectorHealthState, ConnectorStatus

    calls: list[str] = []

    def _check(name: str) -> ConnectorStatus:
        calls.append(name)
        return ConnectorStatus(connector=name, state=ConnectorHealthState.HEALTHY, message="ok", api_version="3")

    monkeypatch.setattr("agent_bom.connectors.check_connector_health", _check)
    return calls


@pytest.mark.parametrize("headers", [VIEWER, ANALYST], ids=["viewer-other-tenant", "analyst"])
def test_connector_health_never_calls_out_for_non_admins(
    client: TestClient, health_calls: list, monkeypatch: pytest.MonkeyPatch, headers: dict
) -> None:
    monkeypatch.setenv(_CONNECTORS, "1")

    response = client.get("/v1/connectors/jira/health", headers=headers)

    assert response.status_code == 200
    assert response.json()["state"] == "disabled"
    assert health_calls == []


def test_connector_health_needs_the_operator_flag(client: TestClient, health_calls: list) -> None:
    body = client.get("/v1/connectors/jira/health", headers=ADMIN).json()

    assert body["state"] == "disabled"
    assert _CONNECTORS in body["message"]
    assert health_calls == []


def test_connector_health_for_opted_in_admin(client: TestClient, health_calls: list, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_CONNECTORS, "1")

    body = client.get("/v1/connectors/jira/health", headers=ADMIN).json()

    assert body["state"] == "healthy"
    assert health_calls == ["jira"]


def test_unknown_connector_is_still_404(client: TestClient, health_calls: list) -> None:
    assert client.get("/v1/connectors/nope/health", headers=VIEWER).status_code == 404


# ── Model provenance ─────────────────────────────────────────────────────────


@pytest.fixture
def hub(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    # A stub module, so these tests run without the optional huggingface extra installed.
    huggingface_hub = types.ModuleType("huggingface_hub")
    hub_utils = types.ModuleType("huggingface_hub.utils")
    hub_utils.GatedRepoError = type("GatedRepoError", (Exception,), {})
    hub_utils.RepositoryNotFoundError = type("RepositoryNotFoundError", (Exception,), {})
    huggingface_hub.utils = hub_utils
    monkeypatch.setitem(sys.modules, "huggingface_hub", huggingface_hub)
    monkeypatch.setitem(sys.modules, "huggingface_hub.utils", hub_utils)

    tokens: list[Any] = []

    class _Api:
        def __init__(self, token: Any = None) -> None:
            tokens.append(token)

        def model_info(self, *_: Any, **__: Any) -> Any:
            return SimpleNamespace(gated=False, private=False, siblings=[], card_data=None, cardData=None, safetensors=None)

    huggingface_hub.HfApi = _Api
    monkeypatch.setenv("HF_TOKEN", "hf_placeholder_for_test")
    return tokens


def test_model_provenance_is_anonymous_for_non_admins(client: TestClient, hub: list, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_MODEL_HUB, "1")

    response = client.post("/v1/scan/model-provenance", json={"hf_models": ["org/model"]}, headers=ANALYST)

    assert response.status_code == 200
    assert hub == [False]


def test_model_provenance_is_anonymous_without_opt_in(client: TestClient, hub: list) -> None:
    client.post("/v1/scan/model-provenance", json={"hf_models": ["org/model"]}, headers=ADMIN)

    assert hub == [False]


def test_model_provenance_uses_server_token_for_opted_in_admin(client: TestClient, hub: list, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_MODEL_HUB, "1")

    client.post("/v1/scan/model-provenance", json={"hf_models": ["org/model"]}, headers=ADMIN)

    assert hub == ["hf_placeholder_for_test"]


def test_ollama_probe_needs_opt_in_and_admin(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    probes: list[str] = []
    monkeypatch.setattr("agent_bom.cloud.model_provenance._get_ollama_manifest_api", lambda host, name: probes.append(name))

    assert client.post("/v1/scan/model-provenance", json={"ollama_models": ["llama3"]}, headers=ADMIN).status_code == 403
    monkeypatch.setenv(_MODEL_HUB, "1")
    assert client.post("/v1/scan/model-provenance", json={"ollama_models": ["llama3"]}, headers=ANALYST).status_code == 403
    assert probes == []
    assert client.post("/v1/scan/model-provenance", json={"ollama_models": ["llama3"]}, headers=ADMIN).status_code == 200
    assert probes == ["llama3"]
