"""Snowflake governance and Cortex reads spend the control plane's own identity.

``/v1/governance``, ``/v1/governance/findings`` and ``/v1/cortex/*`` connect
with the API process's ``SNOWFLAKE_*`` credentials, not a tenant's stored
connection. They follow the same contract as the ambient CIS benchmark:

* off unless an operator sets ``AGENT_BOM_SNOWFLAKE_GOVERNANCE``,
* admin only (``cloud_ambient``), whatever tenant the caller belongs to,
* hidden on the public demo,
* fixed error text, never provider SDK messages.

``/v1/activity`` stays a viewer read for runtime events, but only includes the
operator's Snowflake query history under the same opt-in and permission.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from starlette.testclient import TestClient

from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_OPT_IN = "AGENT_BOM_SNOWFLAKE_GOVERNANCE"
_SDK_SECRET_TEXT = "250001: Could not connect to Snowflake backend for account opsacct-xyz as user SVC_GOV"

AMBIENT_GOVERNANCE_PATHS = (
    "/v1/governance",
    "/v1/governance/findings",
    "/v1/cortex/telemetry",
    "/v1/cortex/agents/claims-agent/telemetry",
    "/v1/cortex/health",
)


class _Calls:
    def __init__(self) -> None:
        self.count = 0


class _Report:
    findings: list[Any] = []
    warnings: list[str] = []

    def to_dict(self) -> dict[str, Any]:
        return {"account": "opsacct", "findings": [], "warnings": []}


class _Conn:
    def close(self) -> None:
        return None


@pytest.fixture
def client() -> Iterator[TestClient]:
    set_job_store(InMemoryJobStore())
    enable_trusted_proxy_env()
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        disable_trusted_proxy_env()


@pytest.fixture
def snowflake_stub(monkeypatch: pytest.MonkeyPatch) -> _Calls:
    """Stub every warehouse entry point and count how often one is reached."""
    import agent_bom.cloud as cloud_mod
    from agent_bom.cloud import snowflake as snowflake_mod
    from agent_bom.cloud import snowflake_observability as observability_mod

    calls = _Calls()

    def _governance(**_: Any) -> _Report:
        calls.count += 1
        return _Report()

    def _connection(*_: Any, **__: Any) -> _Conn:
        calls.count += 1
        return _Conn()

    def _activity(**_: Any) -> Any:
        calls.count += 1

        class _Timeline:
            def to_dict(self) -> dict[str, Any]:
                return {"events": [{"observed_at": "2026-11-01T00:00:00+00:00", "query_id": "q1"}]}

        return _Timeline()

    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "opsacct")
    monkeypatch.setattr(cloud_mod, "discover_governance", _governance)
    monkeypatch.setattr(cloud_mod, "discover_activity", _activity)
    monkeypatch.setattr(snowflake_mod, "_get_connection", _connection)
    monkeypatch.setattr(snowflake_mod, "_mine_cortex_agent_usage", lambda conn, days: ([], []))
    monkeypatch.setattr(observability_mod, "get_cortex_telemetry", lambda conn, **_: {"agents": [], "warnings": []})
    return calls


@pytest.mark.parametrize("path", AMBIENT_GOVERNANCE_PATHS)
@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_non_admin_in_another_tenant_cannot_read_operator_warehouse(
    client: TestClient, snowflake_stub: _Calls, monkeypatch: pytest.MonkeyPatch, path: str, role: str
) -> None:
    monkeypatch.setenv(_OPT_IN, "1")

    response = client.get(path, headers=proxy_headers(role=role, tenant="tenant-other"))

    assert response.status_code == 403
    assert snowflake_stub.count == 0


@pytest.mark.parametrize("path", AMBIENT_GOVERNANCE_PATHS)
def test_admin_without_operator_opt_in_gets_a_fixed_disabled_answer(
    client: TestClient, snowflake_stub: _Calls, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    monkeypatch.delenv(_OPT_IN, raising=False)

    response = client.get(path, headers=proxy_headers(role="admin", tenant="tenant-alpha"))

    assert response.status_code == 404
    detail = response.json()["detail"]
    assert _OPT_IN in detail
    assert "opsacct" not in detail
    assert snowflake_stub.count == 0


@pytest.mark.parametrize("path", AMBIENT_GOVERNANCE_PATHS)
def test_admin_with_opt_in_reads_the_operator_warehouse(
    client: TestClient, snowflake_stub: _Calls, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    monkeypatch.setenv(_OPT_IN, "1")

    response = client.get(path, headers=proxy_headers(role="admin", tenant="tenant-alpha"))

    assert response.status_code == 200, response.text
    assert snowflake_stub.count >= 1


@pytest.mark.parametrize("path", AMBIENT_GOVERNANCE_PATHS)
def test_warehouse_failures_return_fixed_text(client: TestClient, monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    import agent_bom.cloud as cloud_mod
    from agent_bom.cloud import snowflake as snowflake_mod

    def _boom(*_: Any, **__: Any) -> Any:
        raise RuntimeError(_SDK_SECRET_TEXT)

    monkeypatch.setenv(_OPT_IN, "1")
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "opsacct")
    monkeypatch.setattr(cloud_mod, "discover_governance", _boom)
    monkeypatch.setattr(snowflake_mod, "_get_connection", _boom)

    response = client.get(path, headers=proxy_headers(role="admin", tenant="tenant-alpha"))

    assert response.status_code == 500
    assert "opsacct" not in response.text
    assert "SVC_GOV" not in response.text
    assert "250001" not in response.text


@pytest.mark.parametrize("path", AMBIENT_GOVERNANCE_PATHS)
def test_public_demo_hides_every_warehouse_read(
    client: TestClient, snowflake_stub: _Calls, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    import agent_bom.demo_estate.bootstrap as bootstrap

    monkeypatch.setenv(_OPT_IN, "1")
    monkeypatch.setattr(bootstrap, "demo_estate_enabled", lambda: True)

    response = client.get(path, headers=proxy_headers(role="admin", tenant="tenant-alpha"))

    assert response.status_code == 404
    assert "public demo" in response.json()["detail"]
    assert snowflake_stub.count == 0


@pytest.mark.parametrize("path", AMBIENT_GOVERNANCE_PATHS)
def test_route_policy_requires_admin(path: str) -> None:
    from agent_bom.api.route_policy import required_role

    assert required_role("GET", path) == "admin"


def test_blueprints_stay_a_viewer_read() -> None:
    """Stored, tenant-scoped blueprints are not ambient reads."""
    from agent_bom.api.route_policy import required_role

    assert required_role("GET", "/v1/governance/blueprints") == "viewer"
    assert required_role("GET", "/v1/governance/blueprints/bp-1/diff") == "viewer"


def _snowflake_source(body: dict[str, Any]) -> dict[str, Any]:
    return next(source for source in body["sources"] if source["source"] == "snowflake")


@pytest.mark.parametrize("role", ["viewer", "analyst"])
def test_activity_omits_operator_query_history_for_non_admins(
    client: TestClient, snowflake_stub: _Calls, monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    monkeypatch.setenv(_OPT_IN, "1")

    response = client.get("/v1/activity", headers=proxy_headers(role=role, tenant="tenant-other"))

    assert response.status_code == 200
    source = _snowflake_source(response.json())
    assert source["status"] == "not_configured"
    assert source["event_count"] == 0
    assert "timeline" not in source
    assert snowflake_stub.count == 0


def test_activity_omits_operator_query_history_without_opt_in(
    client: TestClient, snowflake_stub: _Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(_OPT_IN, raising=False)

    response = client.get("/v1/activity", headers=proxy_headers(role="admin", tenant="tenant-alpha"))

    assert response.status_code == 200
    source = _snowflake_source(response.json())
    assert source["status"] == "not_configured"
    assert _OPT_IN in source["detail"]
    assert snowflake_stub.count == 0


def test_activity_includes_query_history_for_opted_in_admin(
    client: TestClient, snowflake_stub: _Calls, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_OPT_IN, "1")

    response = client.get("/v1/activity", headers=proxy_headers(role="admin", tenant="tenant-alpha"))

    assert response.status_code == 200
    source = _snowflake_source(response.json())
    assert source["status"] == "active"
    assert source["event_count"] == 1
    assert snowflake_stub.count == 1


def test_activity_source_failure_uses_fixed_text(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_bom.cloud as cloud_mod

    def _boom(**_: Any) -> Any:
        raise RuntimeError(_SDK_SECRET_TEXT)

    monkeypatch.setenv(_OPT_IN, "1")
    monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "opsacct")
    monkeypatch.setattr(cloud_mod, "discover_activity", _boom)

    response = client.get("/v1/activity", headers=proxy_headers(role="admin", tenant="tenant-alpha"))

    assert response.status_code == 200
    source = _snowflake_source(response.json())
    assert source["status"] == "unavailable"
    assert "SVC_GOV" not in response.text
    assert "250001" not in response.text


@pytest.mark.parametrize("path", AMBIENT_GOVERNANCE_PATHS)
def test_tenant_binding_refuses_admins_of_other_tenants(
    client: TestClient, snowflake_stub: _Calls, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    monkeypatch.setenv(_OPT_IN, "1")
    monkeypatch.setenv("AGENT_BOM_AMBIENT_CREDENTIALS_TENANT", "tenant-alpha")

    assert client.get(path, headers=proxy_headers(role="admin", tenant="tenant-beta")).status_code == 403
    assert snowflake_stub.count == 0
    assert client.get(path, headers=proxy_headers(role="admin", tenant="tenant-alpha")).status_code == 200


def test_activity_tenant_binding_omits_query_history(client: TestClient, snowflake_stub: _Calls, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_OPT_IN, "1")
    monkeypatch.setenv("AGENT_BOM_AMBIENT_CREDENTIALS_TENANT", "tenant-alpha")

    response = client.get("/v1/activity", headers=proxy_headers(role="admin", tenant="tenant-beta"))

    assert _snowflake_source(response.json())["status"] == "not_configured"
    assert snowflake_stub.count == 0
