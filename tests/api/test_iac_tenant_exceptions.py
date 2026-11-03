"""Tenant IaC exceptions: request, four-eyes approval, tenant scoping, and application to repo scans."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores
from agent_bom.api.auth import KeyStore, Role, create_api_key, get_key_store, set_key_store
from agent_bom.api.exception_store import ExceptionStatus, InMemoryExceptionStore, SQLiteExceptionStore, VulnException
from agent_bom.api.server import app, configure_api
from agent_bom.api.suppression_approval import activate_suppression, approval_error, suppression_active
from agent_bom.suppression_rules import tenant_iac_exceptions

POD = """apiVersion: v1
kind: Pod
metadata:
  name: node-debugger
  namespace: ops
spec:
  containers:
    - name: app
      image: nginx:1.25@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      securityContext:
        privileged: true
"""


def _in_days(days: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def _iac(tenant: str = "tenant-a", **overrides) -> VulnException:
    fields = {
        "iac_rule_id": "K8S-001",
        "iac_path": "k8s/*.yaml",
        "iac_resource": {"kind": "Pod", "name": "node-debugger"},
        "reason": "node debugger needs host access",
        "requested_by": "alice",
        "expires_at": _in_days(30),
        "tenant_id": tenant,
    }
    fields.update(overrides)
    return VulnException(**fields)


def _approved(exc: VulnException) -> VulnException:
    activate_suppression(exc, actor="bob")
    return exc


def test_iac_fields_round_trip_through_sqlite(tmp_path: Path) -> None:
    store = SQLiteExceptionStore(str(tmp_path / "exc.db"))
    exc = _iac()
    store.put(exc, tenant_id="tenant-a")
    loaded = store.get(exc.exception_id, tenant_id="tenant-a")
    assert loaded is not None
    assert (loaded.iac_rule_id, loaded.iac_path, loaded.iac_resource) == ("K8S-001", "k8s/*.yaml", {"kind": "Pod", "name": "node-debugger"})
    assert store.list_all(tenant_id="tenant-a")[0].iac_resource == {"kind": "Pod", "name": "node-debugger"}
    assert loaded.to_dict()["iac_rule_id"] == "K8S-001"


def test_sqlite_store_upgrades_a_legacy_exceptions_table(tmp_path: Path) -> None:
    import sqlite3

    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE exceptions (exception_id TEXT PRIMARY KEY, vuln_id TEXT NOT NULL, package_name TEXT NOT NULL, "
        "server_name TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL DEFAULT '', requested_by TEXT NOT NULL DEFAULT '', "
        "approved_by TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL, "
        "expires_at TEXT NOT NULL DEFAULT '', approved_at TEXT NOT NULL DEFAULT '', revoked_at TEXT NOT NULL DEFAULT '', "
        "tenant_id TEXT NOT NULL DEFAULT 'default')"
    )
    conn.execute("INSERT INTO exceptions (exception_id, vuln_id, package_name, created_at) VALUES ('exc-old', 'CVE-1', 'p', 'now')")
    conn.commit()
    conn.close()
    store = SQLiteExceptionStore(str(db))
    old = store.get("exc-old", tenant_id="default")
    assert old is not None and old.iac_rule_id == "" and old.iac_resource == {}


def test_iac_approval_needs_exact_rule_scope_and_expiry() -> None:
    assert approval_error(_iac()) is None
    assert "exact" in (approval_error(_iac(iac_rule_id="K8S-*")) or "")
    assert "path or resource" in (approval_error(_iac(iac_path="", iac_resource={})) or "")
    assert "expiry" in (approval_error(_iac(expires_at="")) or "")
    with pytest.raises(ValueError):
        activate_suppression(_iac(), actor="alice")  # requester cannot approve their own exception


def test_iac_record_never_matches_a_vulnerability() -> None:
    exc = _approved(_iac())
    assert suppression_active(exc)
    assert not exc.matches("", "")
    assert not exc.matches("CVE-2024-1", "demo")


def test_only_active_iac_exceptions_of_the_tenant_are_loaded() -> None:
    store = InMemoryExceptionStore()
    mine = _approved(_iac())
    pending = _iac()
    other_tenant = _approved(_iac(tenant="tenant-b"))
    vuln = _approved(
        VulnException(
            vuln_id="CVE-2024-1", package_name="demo", reason="x", requested_by="alice", expires_at=_in_days(5), tenant_id="tenant-a"
        )
    )
    for exc in (mine, pending, vuln):
        store.put(exc, tenant_id="tenant-a")
    store.put(other_tenant, tenant_id="tenant-b")
    loaded = tenant_iac_exceptions(store, tenant_id="tenant-a")
    assert [exc.exception_id for exc in loaded] == [mine.exception_id]
    [exc] = loaded
    assert (exc.source, exc.rule, exc.path, exc.approved_by, exc.owner) == ("tenant", "K8S-001", "k8s/*.yaml", "bob", "alice")
    assert exc.resource is not None and exc.resource.kind == "Pod"
    assert exc.expires == datetime.fromisoformat(mine.expires_at).date()
    assert [e.exception_id for e in tenant_iac_exceptions(store, tenant_id="tenant-b")] == [other_tenant.exception_id]


def test_repo_scan_applies_tenant_exceptions_and_keeps_the_evidence(tmp_path: Path) -> None:
    from agent_bom.api.repo_tree_scan import RepoTreeScanResult, _scan_iac_stage

    (tmp_path / "k8s").mkdir()
    (tmp_path / "k8s" / "pod.yaml").write_text(POD)
    store = InMemoryExceptionStore()
    exc = _approved(_iac())
    store.put(exc, tenant_id="tenant-a")
    result = RepoTreeScanResult()
    _scan_iac_stage(tmp_path, result, None, [], tenant_iac_exceptions(store, tenant_id="tenant-a"))
    data = result.iac_findings_data
    assert data is not None
    assert all(row["rule_id"] != "K8S-001" for row in data["findings"])
    [row] = data["suppressed"]
    assert row["suppression"]["source"] == "tenant"
    assert row["suppression"]["approved_by"] == "bob"
    assert row["suppression"]["exception_id"] == exc.exception_id

    other = RepoTreeScanResult()
    _scan_iac_stage(tmp_path, other, None, [], tenant_iac_exceptions(store, tenant_id="tenant-b"))
    assert any(row["rule_id"] == "K8S-001" for row in other.iac_findings_data["findings"])


def test_vulnerability_projection_ignores_iac_exceptions(monkeypatch) -> None:
    from agent_bom.api.finding_suppression import project_current_suppressions

    store = InMemoryExceptionStore()
    store.put(_approved(_iac()), tenant_id="tenant-a")
    monkeypatch.setattr(stores, "_exception_store", store)
    [row] = project_current_suppressions([{"id": "f1", "title": "IaC row with no package"}], "tenant-a")
    assert not row.get("suppressed")


@pytest.fixture
def api(monkeypatch):
    for name in ("AGENT_BOM_EXCEPTION_MAX_EXPIRY_DAYS", "AGENT_BOM_EXCEPTION_ALLOW_SELF_APPROVAL", "AGENT_BOM_ALLOW_UNAUTHENTICATED_API"):
        monkeypatch.delenv(name, raising=False)
    old_keys = get_key_store()
    old_exceptions = stores._get_exception_store()
    keys = KeyStore()
    exceptions = InMemoryExceptionStore()
    set_key_store(keys)
    stores.set_exception_store(exceptions)
    raw_alice, alice = create_api_key(name="alice", role=Role.ADMIN, scopes=["*"], tenant_id="tenant-a")
    raw_bob, bob = create_api_key(name="bob", role=Role.ADMIN, scopes=["*"], tenant_id="tenant-a")
    raw_eve, eve = create_api_key(name="eve", role=Role.ADMIN, scopes=["*"], tenant_id="tenant-b")
    for key in (alice, bob, eve):
        keys.add(key)
    configure_api(api_key=None, allow_unauthenticated=False)
    try:
        yield SimpleNamespace(
            client=TestClient(app),
            store=exceptions,
            alice={"X-API-Key": raw_alice},
            bob={"X-API-Key": raw_bob},
            eve={"X-API-Key": raw_eve},
        )
    finally:
        set_key_store(old_keys)
        stores.set_exception_store(old_exceptions)
        configure_api(api_key=None)


def _iac_body(**overrides) -> dict:
    body = {
        "iac_rule_id": "K8S-001",
        "iac_path": "k8s/*.yaml",
        "iac_resource": {"kind": "Pod", "namespace": "ops", "labels": {"team": "sre"}},
        "reason": "node debugger needs host access",
        "expires_at": _in_days(30),
    }
    body.update(overrides)
    return body


def test_api_request_and_approve_an_iac_exception(api) -> None:
    created = api.client.post("/v1/exceptions", json=_iac_body(), headers=api.alice)
    assert created.status_code == 201, created.text
    body = created.json()
    assert (body["iac_rule_id"], body["iac_path"], body["vuln_id"]) == ("K8S-001", "k8s/*.yaml", "")
    assert body["iac_resource"] == {"kind": "Pod", "namespace": "ops", "labels": {"team": "sre"}}
    assert body["requested_by"] == "alice"
    assert body["suppression_active"] is False

    assert api.client.put(f"/v1/exceptions/{body['exception_id']}/approve", headers=api.alice).status_code == 403
    approved = api.client.put(f"/v1/exceptions/{body['exception_id']}/approve", headers=api.bob)
    assert approved.status_code == 200, approved.text
    assert approved.json()["suppression_active"] is True
    assert [e.rule for e in tenant_iac_exceptions(api.store, tenant_id="tenant-a")] == ["K8S-001"]

    listed = api.client.get("/v1/exceptions", headers=api.alice).json()["exceptions"]
    assert listed[0]["iac_rule_id"] == "K8S-001"
    assert api.client.get("/v1/exceptions", headers=api.eve).json()["exceptions"] == []
    assert api.client.get(f"/v1/exceptions/{body['exception_id']}", headers=api.eve).status_code == 404


@pytest.mark.parametrize(
    "overrides",
    [
        {"reason": ""},
        {"iac_rule_id": ""},
        {"iac_rule_id": "CVE-2024-1"},
        {"iac_resource": {"team": "x"}},
        {"vuln_id": "CVE-2024-1", "package_name": "demo"},
    ],
)
def test_api_rejects_malformed_iac_exceptions(api, overrides) -> None:
    response = api.client.post("/v1/exceptions", json=_iac_body(**overrides), headers=api.alice)
    assert response.status_code == 422, response.text
    assert api.store.list_all(tenant_id="tenant-a") == []


def test_api_still_requires_a_vulnerability_scope_without_iac_fields(api) -> None:
    response = api.client.post("/v1/exceptions", json={"reason": "x", "expires_at": _in_days(3)}, headers=api.alice)
    assert response.status_code == 422


def test_api_vulnerability_exception_contract_is_unchanged(api) -> None:
    response = api.client.post(
        "/v1/exceptions",
        json={"vuln_id": "CVE-2024-1", "package_name": "demo", "reason": "accepted", "expires_at": _in_days(3)},
        headers=api.alice,
    )
    assert response.status_code == 201, response.text
    assert response.json()["iac_rule_id"] == ""
    assert response.json()["status"] == ExceptionStatus.PENDING.value


@pytest.mark.skipif(not __import__("os").environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires isolated live Postgres")
def test_live_postgres_iac_exception_scope_is_persisted_and_tenant_isolated() -> None:
    from uuid import uuid4

    from agent_bom.api import postgres_common
    from agent_bom.api.postgres_access import PostgresExceptionStore

    postgres_common.reset_pool()
    tenant, other = "iac-" + uuid4().hex, "iac-other-" + uuid4().hex
    token = postgres_common.set_current_tenant(tenant)
    try:
        store = PostgresExceptionStore()
        with postgres_common._tenant_connection(store._pool) as conn:
            conn.execute("INSERT INTO teams (team_id,name,slug) VALUES (%s,%s,%s)", (tenant, tenant, tenant))
            conn.commit()
        exc = _approved(_iac(tenant=tenant))
        store.put(exc, tenant_id=tenant)
        postgres_common.reset_pool()
        restored = PostgresExceptionStore()
        loaded = restored.get(exc.exception_id, tenant_id=tenant)
        assert loaded is not None
        assert (loaded.iac_rule_id, loaded.iac_path, loaded.iac_resource) == (
            "K8S-001",
            "k8s/*.yaml",
            {"kind": "Pod", "name": "node-debugger"},
        )
        assert [e.exception_id for e in tenant_iac_exceptions(restored, tenant_id=tenant)] == [exc.exception_id]
        assert restored.find_matching("", "", tenant_id=tenant) is None
        assert tenant_iac_exceptions(restored, tenant_id=other) == []
        with restored._pool.connection() as conn:
            conn.execute("SELECT set_config('app.tenant_id',%s,true)", (other,))
            assert conn.execute("SELECT count(*) FROM exceptions WHERE exception_id=%s", (exc.exception_id,)).fetchone()[0] == 0
    finally:
        postgres_common.reset_current_tenant(token)
        postgres_common.reset_pool()
