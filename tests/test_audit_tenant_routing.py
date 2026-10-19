"""Payload redaction must not change the tenant owning an audit chain."""

from types import SimpleNamespace
from uuid import uuid4

import pytest

from agent_bom.api import audit_log


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_audit_preserves_distinct_tenant_scopes_while_redacting_payload(backend, tmp_path, monkeypatch):
    tenants = ["push-hardening-14c08b63f6254d99af772928bdfce141", "push-hardening-14c08b63f6254d99af772928bdfce142"]
    store = audit_log.InMemoryAuditLog() if backend == "memory" else audit_log.SQLiteAuditLog(str(tmp_path / "audit.db"))
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: store)
    resource = str(uuid4())
    for tenant in tenants:
        audit_log.log_action("results.push.accepted", resource=resource, tenant_id=tenant, password="private-password")

    if backend == "sqlite":
        store = audit_log.SQLiteAuditLog(str(tmp_path / "audit.db"))
    for tenant in tenants:
        entries = store.list_entries(tenant_id=tenant, resource=resource)
        assert len(entries) == 1
        assert entries[0].details["tenant_id"] == tenant
        assert "private-password" not in str(entries[0].details)
        assert entries[0].verify()
        assert store.verify_integrity(tenant_id=tenant) == (1, 0)
    assert store.list_entries(tenant_id="***REDACTED***", resource=resource) == []


def test_audit_uses_ambient_tenant_when_scope_is_omitted(monkeypatch):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

    tenant = "push-hardening-14c08b63f6254d99af772928bdfce141"
    store = audit_log.InMemoryAuditLog()
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: store)
    token = set_current_tenant(tenant)
    try:
        audit_log.log_action("scope.check")
    finally:
        reset_current_tenant(token)
    assert len(store.list_entries(tenant_id=tenant)) == 1


def test_explicit_audit_scope_survives_payload_limits_and_reaches_analytics(monkeypatch):
    from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
    from agent_bom.api.storage import analytics

    tenant = "push-hardening-14c08b63f6254d99af772928bdfce141"
    store = audit_log.InMemoryAuditLog()
    rows = []
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: store)
    monkeypatch.setattr(analytics, "get_analytics_store", lambda: SimpleNamespace(record_audit_event=rows.append))
    details = {"event_id": ["x" * 2000 for _ in range(100)]}
    token = set_current_tenant("other-tenant")
    try:
        audit_log.log_action("scope.check", **details, tenant_id=tenant)
    finally:
        reset_current_tenant(token)
    entries = store.list_entries(tenant_id=tenant)
    assert len(entries) == 1
    assert entries[0].details["_truncated"] is True
    assert entries[0].verify()
    assert store.list_entries(tenant_id="other-tenant") == []
    assert rows[0]["tenant_id"] == tenant
