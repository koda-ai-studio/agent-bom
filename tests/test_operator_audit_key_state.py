"""Losing an ephemeral signing key is not evidence of altered audit rows."""

from types import SimpleNamespace

from agent_bom.api import audit_log
from agent_bom.api.routes.enterprise_routes.governance import audit_integrity


def _integrity(monkeypatch, store):
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: store)
    return audit_integrity(SimpleNamespace(state=SimpleNamespace(tenant_id="default")), limit=1000, include_runtime=False)


def test_restart_with_ephemeral_key_reports_unverifiable(monkeypatch, tmp_path):
    monkeypatch.setattr(audit_log, "_HMAC_ENV_KEY", None)
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"first-test-key")
    path = str(tmp_path / "audit.db")
    first = audit_log.SQLiteAuditLog(path)
    first.append(audit_log.AuditEntry(action="test.first"))
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"second-test-key")
    reopened = audit_log.SQLiteAuditLog(path)
    result = _integrity(monkeypatch, reopened)
    assert result["tampered"] == 0
    assert result["verified"] == 0
    assert result["unverifiable"] == 1
    assert result["checked"] == 1
    assert "key changed" in result["chains"][0]["error"].lower()


def test_configured_key_detects_exact_tampered_row(monkeypatch, tmp_path):
    store = audit_log.SQLiteAuditLog(str(tmp_path / "audit.db"), hmac_key=b"stable-test-key")
    for action in ("first", "second", "third"):
        store.append(audit_log.AuditEntry(action=action))
    store._conn.execute("UPDATE audit_log SET action = 'changed' WHERE action = 'second'")
    store._conn.commit()
    result = _integrity(monkeypatch, store)
    assert (result["verified"], result["tampered"]) == (2, 1)
