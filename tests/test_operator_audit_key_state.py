"""Losing an ephemeral signing key is not evidence of altered audit rows."""

from types import SimpleNamespace

import pytest

from agent_bom.api import audit_log
from agent_bom.api.routes.enterprise_routes.governance import audit_integrity


def _integrity(monkeypatch, store):
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: store)
    return audit_integrity(SimpleNamespace(state=SimpleNamespace(tenant_id="default")), limit=1000, include_runtime=False)


def test_key_identity_setup_preserves_first_signature_warning(monkeypatch, tmp_path, caplog):
    monkeypatch.setattr(audit_log, "_HMAC_ENV_KEY", None)
    monkeypatch.setattr(audit_log, "_EPHEMERAL_KEY_WARNED", False)
    store = audit_log.SQLiteAuditLog(str(tmp_path / "warning.db"))
    assert not audit_log._EPHEMERAL_KEY_WARNED
    store.append(audit_log.AuditEntry(action="test.first"))
    assert audit_log._EPHEMERAL_KEY_WARNED
    assert "AGENT_BOM_AUDIT_HMAC_KEY" in caplog.text


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


def test_unverifiable_count_respects_limit_and_tenant(monkeypatch, tmp_path):
    monkeypatch.setattr(audit_log, "_HMAC_ENV_KEY", None)
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"first-test-key")
    path = str(tmp_path / "bounded-audit.db")
    first = audit_log.SQLiteAuditLog(path)
    for tenant in ["default"] * 5 + ["other"] * 3:
        first.append(audit_log.AuditEntry(action="test.record", details={"tenant_id": tenant}))
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"replacement-test-key")
    reopened = audit_log.SQLiteAuditLog(path)
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: reopened)
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="default"))
    # Five entries exceed a limit of two, so none are walked and the count stays true.
    result = audit_integrity(request, limit=2, include_runtime=False)
    assert (result["status"], result["unverifiable"], result["checked"]) == ("not_verified_over_budget", 5, 0)
    assert audit_integrity(request, limit=5, include_runtime=False)["unverifiable"] == 5
    request.state.tenant_id = "absent"
    assert audit_integrity(request, limit=2, include_runtime=False)["checked"] == 0


@pytest.mark.parametrize("persistent", [False, True])
def test_integrity_does_not_walk_a_chain_larger_than_the_requested_budget(monkeypatch, tmp_path, persistent):
    store = (
        audit_log.SQLiteAuditLog(str(tmp_path / "bounded-stable.db"), hmac_key=b"stable-test-key")
        if persistent
        else audit_log.InMemoryAuditLog()
    )
    for number in range(5):
        store.append(audit_log.AuditEntry(action=f"test.{number}", details={"tenant_id": "default"}))
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: store)
    monkeypatch.setattr(audit_log, "_verify_audit_chain_with_checkpoint", lambda *_args: pytest.fail("unbounded verification"))
    if persistent:
        monkeypatch.setattr(store, "_list_entries_chronological", lambda **_kwargs: pytest.fail("unbounded verification"))
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="default"))
    result = audit_integrity(request, limit=2, include_runtime=False)
    assert (result["verified"], result["tampered"], result["unverifiable"], result["checked"]) == (None, 0, 5, 0)
    assert result["status"] == "not_verified_over_budget"
    chain = result["chains"][0]
    assert (chain["verified"], chain["total_entries"], chain["verification_limit"]) == (None, 5, 2)
    assert "5 entries exceed the requested limit of 2" in chain["error"]
    assert result["error"] == chain["error"]


def test_postgres_integrity_checks_budget_before_fetching_entries(monkeypatch):
    from agent_bom.api.audit_key_state import AuditVerificationLimitExceededError
    from agent_bom.api.postgres_audit import PostgresAuditLog

    store = PostgresAuditLog.__new__(PostgresAuditLog)
    monkeypatch.setattr(store, "count", lambda **_kwargs: 5)
    monkeypatch.setattr(store, "_list_entries_chronological", lambda **_kwargs: pytest.fail("unbounded verification"))
    with pytest.raises(AuditVerificationLimitExceededError) as error:
        store.verify_integrity(limit=2, tenant_id="default")
    assert error.value.total == 5


def test_default_export_never_reports_zero_verified_over_budget(monkeypatch, tmp_path):
    import json

    from agent_bom.api.routes.enterprise_routes.governance import export_audit_entries

    store = audit_log.SQLiteAuditLog(str(tmp_path / "export.db"), hmac_key=b"stable-test-key")
    for number in range(5):
        store.append(audit_log.AuditEntry(action=f"test.{number}", details={"tenant_id": "default"}))
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: store)
    request = SimpleNamespace(state=SimpleNamespace(tenant_id="default", api_key_name="tester"))
    packet = json.loads(export_audit_entries(request, limit=2).body)
    assert packet["integrity"]["verified"] is None
    assert packet["integrity"]["status"] == "not_verified_over_budget"
    assert (packet["integrity"]["total_entries"], packet["integrity"]["verification_limit"]) == (5, 2)


def test_integrity_response_contract_accepts_an_unverified_chain(monkeypatch):
    from agent_bom.api.read_models.enterprise import AuditExportIntegrity, AuditIntegrityResponse

    store = audit_log.InMemoryAuditLog()
    for number in range(3):
        store.append(audit_log.AuditEntry(action=f"test.{number}", details={"tenant_id": "default"}))
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: store)
    result = audit_integrity(SimpleNamespace(state=SimpleNamespace(tenant_id="default")), limit=1, include_runtime=False)
    AuditIntegrityResponse.model_validate(result)
    AuditExportIntegrity.model_validate(
        {key: value for key, value in result["chains"][0].items() if key in AuditExportIntegrity.model_fields}
    )


def test_a_verified_runtime_chain_is_not_hidden_by_an_over_budget_control_plane(monkeypatch, tmp_path):
    from agent_bom.api.routes.enterprise_routes import governance

    store = audit_log.InMemoryAuditLog()
    for number in range(3):
        store.append(audit_log.AuditEntry(action=f"test.{number}", details={"tenant_id": "default"}))
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: store)
    log = tmp_path / "runtime.jsonl"
    log.write_text("")
    monkeypatch.setattr(governance, "_configured_runtime_audit_log_path", lambda: log)
    monkeypatch.setattr(
        "agent_bom.audit_integrity.verify_audit_jsonl_chain", lambda *_a, **_k: {"verified": 4, "tampered": 0, "checked": 4}
    )
    result = governance.audit_integrity(SimpleNamespace(state=SimpleNamespace(tenant_id="default")), limit=1, include_runtime=True)
    assert result["verified"] == 4
    assert result["unverifiable"] == 3
    assert result["status"] == "not_verified_over_budget"


def _identity_row(store):
    return store._conn.execute("SELECT fingerprint FROM audit_key_identity WHERE singleton = 1").fetchone()[0]


def test_new_key_identity_is_salted_and_contains_no_plain_digest(tmp_path):
    import hashlib

    key = b"weak-but-test-only"
    first = audit_log.SQLiteAuditLog(str(tmp_path / "one.db"), hmac_key=key)
    second = audit_log.SQLiteAuditLog(str(tmp_path / "two.db"), hmac_key=key)
    stored = _identity_row(first)
    assert hashlib.sha256(key).hexdigest() not in stored
    assert stored != _identity_row(second)
    assert stored.startswith("v2:")


def test_existing_unsalted_identity_is_upgraded_and_still_matches_its_key(monkeypatch, tmp_path):
    import hashlib
    import sqlite3

    from agent_bom.api.audit_key_state import key_matches_identity

    monkeypatch.setattr(audit_log, "_HMAC_ENV_KEY", None)
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"legacy-test-key")
    path = str(tmp_path / "legacy.db")
    first = audit_log.SQLiteAuditLog(path)
    first.append(audit_log.AuditEntry(action="test.first"))
    legacy = hashlib.sha256(b"legacy-test-key").hexdigest()
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE audit_key_identity SET fingerprint = ?", (legacy,))

    reopened = audit_log.SQLiteAuditLog(path)
    stored = _identity_row(reopened)
    assert legacy not in stored
    assert key_matches_identity(b"legacy-test-key", stored)
    assert not key_matches_identity(b"another-key", stored)
    assert _integrity(monkeypatch, reopened)["verified"] == 1

    # A row whose key is gone upgrades too, and still reports unverifiable.
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"replacement-key")
    assert _integrity(monkeypatch, audit_log.SQLiteAuditLog(path))["unverifiable"] == 1


def test_legacy_marker_rows_keep_their_meaning(monkeypatch, tmp_path):
    import sqlite3

    monkeypatch.setattr(audit_log, "_HMAC_ENV_KEY", None)
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"marker-test-key")
    path = str(tmp_path / "marker.db")
    first = audit_log.SQLiteAuditLog(path)
    first.append(audit_log.AuditEntry(action="test.first"))
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE audit_key_identity SET fingerprint = 'legacy-key-unrecorded'")
        connection.execute("DROP TABLE audit_key_boundary")
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"another-ephemeral-key")
    reopened = audit_log.SQLiteAuditLog(path)
    assert _identity_row(reopened) == "legacy-key-unrecorded"
    result = _integrity(monkeypatch, reopened)
    assert (result["tampered"], result["unverifiable"]) == (0, 1)
