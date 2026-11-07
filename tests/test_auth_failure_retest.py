"""Integrity after key changes, websocket and MCP limits, and prompt evidence of dropped receipts."""

from __future__ import annotations

import re
import sqlite3
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from agent_bom.api import audit_log
from agent_bom.api.auth_failure_receipts import AuthFailureReceipts
from agent_bom.api.auth_failure_store import SQLiteAuthFailureStore
from agent_bom.api.routes.enterprise_routes.governance import audit_integrity

_REQUEST = SimpleNamespace(state=SimpleNamespace(tenant_id="default"))
_RIGHT = "valid-websocket-credential"


def _append(store, count, prefix="row"):
    for number in range(count):
        store.append(audit_log.AuditEntry(action=f"{prefix}.{number}", details={"tenant_id": "default"}))


def _tamper(store, action):
    store._conn.execute("UPDATE audit_log SET action = 'changed' WHERE action = ?", (action,))
    store._conn.commit()


def _integrity(monkeypatch, store):
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: store)
    return audit_integrity(_REQUEST, limit=1000, include_runtime=False)


def _counts(result):
    return result["verified"], result["tampered"], result["unverifiable"]


def _keyless_then(monkeypatch, path, key):
    """Boot once with no configured key, as a first start does, then configure one."""
    monkeypatch.setattr(audit_log, "_HMAC_ENV_KEY", None)
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"ephemeral-first-boot")
    first = audit_log.SQLiteAuditLog(path)
    monkeypatch.setattr(audit_log, "_HMAC_ENV_KEY", key.decode())
    monkeypatch.setattr(audit_log, "_HMAC_KEY", key)
    return first


def test_key_configured_after_an_empty_first_boot_is_verified_exactly(monkeypatch, tmp_path):
    path = str(tmp_path / "audit.db")
    _keyless_then(monkeypatch, path, b"configured-key")
    store = audit_log.SQLiteAuditLog(path)
    _append(store, 6)
    assert _counts(_integrity(monkeypatch, store)) == (6, 0, 0)
    _tamper(store, "row.2")
    assert _counts(_integrity(monkeypatch, store)) == (5, 1, 0)
    # The first row under a key is held to it as well: nothing before it to confuse it with.
    _tamper(store, "row.0")
    assert _counts(_integrity(monkeypatch, store)) == (4, 2, 0)


def test_rows_under_an_earlier_key_are_counted_and_later_rows_stay_exact(monkeypatch, tmp_path):
    path = str(tmp_path / "audit.db")
    first = _keyless_then(monkeypatch, path, b"configured-key")
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"ephemeral-first-boot")
    _append(first, 3, "old")
    monkeypatch.setattr(audit_log, "_HMAC_KEY", b"configured-key")
    store = audit_log.SQLiteAuditLog(path)
    _append(store, 3, "new")
    result = _integrity(monkeypatch, store)
    assert _counts(result) == (3, 0, 3)
    assert result["status"] == "partially_unverifiable"
    assert "3 of 6" in result["error"]
    _tamper(store, "new.0")
    assert _counts(_integrity(monkeypatch, store)) == (2, 1, 3)


def test_rotation_keeps_new_rows_exact_and_old_rows_checkable_with_their_key(monkeypatch, tmp_path):
    path = str(tmp_path / "audit.db")
    first = audit_log.SQLiteAuditLog(path, hmac_key=b"key-a")
    _append(first, 2, "a")
    second = audit_log.SQLiteAuditLog(path, hmac_key=b"key-b")
    _append(second, 2, "b")
    assert _counts(_integrity(monkeypatch, second)) == (2, 0, 2)
    _tamper(second, "b.1")
    assert _counts(_integrity(monkeypatch, second)) == (1, 1, 2)
    # Restarting with the old key checks its rows, and rows it cannot check are not called altered.
    back = audit_log.SQLiteAuditLog(path, hmac_key=b"key-a")
    assert _counts(_integrity(monkeypatch, back)) == (2, 0, 2)


def test_garbled_identity_row_does_not_stop_detection(monkeypatch, tmp_path):
    path = str(tmp_path / "audit.db")
    store = audit_log.SQLiteAuditLog(path, hmac_key=b"stable-key")
    _append(store, 4)
    store._conn.execute("UPDATE audit_key_identity SET fingerprint = 'garbled'")
    store._conn.commit()
    reopened = audit_log.SQLiteAuditLog(path, hmac_key=b"stable-key")
    _tamper(reopened, "row.1")
    assert _counts(_integrity(monkeypatch, reopened)) == (3, 1, 0)


def test_a_boundary_not_signed_by_the_key_cannot_hide_changes(monkeypatch, tmp_path):
    path = str(tmp_path / "audit.db")
    store = audit_log.SQLiteAuditLog(path, hmac_key=b"stable-key")
    _append(store, 4)
    store._conn.execute("INSERT INTO audit_key_boundary (first_rowid, signature) VALUES (1000, 'forged')")
    store._conn.commit()
    _tamper(store, "row.1")
    assert _counts(_integrity(monkeypatch, store)) == (3, 1, 0)


def test_removing_the_boundary_leaves_later_changes_detected(monkeypatch, tmp_path):
    path = str(tmp_path / "audit.db")
    store = audit_log.SQLiteAuditLog(path, hmac_key=b"stable-key")
    _append(store, 4)
    store._conn.execute("DELETE FROM audit_key_boundary")
    store._conn.commit()
    _tamper(store, "row.2")
    assert _counts(_integrity(monkeypatch, store)) == (3, 1, 0)


def test_deleting_or_reordering_rows_under_an_earlier_key_is_detected(monkeypatch, tmp_path):
    path = str(tmp_path / "audit.db")
    first = audit_log.SQLiteAuditLog(path, hmac_key=b"key-a")
    _append(first, 4, "a")
    second = audit_log.SQLiteAuditLog(path, hmac_key=b"key-b")
    second._conn.execute("DELETE FROM audit_log WHERE action = 'a.1'")
    second._conn.commit()
    result = _integrity(monkeypatch, second)
    assert result["tampered"] >= 1
    assert result["verified"] == 0


def test_truncation_is_tampering_whichever_key_is_held(monkeypatch, tmp_path):
    path = str(tmp_path / "audit.db")
    store = audit_log.SQLiteAuditLog(path, hmac_key=b"key-a")
    _append(store, 4, "a")
    store._conn.execute("DELETE FROM audit_log WHERE action = 'a.3'")
    store._conn.commit()
    assert _integrity(monkeypatch, store)["tampered"] >= 1
    other = audit_log.SQLiteAuditLog(path, hmac_key=b"key-b")
    assert _integrity(monkeypatch, other)["tampered"] >= 1


def _postgres_like(entries, checkpoint):
    from agent_bom.api.postgres_audit import PostgresAuditLog

    store = PostgresAuditLog.__new__(PostgresAuditLog)
    store.count = lambda **_kwargs: len(entries)
    store._list_entries_chronological = lambda **_kwargs: list(entries)
    store._get_checkpoint = lambda _tenant: checkpoint
    return store


def _signed_chain(count):
    memory = audit_log.InMemoryAuditLog()
    for number in range(count):
        memory.append(audit_log.AuditEntry(action=f"row.{number}", details={"tenant_id": "default"}))
    return list(memory._entries), memory._checkpoint_by_tenant["default"]


def test_postgres_truncation_to_the_newest_row_reads_as_tampering(monkeypatch):
    entries, checkpoint = _signed_chain(5)
    result = _integrity(monkeypatch, _postgres_like(entries[-1:], checkpoint))
    assert result["tampered"] >= 1
    assert "key changed" not in str(result["chains"][0].get("error") or "").lower()


def test_postgres_truncation_with_no_checkpoint_is_still_seen_by_the_broken_link(monkeypatch):
    entries, _checkpoint = _signed_chain(5)
    assert _integrity(monkeypatch, _postgres_like(entries[-1:], None))["tampered"] >= 1


def test_postgres_change_in_the_middle_is_tampering(monkeypatch):
    entries, checkpoint = _signed_chain(5)
    entries[2].action = "changed"
    assert _counts(_integrity(monkeypatch, _postgres_like(entries, checkpoint))) == (4, 1, 0)


def test_postgres_all_rows_failing_states_what_it_cannot_tell_apart(monkeypatch):
    entries, checkpoint = _signed_chain(1)
    entries[0].action = "changed"
    result = _integrity(monkeypatch, _postgres_like(entries, checkpoint))
    assert _counts(result) == (0, 0, 1)
    assert "altered" in result["error"]
    assert "cannot be told apart" in result["error"]


def test_docs_state_detection_in_each_state():
    from pathlib import Path

    docs = (Path(__file__).resolve().parents[1] / "docs/RUNTIME_FAIL_MODES.md").read_text()
    section = docs[docs.index("### What integrity checks detect") :]
    for phrase in ("before the key's boundary", "cannot be told apart", "Postgres", "removes the boundary"):
        assert phrase in section


# Websockets


@pytest.fixture
def websocket_client(monkeypatch, tmp_path):
    from fastapi import FastAPI

    from agent_bom.api import auth
    from agent_bom.api.auth import KeyStore
    from agent_bom.api.middleware_limits import GlobalRateLimitMiddleware
    from agent_bom.api.routes.proxy import ws_router

    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "3")
    monkeypatch.setenv("AGENT_BOM_API_KEY", _RIGHT)
    monkeypatch.setattr(auth, "_key_store", KeyStore())
    monkeypatch.setattr(audit_log, "_audit_log", audit_log.InMemoryAuditLog())
    monkeypatch.setattr("agent_bom.api.websocket_auth._ws_auth_required", lambda: True)
    monkeypatch.setattr("agent_bom.api.websocket_auth._ws_handshake_within_rate_limit", _always_allowed)
    app = FastAPI()
    app.include_router(ws_router)
    app.add_middleware(GlobalRateLimitMiddleware, rpm=300_000)
    return TestClient(app, client=("192.0.2.180", 1000))


async def _always_allowed(_websocket):
    return True


def _connect(client, path, token):
    """Return the close code, or None when the stream was accepted."""
    try:
        with client.websocket_connect(path, headers={"authorization": f"Bearer {token}"}) as socket:
            socket.send_json({"type": "none"})
            socket.receive_json()
            return None
    except WebSocketDisconnect as closed:
        return closed.code


def _ws_paths():
    from agent_bom.api.routes.proxy import ws_router

    paths = [route.path for route in ws_router.routes]
    assert len(paths) >= 2
    return paths


@pytest.mark.parametrize("path", ["/ws/proxy/metrics", "/ws/proxy/alerts"])
def test_wrong_websocket_tokens_count_and_a_blocked_source_cannot_connect(websocket_client, path):
    codes = [_connect(websocket_client, path, "wrong-token") for _ in range(8)]
    assert 4029 in codes
    assert codes.count(4001) < 4
    # Blocked: the right key is refused exactly like a wrong one, with nothing verified.
    assert _connect(websocket_client, path, _RIGHT) == 4029
    assert _connect(websocket_client, path, "wrong-token") == 4029


def test_websocket_auth_message_counts_and_a_valid_key_without_scope_does_not(websocket_client):
    def message_attempt(token):
        with websocket_client.websocket_connect("/ws/proxy/metrics") as socket:
            socket.send_json({"type": "auth", "token": token})
            with pytest.raises(WebSocketDisconnect) as closed:
                socket.receive_json()
                socket.receive_json()
            return closed.value.code

    codes = [message_attempt("wrong-token") for _ in range(3)]
    assert codes[0] == 4001
    assert codes[-1] == 4029


def test_scope_refusal_is_not_a_failed_credential():
    from agent_bom.api.websocket_auth import _ws_auth_from_token

    rejected: list[bool] = []
    assert _ws_auth_from_token("", rejected=rejected) is None
    assert rejected == []


def test_expired_oidc_token_on_a_websocket_does_not_count(monkeypatch):
    from agent_bom.api import auth, oidc
    from agent_bom.api.auth import KeyStore
    from agent_bom.api.websocket_auth import _ws_auth_from_token

    monkeypatch.delenv("AGENT_BOM_API_KEY", raising=False)
    monkeypatch.setattr(auth, "_key_store", KeyStore())
    monkeypatch.setattr(oidc, "oidc_enabled_from_env", lambda: True)

    def expired(_token):
        raise oidc.OIDCTokenExpiredError("expired")

    monkeypatch.setattr(oidc.OIDCConfig, "from_env", classmethod(lambda cls: SimpleNamespace(enabled=True, verify=expired)))
    rejected: list[bool] = []
    assert _ws_auth_from_token("header.payload.signature", rejected=rejected) is None
    assert rejected == []


def test_every_websocket_route_is_covered_by_the_limit(websocket_client):
    leaks = []
    assert _connect(websocket_client, _ws_paths()[0], "wrong-token") == 4001
    for _ in range(4):
        _connect(websocket_client, _ws_paths()[0], "wrong-token")
    for path in _ws_paths():
        path = re.sub(r"\{[^}]+\}", "x", path)
        right, wrong = _connect(websocket_client, path, _RIGHT), _connect(websocket_client, path, "wrong-token")
        if right != 4029 or wrong != 4029:
            leaks.append((path, right, wrong))
    assert leaks == []


def test_a_blocked_source_on_http_is_blocked_on_websockets(websocket_client):
    with websocket_client as client:
        for _ in range(3):
            client.get("/v1/findings", headers={"x-api-key": "wrong"})
        for _ in range(4):
            _connect(client, "/ws/proxy/alerts", "wrong-token")
        assert _connect(client, "/ws/proxy/metrics", _RIGHT) == 4029


def test_wrong_proxy_attestation_on_a_websocket_counts(websocket_client, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", "p" * 40)
    headers = {"x-agent-bom-proxy-secret": "wrong", "x-agent-bom-role": "viewer", "x-agent-bom-tenant-id": "tenant"}
    codes = []
    for _ in range(6):
        try:
            with websocket_client.websocket_connect("/ws/proxy/metrics", headers=headers) as socket:
                socket.send_json({"type": "none"})
                socket.receive_json()
        except WebSocketDisconnect as closed:
            codes.append(closed.code)
    assert 4029 in codes


# MCP routes


@pytest.mark.parametrize("builder", ["streamable_http_app", "sse_app"])
def test_every_mcp_route_answers_alike_for_right_and_wrong_tokens_while_blocked(monkeypatch, builder):
    from datetime import datetime, timedelta, timezone

    from agent_bom.mcp_server import create_mcp_server

    monkeypatch.setenv("AGENT_BOM_AUTH_FAILURE_LIMIT", "1")
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat())
    monkeypatch.setattr(audit_log, "log_action", lambda *_a, **_k: None)
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token="right-mcp-token", profile="scan")
    app = getattr(server, builder)()
    paths = {getattr(route, "path", "") for route in app.routes} - {""}
    assert paths
    leaks = []
    with TestClient(app, base_url="http://localhost:8000", client=("192.0.2.181", 1000)) as client:
        first = sorted(paths)[0]
        client.post("/mcp", headers={"authorization": "Bearer wrong"})
        client.get("/sse", headers={"authorization": "Bearer wrong"}) if builder == "sse_app" else None
        for path in sorted(paths):
            for method in ("POST", "DELETE", "PUT", "OPTIONS"):
                wrong = client.request(method, path, headers={"authorization": "Bearer wrong"}).status_code
                right = client.request(method, path, headers={"authorization": "Bearer right-mcp-token"}).status_code
                if wrong != right or wrong == 401:
                    leaks.append((method, path, wrong, right))
        assert first
    assert leaks == []


# Dropped receipts leave a prompt record


def test_a_gap_is_recorded_without_waiting_for_a_later_failure(monkeypatch):
    written = []
    monkeypatch.setattr(audit_log, "log_action", lambda action, **details: written.append((action, details)))
    receipts = AuthFailureReceipts(gap_interval_seconds=0.05)
    for number in range(5):
        receipts.submit(f"198.51.100.{number}", 100.0 + number, lambda *_a: False, status_code=401)
    deadline_written = _wait_for(lambda: any(action == "auth.receipts_dropped" for action, _ in written))
    assert deadline_written
    gap = next(details for action, details in written if action == "auth.receipts_dropped")
    assert gap["dropped_receipts"] == 5
    assert gap["dropped_source_count"] == 5
    assert "198.51.100.0" in gap["dropped_sources"]
    assert gap["window_started_at"] <= gap["window_ended_at"]
    assert gap["tenant_id"] == audit_log.AUTH_FAILURE_AUDIT_TENANT


def _wait_for(check, attempts=100):
    import time

    for _ in range(attempts):
        if check():
            return True
        time.sleep(0.02)
    return False


def test_a_gap_survives_audit_redaction_with_its_window_and_sources(monkeypatch):
    store = audit_log.InMemoryAuditLog()
    monkeypatch.setattr(audit_log, "_audit_log", store)
    receipts = AuthFailureReceipts(gap_interval_seconds=0.05)
    receipts.submit("198.51.100.7", 100.0, lambda *_a: False, status_code=401)
    assert _wait_for(lambda: store.list_entries(action="auth.receipts_dropped", tenant_id=audit_log.AUTH_FAILURE_AUDIT_TENANT))
    details = store.list_entries(action="auth.receipts_dropped", tenant_id=audit_log.AUTH_FAILURE_AUDIT_TENANT)[0].details
    assert details["dropped_receipts"] == 1
    assert details["window_started_at"]
    assert details["window_ended_at"]
    assert details["dropped_source_count"] == 1
    assert details["dropped_sources"] == ["198.51.100.7"]


def test_a_failed_gap_write_keeps_its_counts_and_is_retried(monkeypatch):
    written = []
    failures = {"left": 1}

    def flaky(action, **details):
        if failures["left"]:
            failures["left"] -= 1
            raise sqlite3.OperationalError("database is locked")
        written.append(details)

    monkeypatch.setattr(audit_log, "log_action", flaky)
    receipts = AuthFailureReceipts(gap_interval_seconds=0.05)
    receipts.submit("198.51.100.8", 100.0, lambda *_a: False, status_code=401)
    assert _wait_for(lambda: bool(written))
    assert written[0]["dropped_receipts"] == 1


def test_gap_records_are_bounded_during_a_flood(monkeypatch):
    written = []
    monkeypatch.setattr(audit_log, "log_action", lambda action, **details: written.append(action))
    receipts = AuthFailureReceipts(gap_interval_seconds=60)
    for number in range(50):
        receipts.submit(f"198.51.100.{number}", 100.0, lambda *_a: False, status_code=401)
        receipts.submit(f"198.51.100.{number}", 100.0, lambda *_a: True, status_code=401)
    assert receipts.flush()
    assert written.count("auth.receipts_dropped") <= 2
    assert written.count("auth.failed") == 50


def test_one_network_cannot_use_up_every_other_sources_first_receipt(tmp_path):
    store = SQLiteAuthFailureStore(str(tmp_path / "limits.db"))
    flood = sum(store.audit_allowed(f"198.51.{n // 256}.{n % 256}", 100) for n in range(405))
    assert flood <= 25
    assert store.audit_allowed("203.0.113.9", 100) is True


def test_ipv6_sources_share_by_a_wider_prefix_for_receipts(tmp_path):
    store = SQLiteAuthFailureStore(str(tmp_path / "limits.db"))
    flood = sum(store.audit_allowed(f"2001:db8:1:{n:x}::/64", 100) for n in range(100))
    assert flood <= 25
    assert store.audit_allowed("2001:db8:2:1::/64", 100) is True


def test_first_receipts_across_many_networks_remain_bounded(tmp_path):
    store = SQLiteAuthFailureStore(str(tmp_path / "limits.db"))
    allowed = sum(store.audit_allowed(f"{a}.{b}.0.1", 100) for a in range(1, 100) for b in range(0, 20))
    assert 100 < allowed <= 400
