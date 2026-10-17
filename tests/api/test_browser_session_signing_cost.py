"""Bound cookie verification work without caching authentication decisions."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import Mock

import pytest

from agent_bom.api import browser_session as sessions


@pytest.fixture
def signing(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY", "synthetic-session-cost-key")
    monkeypatch.delenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_FILE", raising=False)
    monkeypatch.setattr(sessions, "_SIGNING_KEY_CACHE", None, raising=False)
    derive = Mock(wraps=sessions.hashlib.pbkdf2_hmac)
    monkeypatch.setattr(sessions.hashlib, "pbkdf2_hmac", derive)
    return derive


def issue():
    return sessions.create_browser_session_token(
        subject="test-reader", role="viewer", tenant_id="tenant-a", auth_method="browser_session", max_age_seconds=60
    )[0]


def test_repeated_valid_and_forged_cookies_do_not_repeat_key_derivation(signing):
    token = issue()
    forged = token.split(".")[0] + "." + sessions._b64encode(bytes(32))
    for _ in range(3):
        assert sessions.verify_browser_session_token(token)["tenant_id"] == "tenant-a"
        with pytest.raises(sessions.BrowserSessionError, match="signature is invalid"):
            sessions.verify_browser_session_token(forged)
    assert signing.call_count == 1


def test_concurrent_cold_cookie_checks_derive_once(signing):
    start = Barrier(2)

    def verify(_):
        start.wait(timeout=5)
        with pytest.raises(sessions.BrowserSessionError):
            sessions.verify_browser_session_token("forged." + sessions._b64encode(bytes(32)))

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(verify, range(2)))
    assert signing.call_count == 1


@pytest.mark.parametrize("token", ["payload.", "payload.!!!", "é." + sessions._b64encode(bytes(32))])
def test_malformed_cookie_is_rejected_before_key_derivation(signing, token):
    with pytest.raises(sessions.BrowserSessionError):
        sessions.verify_browser_session_token(token)
    signing.assert_not_called()


def test_mounted_key_rotation_and_removal_are_not_hidden_by_cache(signing, monkeypatch, tmp_path):
    key_file = tmp_path / "session-key"
    key_file.write_text("synthetic-mounted-key-one")
    monkeypatch.setenv("AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_FILE", str(key_file))
    old = issue()
    assert sessions.verify_browser_session_token(old)["tenant_id"] == "tenant-a"
    key_file.write_text("synthetic-mounted-key-two")
    with pytest.raises(sessions.BrowserSessionError, match="signature is invalid"):
        sessions.verify_browser_session_token(old)
    new = issue()
    assert sessions.verify_browser_session_token(new)["tenant_id"] == "tenant-a"
    assert signing.call_count == 2
    key_file.unlink()
    with pytest.raises(ValueError, match="not found"):
        sessions.verify_browser_session_token(new)


def test_warm_key_does_not_cache_revocation_decision(signing):
    token = issue()
    sessions.verify_browser_session_token(token)
    assert sessions.revoke_browser_session_token(token)
    with pytest.raises(sessions.BrowserSessionError, match="revoked"):
        sessions.verify_browser_session_token(token)
    assert signing.call_count == 1
