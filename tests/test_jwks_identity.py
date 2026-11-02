"""Tests for JWKS signature verification in agent_identity."""

from __future__ import annotations

import base64
import json
import socket
import time
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.agent_identity import (
    ANONYMOUS,
    _fetch_jwks,
    _resolve_jwks_uri,
    _verify_jwt_signature,
    check_identity,
    resolve_agent_id,
)

# ─── Helpers ─────────────────────────────────────────────────────────────────

_PUBLIC_TEST_IP = "93.184.216.34"
_real_getaddrinfo = socket.getaddrinfo


@pytest.fixture(autouse=True)
def _public_example_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    """Identity metadata URLs pass the egress guard; resolve test hosts to a public address offline."""

    def fake_getaddrinfo(host, *args, **kwargs):
        if isinstance(host, str) and host.endswith("example.com"):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_PUBLIC_TEST_IP, 0))]
        return _real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr("agent_bom.core.egress_resolution.socket.getaddrinfo", fake_getaddrinfo)
    monkeypatch.delenv("AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS", raising=False)


def _b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def _make_jwt(payload: dict, header: dict | None = None) -> str:
    h = header or {"alg": "RS256", "typ": "JWT", "kid": "test-key"}
    return f"{_b64(h)}.{_b64(payload)}.fakesig"


def _mock_jwks_response(keys: list[dict]) -> MagicMock:
    mock = MagicMock()
    mock.status_code = 200
    mock.json.return_value = {"keys": keys}
    mock.raise_for_status = MagicMock()
    return mock


# ─── _resolve_jwks_uri ────────────────────────────────────────────────────────


def test_resolve_jwks_uri_direct():
    policy = {"jwks_uri": "https://example.com/.well-known/jwks.json"}
    assert _resolve_jwks_uri(policy) == "https://example.com/.well-known/jwks.json"


def test_resolve_jwks_uri_none_when_empty():
    assert _resolve_jwks_uri({}) is None


def test_resolve_jwks_uri_from_oidc_issuer():
    discovery = {"jwks_uri": "https://idp.example.com/jwks"}
    mock_resp = MagicMock()
    mock_resp.json.return_value = discovery
    mock_resp.raise_for_status = MagicMock()
    with patch("httpx.get", return_value=mock_resp):
        result = _resolve_jwks_uri({"oidc_issuer": "https://idp.example.com"})
    assert result == "https://idp.example.com/jwks"


def test_resolve_jwks_uri_oidc_network_failure():
    import httpx

    with patch("httpx.get", side_effect=httpx.ConnectError("timeout")):
        result = _resolve_jwks_uri({"oidc_issuer": "https://idp.example.com"})
    assert result is None


@pytest.mark.parametrize(
    "issuer",
    [
        "http://169.254.169.254/latest/meta-data",
        "http://127.0.0.1:8080",
        "https://10.0.0.5",
        "http://idp.example.com",
        "file:///etc/passwd",
    ],
)
def test_oidc_discovery_refuses_unsafe_issuer_without_fetching(issuer):
    with patch("httpx.get") as mock_get:
        assert _resolve_jwks_uri({"oidc_issuer": issuer}) is None
    mock_get.assert_not_called()


def test_discovered_jwks_uri_pointing_inward_is_not_fetched():
    discovery = MagicMock()
    discovery.json.return_value = {"jwks_uri": "http://169.254.169.254/keys"}
    discovery.raise_for_status = MagicMock()
    with patch("httpx.get", return_value=discovery) as mock_get:
        jwks_uri = _resolve_jwks_uri({"oidc_issuer": "https://idp.example.com"})
        assert _fetch_jwks(str(jwks_uri)) is None
    assert mock_get.call_count == 1


@pytest.mark.parametrize("uri", ["http://169.254.169.254/keys", "https://192.168.1.10/jwks", "gopher://example.com/x"])
def test_fetch_jwks_refuses_unsafe_uri_without_fetching(uri):
    with patch("httpx.get") as mock_get:
        assert _fetch_jwks(uri) is None
    mock_get.assert_not_called()


def test_private_identity_provider_allowed_by_operator_override(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS", "1")
    keys = [{"kty": "RSA", "kid": "k1", "n": "abc", "e": "AQAB"}]
    with patch("httpx.get", return_value=_mock_jwks_response(keys)):
        assert _fetch_jwks("https://10.0.0.5/jwks") == {"keys": keys}


# ─── _fetch_jwks ──────────────────────────────────────────────────────────────


def test_fetch_jwks_success():
    keys = [{"kty": "RSA", "kid": "k1", "n": "abc", "e": "AQAB"}]
    mock_resp = _mock_jwks_response(keys)
    with patch("httpx.get", return_value=mock_resp):
        result = _fetch_jwks("https://example.com/jwks")
    assert result == {"keys": keys}


def test_fetch_jwks_network_error_returns_none():
    import httpx

    with patch("httpx.get", side_effect=httpx.ConnectError("down")):
        result = _fetch_jwks("https://unreachable.example.com/jwks")
    assert result is None


def test_fetch_jwks_cached(monkeypatch):
    """Second call with same URI should NOT make a second HTTP request."""
    import agent_bom.agent_identity as mod

    # Pre-populate cache
    mod._jwks_cache["https://cached.example.com/jwks"] = ({"keys": []}, time.time())
    with patch("httpx.get") as mock_get:
        _fetch_jwks("https://cached.example.com/jwks")
        mock_get.assert_not_called()


# ─── _verify_jwt_signature ───────────────────────────────────────────────────


def test_verify_jwt_none_algorithm_rejected():
    token = _make_jwt({"sub": "x"}, header={"alg": "none", "typ": "JWT"})
    verified, err = _verify_jwt_signature(token, "https://example.com/jwks")
    assert not verified
    assert err is not None
    assert "none" in err.lower() or "not accepted" in err.lower()


def test_verify_jwt_unknown_algorithm_rejected():
    token = _make_jwt({"sub": "x"}, header={"alg": "HS256", "typ": "JWT"})
    verified, err = _verify_jwt_signature(token, "https://example.com/jwks")
    assert not verified


def test_verify_jwt_no_matching_kid():
    keys = [{"kty": "RSA", "kid": "different-kid", "n": "x", "e": "AQAB"}]
    mock_resp = _mock_jwks_response(keys)
    with patch("httpx.get", return_value=mock_resp):
        token = _make_jwt({"sub": "agent"}, header={"alg": "RS256", "kid": "missing-kid"})
        verified, err = _verify_jwt_signature(token, "https://example.com/jwks")
    assert not verified
    assert "kid" in (err or "").lower() or "key" in (err or "").lower()


def test_verify_jwt_jwks_unreachable():
    import httpx

    token = _make_jwt({"sub": "x"})
    with patch("httpx.get", side_effect=httpx.ConnectError("down")):
        verified, err = _verify_jwt_signature(token, "https://down.example.com/jwks")
    assert not verified
    assert "unreachable" in (err or "").lower()


def test_verify_jwt_pyjwt_not_available(monkeypatch):
    """When PyJWT is not installed, returns (False, reason)."""
    import builtins

    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "jwt":
            raise ImportError("No module named 'jwt'")
        return real_import(name, *args, **kwargs)

    token = _make_jwt({"sub": "x"})
    with patch("builtins.__import__", side_effect=mock_import):
        verified, err = _verify_jwt_signature(token, "https://example.com/jwks")
    assert not verified
    assert err is not None


# ─── resolve_agent_id with jwks_uri in policy ─────────────────────────────────


def test_resolve_agent_id_no_jwks_skips_verification():
    """Without jwks_uri, signature is not verified — existing behavior preserved."""
    token = _make_jwt({"sub": "agent-alice", "iat": int(time.time())})
    agent_id, err = resolve_agent_id(token, {})
    assert agent_id == "agent-alice"
    assert err is None


def test_resolve_agent_id_jwks_blocks_on_invalid_signature():
    """With jwks_uri configured and invalid signature, returns ANONYMOUS."""
    import httpx

    token = _make_jwt({"sub": "agent-bad"})
    # expected_audience is required for a direct jwks_uri; set it so this test
    # exercises the signature-verification path (not the audience-pin gate).
    policy = {"jwks_uri": "https://idp.example.com/jwks", "expected_audience": "svc"}
    with patch("httpx.get", side_effect=httpx.ConnectError("unreachable")):
        agent_id, err = resolve_agent_id(token, policy)
    assert agent_id == ANONYMOUS
    assert err is not None
    assert "signature" in err.lower() or "unreachable" in err.lower()


def test_resolve_agent_id_expired_still_blocked_with_jwks():
    token = _make_jwt({"sub": "agent-x", "exp": int(time.time()) - 60})
    # Expiry is checked before signature — should fail on expiry first
    agent_id, err = resolve_agent_id(token, {"jwks_uri": "https://idp.example.com/jwks"})
    assert agent_id == ANONYMOUS
    assert "expired" in (err or "").lower()


# ─── check_identity integration ──────────────────────────────────────────────


def test_check_identity_jwks_required_blocks_on_no_jwks_key():
    """require_agent_identity + jwks_uri + invalid token → blocked."""
    import httpx

    def _msg(token):
        return {
            "method": "tools/call",
            "params": {"name": "x", "arguments": {}, "_meta": {"agent_identity": token}},
        }

    token = _make_jwt({"sub": "agent-z"})
    policy = {"require_agent_identity": True, "jwks_uri": "https://idp.example.com/jwks"}
    with patch("httpx.get", side_effect=httpx.ConnectError("down")):
        agent_id, block = check_identity(_msg(token), policy)
    assert block is not None


def test_check_identity_no_jwks_configured_audit_mode_passes_as_before():
    """Without jwks_uri, non-enforcing audit mode still resolves a well-formed JWT."""

    def _msg(token):
        return {
            "method": "tools/call",
            "params": {"name": "x", "arguments": {}, "_meta": {"agent_identity": token}},
        }

    token = _make_jwt({"sub": "agent-ok"})
    agent_id, block = check_identity(_msg(token), {})
    assert agent_id == "agent-ok"
    assert block is None


def test_check_identity_required_jwt_without_verification_policy_blocks():
    """Enforced identity mode must not trust an unsigned JWT identity claim."""

    def _msg(token):
        return {
            "method": "tools/call",
            "params": {"name": "x", "arguments": {}, "_meta": {"agent_identity": token}},
        }

    token = _make_jwt({"sub": "agent-claimed"})
    agent_id, block = check_identity(_msg(token), {"require_agent_identity": True})
    assert agent_id == ANONYMOUS
    assert block is not None
    assert "signature verification required" in block


# ─── F2: aud/iss binding in JWT verification ──────────────────────────────────


def _signing_key():
    from agent_bom.api.oauth_as import OAuthSigningKey

    return OAuthSigningKey()


def _signed_identity_jwt(key, *, sub="agent-x", aud="service-b", iss="https://issuer-b"):
    now = int(time.time())
    return key.sign({"sub": sub, "aud": aud, "iss": iss, "iat": now, "exp": now + 3600})


def test_verify_jwt_wrong_audience_rejected_when_pinned():
    key = _signing_key()
    token = _signed_identity_jwt(key, aud="service-b")
    with patch("agent_bom.agent_identity._fetch_jwks", return_value=key.jwks()):
        verified, err = _verify_jwt_signature(token, "https://idp/jwks", expected_audience="service-a", expected_issuer="https://issuer-b")
    assert not verified
    assert err and "claim mismatch" in err


def test_verify_jwt_wrong_issuer_rejected_when_pinned():
    key = _signing_key()
    token = _signed_identity_jwt(key, iss="https://issuer-b")
    with patch("agent_bom.agent_identity._fetch_jwks", return_value=key.jwks()):
        verified, err = _verify_jwt_signature(token, "https://idp/jwks", expected_audience="service-b", expected_issuer="https://issuer-a")
    assert not verified
    assert err and "claim mismatch" in err


def test_verify_jwt_matching_aud_iss_accepted():
    key = _signing_key()
    token = _signed_identity_jwt(key)
    with patch("agent_bom.agent_identity._fetch_jwks", return_value=key.jwks()):
        verified, err = _verify_jwt_signature(token, "https://idp/jwks", expected_audience="service-b", expected_issuer="https://issuer-b")
    assert verified
    assert err is None


def test_resolve_agent_id_rejects_audience_confusion():
    key = _signing_key()
    token = _signed_identity_jwt(key, sub="agent-x", aud="service-b", iss="https://issuer-b")
    policy = {
        "jwks_uri": "https://idp/jwks",
        "expected_audience": "service-a",
        "expected_issuer": "https://issuer-b",
    }
    with patch("agent_bom.agent_identity._fetch_jwks", return_value=key.jwks()):
        agent_id, err = resolve_agent_id(token, policy)
    assert agent_id == ANONYMOUS
    assert err and "signature invalid" in err


def test_resolve_agent_id_accepts_matching_aud_iss():
    key = _signing_key()
    token = _signed_identity_jwt(key, sub="agent-x", aud="service-b", iss="https://issuer-b")
    policy = {
        "jwks_uri": "https://idp/jwks",
        "expected_audience": "service-b",
        "expected_issuer": "https://issuer-b",
    }
    with patch("agent_bom.agent_identity._fetch_jwks", return_value=key.jwks()):
        agent_id, err = resolve_agent_id(token, policy)
    assert err is None
    assert agent_id == "agent-x"


def test_resolve_agent_id_direct_jwks_without_audience_is_rejected():
    # A direct jwks_uri with NO expected_audience must fail closed: a validly-signed
    # token minted by the same IdP keys for a DIFFERENT relying party would otherwise
    # be accepted (audience confusion). The operator must pin expected_audience.
    key = _signing_key()
    token = _signed_identity_jwt(key, sub="agent-x", aud="some-other-service", iss="https://whatever")
    policy = {"jwks_uri": "https://idp/jwks"}
    with patch("agent_bom.agent_identity._fetch_jwks", return_value=key.jwks()):
        agent_id, err = resolve_agent_id(token, policy)
    assert agent_id == ANONYMOUS
    assert err and "audience" in err.lower() and "expected_audience" in err
