"""DPoP-bound, narrowly scoped Okta machine authentication contracts."""

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from agent_bom.identity.okta_oauth import OktaOAuth


@pytest.fixture
def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def test_nonce_exchange_and_distinct_bound_proofs(key):
    calls = []

    def handler(request):
        calls.append(request)
        proof = jwt.decode(request.headers["dpop"], options={"verify_signature": False})
        assert proof["htm"] == "POST"
        assert proof["htu"] == "https://example.okta.com/oauth2/v1/token"
        if len(calls) == 1:
            return httpx.Response(400, json={"error": "use_dpop_nonce"}, headers={"DPoP-Nonce": "challenge"})
        assert proof["nonce"] == "challenge"
        return httpx.Response(
            200,
            json={"access_token": "test-access", "token_type": "DPoP", "scope": "okta.apps.read okta.apiTokens.read", "expires_in": 3600},
        )

    auth = OktaOAuth("https://example.okta.com", "client-id", key, "test-kid")
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        first = auth.headers(client, "GET", "https://example.okta.com/api/v1/apps?limit=200")
        second = auth.headers(client, "GET", "https://example.okta.com/api/v1/apps?limit=200")
    a, b = [jwt.decode(h["DPoP"], options={"verify_signature": False}) for h in (first, second)]
    assert len(calls) == 2
    assert first["Authorization"] == "DPoP test-access"
    assert a["jti"] != b["jti"]
    assert a["ath"] == b["ath"]
    assert a["htu"] == "https://example.okta.com/api/v1/apps"
    assert "test-access" not in repr(auth)


@pytest.mark.parametrize("overrides", [{"token_type": "Bearer"}, {"scope": "okta.apps.manage"}, {"expires_in": 0}, {"access_token": ""}])
def test_token_contract_fails_closed(key, overrides):
    payload = {
        "access_token": "test-access",
        "token_type": "DPoP",
        "scope": "okta.apps.read okta.apiTokens.read",
        "expires_in": 3600,
        **overrides,
    }
    auth = OktaOAuth("https://example.okta.com", "client-id", key, "test-kid")
    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=payload))) as client:
        with pytest.raises(ValueError):
            auth.headers(client, "GET", "https://example.okta.com/api/v1/apps")


def test_auth_rejects_cross_tenant_before_token_request(key):
    def handler(request):
        pytest.fail("Must validate target before authenticating")

    auth = OktaOAuth("https://example.okta.com", "client-id", key, "test-kid")
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ValueError):
            auth.headers(client, "GET", "https://other.okta.com/api/v1/apps")


def test_private_key_loader_rejects_readable_file_and_symlink(tmp_path, monkeypatch, key):
    from agent_bom.identity.okta_oauth import from_environment

    path = tmp_path / "key.pem"
    path.write_bytes(key)
    path.chmod(0o644)
    monkeypatch.setenv("AGENT_BOM_OKTA_CLIENT_ID", "fixture")
    monkeypatch.setenv("AGENT_BOM_OKTA_KEY_ID", "fixture")
    monkeypatch.setenv("AGENT_BOM_OKTA_PRIVATE_KEY_FILE", str(path))
    with pytest.raises(ValueError, match="owner-only"):
        from_environment("https://example.okta.com")
    path.chmod(0o600)
    assert isinstance(from_environment("https://example.okta.com"), OktaOAuth)
    link = tmp_path / "link.pem"
    link.symlink_to(path)
    monkeypatch.setenv("AGENT_BOM_OKTA_PRIVATE_KEY_FILE", str(link))
    with pytest.raises(OSError):
        from_environment("https://example.okta.com")
