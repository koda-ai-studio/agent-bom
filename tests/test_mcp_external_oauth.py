"""External MCP access tokens cannot widen the server's authority."""

import json
import time
from unittest.mock import Mock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from agent_bom.mcp_tools.oauth import OAuthConfig, OAuthTokenVerifier

ISSUER = "https://identity.example/realms/agent-bom"
AUDIENCE = "https://mcp.example/mcp"


@pytest.fixture
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def verifier(signing_key, monkeypatch):
    verifier = OAuthTokenVerifier(
        OAuthConfig(
            ISSUER,
            AUDIENCE,
            ISSUER + "/certs",
            frozenset({"approved-user"}),
            "tenant-a",
            ISSUER + "/introspect",
            "resource",
            "test-only-secret",
        )
    )
    monkeypatch.setattr(verifier, "_active", lambda token, claims: True)
    verifier.keys = Mock()
    verifier.keys.get_signing_key_from_jwt.return_value.key = signing_key.public_key()
    return verifier


def token(key, **changes):
    now = int(time.time())
    claims = dict(iss=ISSUER, aud=AUDIENCE, sub="approved-user", iat=now, exp=now + 600, scope="read", tenant_id="tenant-a")
    claims.update(changes)
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": "first"})


@pytest.mark.asyncio
async def test_approved_token_is_read_only(verifier, signing_key):
    result = await verifier.verify_token(token(signing_key, scope="read admin scan:write", roles=["admin"]))
    assert result is not None
    assert result.scopes == ["read"]
    assert result.client_id == "oauth:tenant-a:approved-user"
    assert result.resource == AUDIENCE


@pytest.mark.parametrize(
    "changes",
    [
        {"iss": "https://other.example"},
        {"aud": "other-api"},
        {"sub": "unapproved"},
        {"scope": ["read"]},
        {"exp": 1},
        lambda: {"exp": int(time.time()) + 7200},
        lambda: {"iat": int(time.time()) + 30},
        {"iat": True},
        {"sub": None},
    ],
)
@pytest.mark.asyncio
async def test_rejects_invalid_claims(verifier, signing_key, changes):
    # Resolve relative timestamps at execution, after potentially slow collection.
    changes = changes() if callable(changes) else changes
    assert await verifier.verify_token(token(signing_key, **changes)) is None


@pytest.mark.asyncio
async def test_rejects_invalid_signature_and_provider_outage(verifier):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert await verifier.verify_token(token(other)) is None
    verifier.keys.get_signing_key_from_jwt.side_effect = OSError("provider unavailable")
    assert await verifier.verify_token(token(other)) is None


@pytest.fixture
def oauth_env(monkeypatch):
    for key, value in {"ISSUER": ISSUER, "AUDIENCE": AUDIENCE, "JWKS_URI": ISSUER + "/certs", "SUBJECTS": "approved-user"}.items():
        monkeypatch.setenv("AGENT_BOM_MCP_OAUTH_" + key, value)
    monkeypatch.setenv("AGENT_BOM_MCP_PUBLIC_URL", "https://mcp.example")
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")
    monkeypatch.setenv("AGENT_BOM_MCP_OAUTH_INTROSPECTION_URL", ISSUER + "/introspect")
    monkeypatch.setenv("AGENT_BOM_MCP_OAUTH_INTROSPECTION_CLIENT_ID", "resource")
    monkeypatch.setenv("AGENT_BOM_MCP_OAUTH_INTROSPECTION_CLIENT_SECRET", "test-only-secret")
    monkeypatch.delenv("AGENT_BOM_MCP_OPERATOR_TOKEN", raising=False)


def test_incomplete_or_wildcard_configuration_fails(oauth_env, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_MCP_OAUTH_SUBJECTS", "*")
    with pytest.raises(ValueError, match="explicit approved"):
        OAuthConfig.from_env()
    monkeypatch.delenv("AGENT_BOM_MCP_OAUTH_SUBJECTS")
    with pytest.raises(ValueError, match="requires"):
        OAuthConfig.from_env()


def test_metadata_and_actual_transport_authorization(oauth_env, monkeypatch, verifier, signing_key):
    from agent_bom.mcp_server_factory import create_fastmcp_server

    monkeypatch.setattr("agent_bom.mcp_tools.oauth.OAuthTokenVerifier", lambda config: verifier)
    server = create_fastmcp_server(
        host="0.0.0.0", port=8000, bearer_token=None, version="test", token_verifier_factory=Mock(), oauth_enabled=True
    )
    with TestClient(server.streamable_http_app(host="0.0.0.0"), base_url="https://mcp.example") as client:
        metadata = client.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.status_code == 200
        assert metadata.json()["authorization_servers"] == [ISSUER]
        assert metadata.json()["resource"] == AUDIENCE
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
        }
        headers = {"Accept": "application/json, text/event-stream"}
        assert client.post("/mcp", json=message, headers=headers).status_code == 401
        headers["Authorization"] = "Bearer " + token(signing_key)
        initialized = client.post("/mcp", json=message, headers=headers)
        assert initialized.status_code == 200
        headers["mcp-session-id"] = initialized.headers["mcp-session-id"]
        headers["mcp-protocol-version"] = "2025-11-25"
        client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=headers)
        listing = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, headers=headers)
        assert listing.status_code == 200
        assert '"tools"' in listing.text
        assert client.post("/oauth/register", json={}).status_code == 404


def test_oauth_configuration_does_not_activate_stdio_or_other_servers(oauth_env):
    from agent_bom.mcp_server_factory import create_fastmcp_server

    server = create_fastmcp_server(host="127.0.0.1", port=8000, bearer_token=None, version="test", token_verifier_factory=Mock())
    assert server.settings.auth is None


@pytest.mark.asyncio
async def test_jwks_rotates_and_new_access_token_works(monkeypatch, signing_key):
    from jwt import PyJWKClient

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keys = [
        {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(k.public_key())), "kid": kid}
        for k, kid in [(signing_key, "first"), (other, "second")]
    ]
    verifier = OAuthTokenVerifier(
        OAuthConfig(
            ISSUER,
            AUDIENCE,
            ISSUER + "/certs",
            frozenset({"approved-user"}),
            "tenant-a",
            ISSUER + "/introspect",
            "resource",
            "test-only-secret",
        )
    )
    monkeypatch.setattr(verifier, "_active", lambda token, claims: True)
    responses = iter([{"keys": [keys[0]]}, {"keys": keys}])

    def fetch():
        data = next(responses)
        verifier.keys.jwk_set_cache.put(data)
        return data

    monkeypatch.setattr(verifier.keys, "fetch_data", fetch)
    assert isinstance(verifier.keys, PyJWKClient)
    assert await verifier.verify_token(token(signing_key)) is not None
    now = int(time.time())
    renewed = jwt.encode(
        dict(iss=ISSUER, aud=AUDIENCE, sub="approved-user", iat=now, exp=now + 600, scope="read", tenant_id="tenant-a"),
        other,
        algorithm="RS256",
        headers={"kid": "second"},
    )
    assert await verifier.verify_token(renewed) is not None


@pytest.mark.asyncio
async def test_expired_credential_does_not_require_server_restart(verifier, signing_key):
    now = int(time.time())
    assert await verifier.verify_token(token(signing_key, iat=now - 600, exp=now - 1)) is None
    assert await verifier.verify_token(token(signing_key)) is not None


def test_external_and_static_modes_cannot_be_combined(oauth_env):
    from agent_bom.mcp_server_factory import create_fastmcp_server

    with pytest.raises(ValueError, match="not both"):
        create_fastmcp_server(
            host="0.0.0.0",
            port=8000,
            bearer_token="existing",
            version="test",
            token_verifier_factory=Mock(),
            oauth_enabled=True,
        )


def test_server_card_advertises_oauth_when_the_issuer_protects_the_transport(oauth_env, monkeypatch, tmp_path, verifier):
    from agent_bom.mcp_server import create_mcp_server

    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setattr("agent_bom.mcp_tools.oauth.OAuthTokenVerifier", lambda config: verifier)
    server = create_mcp_server(host="0.0.0.0", port=8000, bearer_token=None, oauth_enabled=True)
    with TestClient(server.streamable_http_app(host="0.0.0.0"), base_url="https://mcp.example") as client:
        card = client.get("/.well-known/mcp/server-card.json").json()
        assert card["authentication"] == {"required": True, "schemes": ["oauth2"], "public_readonly": False, "anonymous_tools": []}
        assert client.get("/.well-known/oauth-protected-resource/mcp").json()["authorization_servers"] == [ISSUER]
        assert client.post("/mcp", json={}).status_code == 401


@pytest.mark.parametrize("deployment", ["railway", "procfile"])
def test_hosted_startup_preserves_configured_oauth(deployment, oauth_env, monkeypatch, tmp_path, verifier, signing_key):
    """The shipped startup command must work with an existing OAuth deployment."""
    from pathlib import Path

    from agent_bom.mcp_server import create_mcp_server

    root = Path(__file__).resolve().parents[1]
    if deployment == "railway":
        manifest = json.loads((root / "railway.json").read_text())
        command = manifest["deploy"].get("startCommand")
        if command is None:
            command = next(line for line in (root / "deploy/docker/Dockerfile.sse").read_text().splitlines() if line.startswith("CMD "))
    else:
        command = (root / "deploy/Procfile").read_text()
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_MCP_PUBLIC_READONLY", "1" if "--public-readonly" in command else "0")
    monkeypatch.setattr("agent_bom.mcp_tools.oauth.OAuthTokenVerifier", lambda config: verifier)
    server = create_mcp_server(host="0.0.0.0", port=8000, bearer_token=None, oauth_enabled=True)
    with TestClient(server.streamable_http_app(host="0.0.0.0"), base_url="https://mcp.example") as client:
        card = client.get("/.well-known/mcp/server-card.json").json()
        assert card["authentication"]["schemes"] == ["oauth2"]
        assert card["authentication"]["public_readonly"] is False
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "test", "version": "1"}},
        }
        headers = {"Accept": "application/json, text/event-stream"}
        assert client.post("/mcp", json=message, headers=headers).status_code == 401
        headers["Authorization"] = "Bearer " + token(signing_key)
        assert client.post("/mcp", json=message, headers=headers).status_code == 200


@pytest.mark.asyncio
async def test_valid_token_without_read_scope_grants_no_authority(verifier, signing_key):
    result = await verifier.verify_token(token(signing_key, scope="admin"))
    assert result is not None
    assert result.scopes == []  # SDK required_scopes rejects this token with 403.
