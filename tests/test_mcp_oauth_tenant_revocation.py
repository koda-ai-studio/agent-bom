"""OAuth tenant and revocation checks apply before any MCP request executes."""

import json
import time
from unittest.mock import Mock

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from agent_bom.mcp_tools.oauth import OAuthConfig, OAuthTokenVerifier

ISSUER = "https://identity.example/realm"
AUDIENCE = "https://mcp.example/mcp"


@pytest.fixture
def oauth_boundary(monkeypatch):
    for key, value in {
        "ISSUER": ISSUER,
        "AUDIENCE": AUDIENCE,
        "JWKS_URI": ISSUER + "/certs",
        "SUBJECTS": "approved-user",
        "INTROSPECTION_URL": ISSUER + "/introspect",
        "INTROSPECTION_CLIENT_ID": "resource-server",
        "INTROSPECTION_CLIENT_SECRET": "test-only-introspection-secret",
    }.items():
        monkeypatch.setenv("AGENT_BOM_MCP_OAUTH_" + key, value)
    monkeypatch.setenv("AGENT_BOM_MCP_TENANT_ID", "tenant-a")
    monkeypatch.setattr("agent_bom.security.validate_url", lambda url: None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    claims = dict(iss=ISSUER, aud=AUDIENCE, sub="approved-user", iat=now, exp=now + 600, scope="read", tenant_id="tenant-a")
    state = {"active": True, **claims}
    calls = []

    def respond(request):
        calls.append(request)
        return httpx.Response(200, json=state)

    client = httpx.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: client(transport=httpx.MockTransport(respond), **kwargs))
    verifier = OAuthTokenVerifier(OAuthConfig.from_env())
    verifier.keys = Mock()
    verifier.keys.get_signing_key_from_jwt.return_value.key = key.public_key()

    def issue(**changes):
        return jwt.encode({**claims, **changes}, key, algorithm="RS256", headers={"kid": "fixture"})

    return verifier, issue, state, calls


@pytest.mark.asyncio
@pytest.mark.parametrize("tenant", ["tenant-b", "", None, ["tenant-a", "tenant-b"]])
async def test_signed_token_cannot_select_another_tenant(oauth_boundary, tenant):
    verifier, issue, _, _ = oauth_boundary
    assert await verifier.verify_token(issue(tenant_id=tenant)) is None


@pytest.mark.asyncio
async def test_revoked_token_is_denied_on_the_next_request(oauth_boundary):
    verifier, issue, state, calls = oauth_boundary
    token = issue()
    assert await verifier.verify_token(token) is not None
    state["active"] = False
    assert await verifier.verify_token(token) is None
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_introspection_cannot_change_signed_identity(oauth_boundary):
    verifier, issue, state, _ = oauth_boundary
    state["tenant_id"] = "tenant-b"
    assert await verifier.verify_token(issue()) is None


@pytest.mark.asyncio
async def test_active_must_be_a_boolean_and_not_a_truthy_string(oauth_boundary):
    verifier, issue, state, _ = oauth_boundary
    state["active"] = "false"
    assert await verifier.verify_token(issue()) is None


def test_oauth_requires_explicit_deployment_tenant(oauth_boundary, monkeypatch):
    monkeypatch.delenv("AGENT_BOM_MCP_TENANT_ID")
    monkeypatch.delenv("AGENT_BOM_TENANT_ID", raising=False)
    with pytest.raises(ValueError, match="tenant"):
        OAuthConfig.from_env()


@pytest.mark.asyncio
async def test_oauth_catalog_excludes_writes_and_activity(oauth_boundary, monkeypatch, tmp_path):
    from agent_bom.mcp_server import create_mcp_server
    from agent_bom.mcp_tools.tool_capabilities import _TOOL_CAPABILITY_CLASSES

    verifier, _, _, _ = oauth_boundary
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_MCP_PUBLIC_URL", "https://mcp.example")
    monkeypatch.setattr("agent_bom.mcp_tools.oauth.OAuthTokenVerifier", lambda config: verifier)
    server = create_mcp_server(oauth_enabled=True, profile="full")
    tools = await server.list_tools()
    assert tools
    assert "agent_activity" not in {tool.name for tool in tools}
    for tool in tools:
        assert "WRITE" not in _TOOL_CAPABILITY_CLASSES[tool.name]
        assert "PROCESS_EXECUTION" not in _TOOL_CAPABILITY_CLASSES[tool.name]
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False
        assert isinstance(tool.annotations.open_world_hint, bool)


def test_transport_cannot_read_another_tenants_persisted_assets(oauth_boundary, monkeypatch, tmp_path):
    from starlette.testclient import TestClient

    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.graph import EntityType, UnifiedGraph, UnifiedNode
    from agent_bom.mcp_server import create_mcp_server

    verifier, issue, state, _ = oauth_boundary
    store = SQLiteGraphStore(tmp_path / "graph.db")
    for tenant in ("tenant-a", "tenant-b"):
        graph = UnifiedGraph(scan_id="shared-id", tenant_id=tenant)
        graph.add_node(UnifiedNode(id="package:private", entity_type=EntityType.PACKAGE, label=f"{tenant}-private-package"))
        store.save_graph(graph)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_MCP_PUBLIC_URL", "https://mcp.example")
    monkeypatch.setattr("agent_bom.api.stores._get_graph_store", lambda: store)
    monkeypatch.setattr("agent_bom.mcp_tools.oauth.OAuthTokenVerifier", lambda config: verifier)
    server = create_mcp_server(oauth_enabled=True, profile="graph")
    with TestClient(server.streamable_http_app(host="0.0.0.0"), base_url="https://mcp.example") as client:
        headers = {"Accept": "application/json, text/event-stream", "Authorization": "Bearer " + issue(), "X-Tenant-ID": "tenant-b"}
        initialized = client.post(
            "/mcp",
            headers=headers,
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "tenant-test", "version": "1"},
                },
            },
        )
        assert initialized.status_code == 200
        headers["mcp-session-id"] = initialized.headers["mcp-session-id"]
        client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"})

        def inventory(tenant):
            response = client.post(
                "/mcp",
                headers=headers,
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "inventory_list",
                        "arguments": {"tenant_id": tenant, "scan_id": "shared-id"},
                    },
                },
            )
            assert response.status_code == 200
            return json.loads(next(line[6:] for line in response.text.splitlines() if line.startswith("data: ")))["result"]

        own = inventory("tenant-a")
        assert own.get("isError") is not True
        assert "tenant-a-private-package" in json.dumps(own)
        assert "tenant-b-private-package" not in json.dumps(own)
        denied = inventory("tenant-b")
        assert denied["isError"] is True
        assert "tenant-b-private-package" not in json.dumps(denied)
        # A signed tenant-B token cannot even initialize this tenant-A endpoint.
        headers["Authorization"] = "Bearer " + issue(tenant_id="tenant-b")
        assert client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"}).status_code == 401
        headers["Authorization"] = "Bearer " + issue()
        state["scope"] = "other"
        headers["Authorization"] = "Bearer " + issue(scope="other")
        insufficient = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"})
        assert insufficient.status_code == 403
        assert "insufficient_scope" in insufficient.headers["www-authenticate"]
        state["scope"] = "read"
        headers["Authorization"] = "Bearer " + issue()
        state["active"] = False
        assert client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 4, "method": "tools/list"}).status_code == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["timeout", "redirect", "malformed", "oversize", "unavailable"])
async def test_issuer_failure_never_falls_back_to_signature_only(oauth_boundary, monkeypatch, failure):
    verifier, issue, _, _ = oauth_boundary

    def respond(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("fixture timeout", request=request)
        if failure == "redirect":
            return httpx.Response(302, headers={"location": "https://other.example/introspect"})
        if failure == "oversize":
            return httpx.Response(200, content=b" " * 262145)
        if failure == "malformed":
            return httpx.Response(200, json=[True])
        return httpx.Response(503)

    # Recover the real class: the fixture installed a client factory already.
    real_client = httpx._client.Client
    monkeypatch.setattr(httpx, "Client", lambda **kwargs: real_client(transport=httpx.MockTransport(respond), **kwargs))
    assert await verifier.verify_token(issue()) is None


def test_introspection_secret_is_not_in_config_repr(oauth_boundary):
    verifier, _, _, _ = oauth_boundary
    assert verifier.config.introspection_client_secret not in repr(verifier.config)


def test_introspection_cannot_send_tokens_to_another_origin(oauth_boundary, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_MCP_OAUTH_INTROSPECTION_URL", "https://other.example/introspect")
    with pytest.raises(ValueError, match="issuer origin"):
        OAuthConfig.from_env()


@pytest.mark.asyncio
async def test_introspection_basic_credentials_are_form_encoded(oauth_boundary):
    import base64
    from dataclasses import replace

    verifier, issue, _, calls = oauth_boundary
    verifier.config = replace(verifier.config, introspection_client_id=AUDIENCE, introspection_client_secret="fixture:secret with+symbols")
    assert await verifier.verify_token(issue()) is not None
    encoded = calls[-1].headers["authorization"].removeprefix("Basic ")
    assert base64.b64decode(encoded).decode() == "https%3A%2F%2Fmcp.example%2Fmcp:fixture%3Asecret+with%2Bsymbols"
