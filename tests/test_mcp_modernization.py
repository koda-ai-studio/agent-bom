"""Wire and inventory regressions for current MCP surfaces."""

import asyncio
import json

import httpx
import pytest

from agent_bom.discovery.config_parsers import parse_mcp_config
from agent_bom.runtime.gateway_relay_contract import forward_jsonrpc_http


def test_auth_and_sandbox_are_evidence_without_secret_values():
    server = parse_mcp_config(
        {
            "servers": {
                "remote": {
                    "type": "http",
                    "url": "https://example.com/mcp",
                    "headers": {"Authorization": "Bearer private-fixture"},
                    "oauth": {"clientId": "client", "enterpriseManaged": True},
                    "sandboxEnabled": True,
                }
            },
            "sandbox": {"network": {"allowedDomains": ["example.com"]}},
        },
        "fixture",
    )[0]
    assert server.auth_mode == "configured-http-auth"
    assert server.connection_metadata["header_names"] == ["Authorization"]
    assert server.connection_metadata["sandbox"]["network"]["allowedDomains"] == ["example.com"]
    assert "private-fixture" not in repr(server)


def test_gateway_decodes_sse_and_emits_protocol_headers():
    async def run():
        def handler(request):
            assert request.headers["Mcp-Method"] == "tools/call"
            assert request.headers["Mcp-Name"] == "echo"
            assert "text/event-stream" in request.headers["Accept"]
            result = {"jsonrpc": "2.0", "id": 1, "result": {"resultType": "complete", "content": [{"type": "text", "text": "ok"}]}}
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                text=": keepalive\n\nevent: message\ndata: " + json.dumps(result) + "\n\n",
            )

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            result = await forward_jsonrpc_http(
                upstream_url="https://example.com/mcp",
                message={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "echo", "arguments": {}}},
                headers={},
                client=client,
            )
        assert result.message["result"]["content"][0]["text"] == "ok"

    asyncio.run(run())


def test_gateway_rejects_mismatched_response_id():
    async def run():
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"jsonrpc": "2.0", "id": 2, "result": {}}))
        ) as client:
            with pytest.raises(ValueError, match="response"):
                await forward_jsonrpc_http(
                    upstream_url="https://example.com/mcp",
                    message={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                    headers={},
                    client=client,
                )

    asyncio.run(run())


def test_operator_scan_auth_is_bound_and_not_persisted(tmp_path, monkeypatch):
    from agent_bom.discovery.mcp_metadata import scan_auth_headers
    from agent_bom.models import MCPServer

    server = MCPServer(name="remote", url="https://example.com/mcp")
    config = tmp_path / "auth.json"
    config.write_text(json.dumps({server.canonical_id: {"url": server.url, "header_env": {"Authorization": "TEST_MCP_TOKEN"}}}))
    monkeypatch.setenv("AGENT_BOM_MCP_SCAN_AUTH_FILE", str(config))
    monkeypatch.setenv("TEST_MCP_TOKEN", "Bearer fixture")
    assert scan_auth_headers(server) == {"Authorization": "Bearer fixture"}
    assert "Bearer fixture" not in repr(server)
    config.write_text(
        json.dumps({server.canonical_id: {"url": "https://other.example/mcp", "header_env": {"Authorization": "TEST_MCP_TOKEN"}}})
    )
    with pytest.raises(ValueError, match="binding"):
        scan_auth_headers(server)


def test_oauth_issuer_mismatch_blocks_before_credentials(monkeypatch):
    from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamConfigError, reset_oauth_cache_for_tests

    reset_oauth_cache_for_tests()
    monkeypatch.setenv("TEST_CLIENT_ID", "fixture")
    monkeypatch.setenv("TEST_CLIENT_SECRET", "fixture-secret")
    posts = []

    def handler(request):
        if request.method == "POST":
            posts.append(request)
        return httpx.Response(200, json={"issuer": "https://wrong.example", "token_endpoint": "https://id.example/token"})

    monkeypatch.setattr(
        "agent_bom.runtime.egress_transport.build_pinned_async_client",
        lambda **kw: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    upstream = UpstreamConfig(
        name="fixture",
        url="https://example.com/mcp",
        auth="oauth2_client_credentials",
        oauth_issuer="https://id.example",
        oauth_token_url="https://id.example/token",
        oauth_client_id_env="TEST_CLIENT_ID",
        oauth_client_secret_env="TEST_CLIENT_SECRET",
    )
    with pytest.raises(UpstreamConfigError, match="issuer"):
        asyncio.run(upstream.resolve_auth_headers())
    assert posts == []


def test_continuation_sensitive_input_is_scanned():
    from agent_bom.proxy_scanner import ScanConfig, scan_tool_call
    from agent_bom.runtime.mcp_protocol import inspection_arguments

    msg = {"params": {"arguments": {"query": "safe"}, "inputResponses": {"login": {"content": {"key": "AKIAIOSFODNN7EXAMPLE"}}}}}
    config = ScanConfig(enabled=True, mode="enforce", scanners=["secrets"])
    assert not scan_tool_call("echo", msg["params"]["arguments"], config)
    assert scan_tool_call("echo", inspection_arguments(msg, msg["params"]["arguments"]), config)


@pytest.mark.asyncio
async def test_authenticated_modern_introspection_wire(tmp_path, monkeypatch):
    import socket
    from datetime import datetime, timedelta, timezone

    import uvicorn

    from agent_bom.mcp_introspect import introspect_server
    from agent_bom.mcp_server import create_mcp_server
    from agent_bom.models import MCPServer, TransportType

    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat())
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("TEST_MCP_WIRE_TOKEN", "Bearer fixture-wire-token")
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    port = sock.getsockname()[1]
    app = create_mcp_server(port=port, bearer_token="fixture-wire-token").streamable_http_app()
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="on"))
    task = asyncio.create_task(server.serve(sockets=[sock]))
    try:
        async with asyncio.timeout(10):
            while not server.started:
                await asyncio.sleep(0.01)
        target = MCPServer(
            name="wire",
            url=f"http://127.0.0.1:{port}/mcp",
            transport=TransportType.STREAMABLE_HTTP,
            connection_metadata={"header_names": ["Authorization"]},
        )
        missing = await introspect_server(target, timeout=5)
        assert not missing.success and "credentials required" in missing.error
        auth = tmp_path / "auth.json"
        auth.write_text(json.dumps({target.canonical_id: {"url": target.url, "header_env": {"Authorization": "TEST_MCP_WIRE_TOKEN"}}}))
        monkeypatch.setenv("AGENT_BOM_MCP_SCAN_AUTH_FILE", str(auth))
        result = await introspect_server(target, timeout=10)
        assert result.success, result.error
        assert result.protocol_version == "2026-07-28"
        assert result.tool_count == 8
        assert "fixture-wire-token" not in json.dumps(result.to_dict())
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, 10)
        sock.close()


def test_boolean_schemas_have_distinct_identity():
    from agent_bom.enforcement import _extract_schema_descriptions
    from agent_bom.models import MCPTool

    tools = [MCPTool(name="echo", description="", input_schema=value) for value in (False, True, {})]
    assert len({tool.canonical_id for tool in tools}) == 3
    assert _extract_schema_descriptions(False) == []


def test_modern_headers_require_matching_body_metadata():
    from starlette.datastructures import Headers

    from agent_bom.runtime.mcp_protocol import MODERN_PROTOCOL, VERSION_KEY, request_headers, validate_request_headers

    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "écho", "_meta": {VERSION_KEY: MODERN_PROTOCOL, "io.modelcontextprotocol/clientCapabilities": {}}},
    }
    headers = request_headers(message, {})
    validate_request_headers(message, Headers(headers))
    headers["Mcp-Name"] = "other"
    with pytest.raises(ValueError, match="match"):
        validate_request_headers(message, Headers(headers))
    message["params"]["_meta"] = None
    with pytest.raises(ValueError, match="metadata"):
        validate_request_headers(message, Headers(headers))


@pytest.mark.asyncio
async def test_parameter_headers_use_authenticated_catalog_and_reject_cycles():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from agent_bom.runtime.mcp_protocol import MODERN_PROTOCOL, VERSION_KEY, parameter_headers

    message = {"method": "tools/call", "params": {"name": "echo", "arguments": {"region": "west"}, "_meta": {VERSION_KEY: MODERN_PROTOCOL}}}
    transport = SimpleNamespace(
        forward=AsyncMock(
            return_value=SimpleNamespace(
                message={
                    "result": {
                        "tools": [
                            {
                                "name": "echo",
                                "inputSchema": {"type": "object", "properties": {"region": {"type": "string", "x-mcp-header": "Region"}}},
                            }
                        ]
                    }
                }
            )
        )
    )
    headers = await parameter_headers(transport, None, message, {"Authorization": "Bearer fixture"})
    assert headers == {"Mcp-Param-Region": "west"}
    assert transport.forward.call_args.args[0].headers == {"Authorization": "Bearer fixture"}
    transport.forward.return_value = SimpleNamespace(message={"result": {"tools": [], "nextCursor": "same"}})
    with pytest.raises(ValueError, match="pagination"):
        await parameter_headers(transport, None, message, {})


@pytest.mark.asyncio
async def test_apps_resources_are_hashed_without_html_in_inventory():
    import hashlib
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from agent_bom.mcp_introspect import ServerIntrospection, _query_capabilities
    from agent_bom.models import MCPServer

    html = "<html>private fixture body</html>"
    tool = SimpleNamespace(
        name="view",
        description="View",
        input_schema=False,
        output_schema=True,
        annotations=None,
        meta={"ui": {"resourceUri": "ui://view", "permissions": {"camera": {}}}},
    )
    session = SimpleNamespace(
        list_tools=AsyncMock(return_value=SimpleNamespace(tools=[tool])),
        list_resources=AsyncMock(return_value=SimpleNamespace(resources=[])),
        list_prompts=AsyncMock(return_value=SimpleNamespace(prompts=[])),
        read_resource=AsyncMock(
            return_value=SimpleNamespace(
                contents=[
                    SimpleNamespace(
                        text=html, mime_type="text/html;profile=mcp-app", meta={"ui": {"csp": {"connectDomains": ["https://example.com"]}}}
                    )
                ]
            )
        ),
    )
    result = await _query_capabilities(session, MCPServer(name="fixture"), ServerIntrospection(server_name="fixture", success=False))
    assert result.runtime_tools[0].ui_metadata["resources"][0]["sha256"] == hashlib.sha256(html.encode()).hexdigest()
    assert result.runtime_tools[0].output_schema is True
    assert html not in json.dumps(result.to_dict())


@pytest.mark.asyncio
async def test_gateway_rejects_subscriptions_without_upstream_effect(monkeypatch):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from agent_bom.api import gateway_relay_pipeline as pipeline

    ctx = SimpleNamespace(message={"method": "subscriptions/listen"}, message_id=19)
    monkeypatch.setattr(pipeline, "parse_relay_request", AsyncMock(return_value=ctx))
    monkeypatch.setattr(pipeline, "RELAY_STAGES", (AsyncMock(return_value=None),))
    forward = AsyncMock()
    monkeypatch.setattr(pipeline, "forward_authorized_request", forward)
    response = await pipeline.run_relay(None, "fixture", None)
    assert response.status_code == 400
    assert json.loads(response.body)["error"]["code"] == -32601
    forward.assert_not_awaited()


@pytest.mark.asyncio
async def test_oauth_cache_isolates_resource_tenant_and_secret_rotation(monkeypatch):
    from urllib.parse import parse_qs

    from agent_bom.gateway_upstreams import UpstreamConfig, reset_oauth_cache_for_tests

    reset_oauth_cache_for_tests()
    monkeypatch.setenv("TEST_CLIENT_ID", "fixture")
    monkeypatch.setenv("TEST_CLIENT_SECRET", "first")
    requests = []

    def handler(request):
        requests.append(parse_qs(request.content.decode()))
        return httpx.Response(200, json={"access_token": f"token-{len(requests)}", "expires_in": 3600})

    monkeypatch.setattr(
        "agent_bom.runtime.egress_transport.build_pinned_async_client",
        lambda **kw: httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )

    def config(tenant, resource):
        return UpstreamConfig(
            name="fixture",
            tenant_id=tenant,
            url="https://example.com/mcp",
            auth="oauth2_client_credentials",
            oauth_token_url="https://id.example/token",
            oauth_resource=resource,
            oauth_client_id_env="TEST_CLIENT_ID",
            oauth_client_secret_env="TEST_CLIENT_SECRET",
        )

    first = config("one", "https://resource.example/one")
    assert await first.resolve_auth_headers() == {"Authorization": "Bearer token-1"}
    assert await first.resolve_auth_headers() == {"Authorization": "Bearer token-1"}
    assert await config("two", first.oauth_resource).resolve_auth_headers() == {"Authorization": "Bearer token-2"}
    assert await config("one", "https://resource.example/two").resolve_auth_headers() == {"Authorization": "Bearer token-3"}
    monkeypatch.setenv("TEST_CLIENT_SECRET", "rotated")
    assert await first.resolve_auth_headers() == {"Authorization": "Bearer token-4"}
    assert requests[0]["resource"] == [first.oauth_resource]


@pytest.mark.asyncio
async def test_paginated_inventory_is_complete_or_explicitly_incomplete():
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from agent_bom.discovery.mcp_metadata import capability_items
    from agent_bom.mcp_introspect import ServerIntrospection, _query_capabilities
    from agent_bom.models import MCPServer

    session = SimpleNamespace(
        list_tools=AsyncMock(side_effect=[SimpleNamespace(tools=[1], next_cursor="next"), SimpleNamespace(tools=[2], next_cursor=None)])
    )
    assert await capability_items(session, "list_tools", "tools") == [1, 2]
    session.list_tools = AsyncMock(return_value=SimpleNamespace(tools=[], next_cursor="repeat"))
    with pytest.raises(ValueError, match="pagination"):
        await capability_items(session, "list_tools", "tools")
    session.list_resources = AsyncMock(side_effect=ValueError("denied"))
    session.list_prompts = AsyncMock(side_effect=ValueError("denied"))
    result = await _query_capabilities(session, MCPServer(name="fixture"), ServerIntrospection(server_name="fixture", success=False))
    assert not result.success
    assert "incomplete" in result.error
    assert result.tools_removed == []


@pytest.mark.parametrize(
    "response",
    [
        {"jsonrpc": "2.0", "id": True, "result": {}},
        {"jsonrpc": "2.0", "id": 1, "result": "unexpected"},
        {"jsonrpc": "2.0", "id": 1, "error": {"code": True, "message": "bad"}},
    ],
)
def test_gateway_rejects_invalid_response_envelopes(response):
    from agent_bom.runtime.mcp_protocol import validate_response

    with pytest.raises(ValueError):
        validate_response({"id": 1}, response)


def test_registry_factory_does_not_import_legacy_smithery_sdk(monkeypatch):
    import builtins

    from agent_bom.mcp_server_entrypoint import create_smithery_server

    original = builtins.__import__

    def guarded(name, *args, **kwargs):
        if name == "smithery" or name.startswith("smithery."):
            raise AssertionError("legacy decorator cannot wrap SDK 2")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", guarded)
    server = object()
    assert create_smithery_server(lambda: server) is server
