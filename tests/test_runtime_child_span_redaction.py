"""Real SDK exports must never auto-record upstream exception text."""

import json
from contextlib import asynccontextmanager

import pytest
from starlette.testclient import TestClient

from agent_bom import gateway_server, proxy
from agent_bom.gateway_server import GatewaySettings, create_gateway_app
from agent_bom.gateway_upstreams import UpstreamConfig, UpstreamRegistry
from agent_bom.runtime import proxy_tracing

SECRET = "http://10.20.30.40:8443/mcp?api_key=sk-live-SYNTHETIC"


@pytest.fixture
def tracing():
    sdk = pytest.importorskip("opentelemetry.sdk.trace")
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    exporter = InMemorySpanExporter()
    provider = sdk.TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    yield provider.get_tracer("test-child-redaction"), exporter
    provider.shutdown()


def assert_sanitized(exporter, name):
    spans = [span for span in exporter.get_finished_spans() if span.name == name]
    assert len(spans) == 1
    exported = spans[0].to_json()
    assert "SYNTHETIC" not in exported
    assert "10.20.30.40" not in exported
    assert spans[0].status.status_code.name == "ERROR"
    assert len(spans[0].events) == 1
    assert spans[0].events[0].attributes["exception.type"] == "RuntimeError"
    assert "exception.stacktrace" not in spans[0].events[0].attributes


def test_gateway_request_failure_exports_only_sanitized_child_span(tracing, monkeypatch):
    tracer, exporter = tracing
    monkeypatch.setattr(gateway_server, "_GATEWAY_TRACER", tracer)

    async def upstream(*args):
        raise RuntimeError(SECRET)

    settings = GatewaySettings(
        registry=UpstreamRegistry([UpstreamConfig(name="fixture", url="http://fixture.local:8123")]),
        policy={},
        upstream_caller=upstream,
    )
    with TestClient(create_gateway_app(settings)) as client:
        response = client.post("/mcp/fixture", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert response.status_code == 502
    assert "SYNTHETIC" not in response.text
    assert_sanitized(exporter, "gateway.relay_upstream")


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["fetch_gateway_policies", "push_audit_batch"])
async def test_proxy_control_plane_failure_exports_only_sanitized_span(tracing, monkeypatch, operation):
    tracer, exporter = tracing
    monkeypatch.setattr(proxy_tracing, "_PROXY_TRACER", tracer)
    failure = RuntimeError(SECRET)
    failure.__cause__ = ValueError("SYNTHETIC_CAUSE")

    @asynccontextmanager
    async def failing_client(**kwargs):
        raise failure
        yield  # pragma: no cover

    monkeypatch.setattr("agent_bom.http_client.create_client", failing_client)
    with pytest.raises(RuntimeError) as caught:
        if operation == "fetch_gateway_policies":
            await proxy._fetch_enabled_gateway_policies("https://fixture.example", "token")
        else:
            await proxy._push_proxy_audit_batch("https://fixture.example", "token", "source", "session", [{"event": "test"}])
    assert caught.value is failure
    assert_sanitized(exporter, "proxy." + operation)


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["tools/call", "prompts/get"])
async def test_proxy_sse_child_failures_do_not_export_raw_exception(tracing, monkeypatch, method):
    import io
    from unittest.mock import AsyncMock

    tracer, exporter = tracing
    monkeypatch.setattr(proxy_tracing, "_PROXY_TRACER", tracer)
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.post.side_effect = RuntimeError(SECRET)
    monkeypatch.setattr("httpx.AsyncClient", lambda **kwargs: client)
    monkeypatch.setattr(proxy, "create_async_stdin_reader", AsyncMock(return_value=object()))
    message = {"jsonrpc": "2.0", "id": 8, "method": method, "params": {"name": "demo", "arguments": {}}}
    monkeypatch.setattr(proxy, "read_async_stdin_line", AsyncMock(side_effect=[json.dumps(message).encode() + b"\n", b""]))
    monkeypatch.setattr(proxy.sys, "stdout", type("Stdout", (), {"buffer": io.BytesIO()})())
    assert await proxy._proxy_sse_server(url="https://fixture.example") == 0
    assert_sanitized(exporter, "proxy.sse_tools_list")
    assert_sanitized(exporter, "proxy.sse_tools_call" if method == "tools/call" else "proxy.sse_gated_message")
