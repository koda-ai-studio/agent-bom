"""Native reader limits apply before JSON parsing, including project discovery."""

import json
from types import SimpleNamespace

import httpx
import pytest

from agent_bom import trace_connectors as connectors


class Stream(httpx.SyncByteStream):
    def __init__(self, chunks, advance=lambda: None):
        self.chunks = chunks
        self.advance = advance
        self.consumed = 0
        self.closed = False

    def __iter__(self):
        for chunk in self.chunks:
            self.advance()
            self.consumed += 1
            yield chunk

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def bounds(monkeypatch):
    monkeypatch.setattr(connectors, "_MAX_RESPONSE_BYTES", 64, raising=False)
    monkeypatch.setattr(connectors, "_validate_pull_url", lambda _: None)


@pytest.mark.parametrize("provider", ["langfuse", "langsmith"])
@pytest.mark.parametrize("operation", ["project", "sample", "page"])
def test_every_native_read_rejects_oversized_stream_before_consuming_body(provider, operation):
    stream = Stream([b" " * 32] * 100)
    credentials = {
        "host": "https://example.test",
        "api_url": "https://example.test",
        "public_key": "pk",
        "secret_key": "secret",
        "api_key": "secret",
        "project": "production",
    }
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=stream))) as client:
        with pytest.raises(connectors.TraceConnectorError, match="size limit"):
            if operation == "project":
                connectors.resolve_trace_project(provider, credentials, client=client)
            elif operation == "sample":
                connectors.fetch_traces(provider, credentials, client=client)
            else:
                connectors.fetch_trace_page(
                    provider,
                    credentials,
                    project_id="p",
                    window_start="2026-10-11T00:00:00Z",
                    window_end="2026-10-12T00:00:00Z",
                    cursor=None,
                    client=client,
                )
    assert stream.consumed == 3
    assert stream.closed


def test_declared_oversized_response_is_rejected_without_reading():
    stream = Stream([b"{}"])
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=stream, headers={"Content-Length": "65"}))
    ) as client:
        with pytest.raises(connectors.TraceConnectorError, match="size limit"):
            connectors._call_json(client, "GET", "https://example.test")
    assert stream.consumed == 0
    assert stream.closed


@pytest.mark.parametrize("header", [None, "2", "invalid"])
def test_actual_byte_limit_does_not_trust_content_length(header):
    stream = Stream([b" " * 32] * 100)
    headers = {} if header is None else {"Content-Length": header}
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=stream, headers=headers))) as client:
        with pytest.raises(connectors.TraceConnectorError, match="size limit"):
            connectors._call_json(client, "GET", "https://example.test")
    assert stream.consumed == 3
    assert stream.closed


def test_response_at_byte_limit_is_accepted():
    payload = b'{"data":[]}' + b" " * 53
    assert len(payload) == 64
    stream = Stream([payload])
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=stream))) as client:
        assert connectors._call_json(client, "GET", "https://example.test") == {"data": []}
    assert stream.closed


@pytest.mark.parametrize("phase", ["headers", "body", "empty_body"])
def test_elapsed_budget_rejects_late_headers_small_chunks_and_empty_responses(monkeypatch, phase):
    now = [0.0]
    monkeypatch.setattr(connectors, "time", SimpleNamespace(monotonic=lambda: now[0], time=lambda: 0))
    monkeypatch.setattr(connectors, "_HTTP_TOTAL_TIMEOUT", 25.0, raising=False)

    def advance():
        now[0] += 13

    stream = Stream([b" ", b" ", b"{}"] if phase == "body" else [], advance)

    def respond(_):
        if phase != "body":
            now[0] = 26
        return httpx.Response(200, stream=stream)

    with httpx.Client(transport=httpx.MockTransport(respond)) as client:
        with pytest.raises(connectors.TraceConnectorError, match="time limit"):
            connectors._call_json(client, "GET", "https://example.test")
    assert stream.closed
    assert stream.consumed <= 2


def test_error_status_and_retry_after_do_not_consume_untrusted_error_body():
    stream = Stream([b"api_key=private-provider-value"] * 100)
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(429, stream=stream, headers={"Retry-After": "120"}))
    ) as client:
        with pytest.raises(connectors._TraceConnectorHTTPError) as caught:
            connectors._call_json(client, "GET", "https://example.test")
    assert caught.value.retry_after == 120
    assert "private-provider-value" not in str(caught.value)
    assert stream.consumed == 0
    assert stream.closed


def test_decoded_compressed_payload_is_also_bounded():
    import gzip

    stream = Stream([gzip.compress(json.dumps({"private": "x" * 200}).encode())])
    with httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=stream, headers={"Content-Encoding": "gzip"}))
    ) as client:
        with pytest.raises(connectors.TraceConnectorError, match="size limit"):
            connectors._call_json(client, "GET", "https://example.test")
    assert stream.closed
