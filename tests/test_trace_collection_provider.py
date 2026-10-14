"""Provider cursors are bounded and metadata is strictly validated before commit."""

import httpx
import pytest

from agent_bom.api.trace_collection.contracts import CollectionState
from agent_bom.api.trace_collection.langfuse import fetch_page
from agent_bom.trace_connectors import TraceConnectorError


def state():
    return CollectionState(
        scope_digest="scope", window_start="2026-10-10T00:00:00+00:00", window_end="2026-10-11T00:00:00+00:00", cursor="previous"
    )


def row():
    return {
        "id": "span-a",
        "traceId": "trace-a",
        "type": "TOOL",
        "name": "read",
        "startTime": "2026-10-10T12:00:00Z",
        "input": "secret",
        "output": "secret",
    }


def collect(payload):
    def handle(request):
        if request.url.path == "/api/public/projects":
            return httpx.Response(200, json={"data": [{"id": "project"}]})
        assert request.url.params["cursor"] == "previous"
        assert request.url.params["limit"] == "100"
        assert request.url.params["fields"] == "core,basic,time,metadata,model,usage"
        return httpx.Response(200, json=payload)

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        return fetch_page(
            "a", "production", {"host": "https://cloud.langfuse.com", "public_key": "pk", "secret_key": "secret"}, state(), client=client
        )


def test_page_preserves_identity_and_excludes_content():
    records, cursor = collect({"data": [row()], "meta": {"cursor": "next"}})
    assert cursor == "next" and len(records) == 1
    assert records[0].trace_id == "trace-a" and records[0].span_id == "span-a"
    assert "secret" not in str(records[0].to_dict())
    assert records[0].metadata["native_type"] == "TOOL"
    assert records[0].metadata["project_id"] == "project"


@pytest.mark.parametrize(
    "payload",
    [
        {"data": [row()], "meta": {"cursor": "previous"}},
        {"data": [row()], "meta": {"cursor": 1}},
        {"data": [row()]},
        {"data": [{**row(), "startTime": "2026-10-12T12:00:00Z"}], "meta": {}},
        {"data": [{**row(), "traceId": ""}], "meta": {}},
        {"data": [row()] * 101, "meta": {}},
    ],
)
def test_bad_pages_never_advance(payload):
    with pytest.raises(TraceConnectorError):
        collect(payload)


@pytest.mark.parametrize(
    "status,code",
    [(401, "access_denied"), (403, "access_denied"), (429, "rate_limited"), (404, "unsupported_api"), (503, "provider_unavailable")],
)
def test_provider_http_failure_has_no_fallback(status, code):
    from agent_bom.api.trace_collection.langfuse import ProviderFailureError

    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(status, headers={"Retry-After": "120"}, text="private provider error")

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        with pytest.raises(ProviderFailureError) as caught:
            fetch_page(
                "a",
                "production",
                {"host": "https://cloud.langfuse.com", "public_key": "pk", "secret_key": "secret"},
                state(),
                client=client,
            )
    assert len(calls) == 1 and caught.value.code == code
    assert caught.value.retry_after == 120
    assert "private" not in str(caught.value)


def test_oversized_provider_response_is_rejected():
    from agent_bom.api.trace_collection.langfuse import MAX_RESPONSE_BYTES, ProviderFailureError

    with httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1)))) as client:
        with pytest.raises(ProviderFailureError) as caught:
            fetch_page(
                "a",
                "production",
                {"host": "https://cloud.langfuse.com", "public_key": "pk", "secret_key": "secret"},
                state(),
                client=client,
            )
    assert caught.value.code == "response_too_large"


def test_collection_uses_native_import_identity_for_non_tool_spans():
    from agent_bom.api.native_trace_import import TraceImportScope, prepare_trace_page
    from agent_bom.runtime.native_trace_spans import native_span

    source_row = {**row(), "type": "GENERATION", "projectId": "project", "parentObservationId": "root"}
    credentials = {"host": "https://cloud.langfuse.com", "public_key": "pk", "secret_key": "secret"}

    def handle(request):
        if request.url.path == "/api/public/projects":
            return httpx.Response(200, json={"data": [{"id": "project"}]})
        assert "type" not in request.url.params
        return httpx.Response(200, json={"data": [source_row], "meta": {}})

    with httpx.Client(transport=httpx.MockTransport(handle)) as client:
        records, _ = fetch_page("a", "production", credentials, state(), client=client)
    expected = prepare_trace_page(
        {"spans": [native_span(source_row, provider="langfuse", include_content=False)]},
        scope=TraceImportScope("a", "langfuse", "production", credentials["host"], "project"),
        collected_at="2026-10-12T00:00:00+00:00",
    ).observations[0]
    assert records[0].observation_id == expected.observation_id
    assert records[0].session_id == expected.session_id
    assert records[0].surface == "imported_trace"
    assert records[0].event_type != "tool_call"
    assert records[0].metadata["native_type"] == "GENERATION"
    assert "secret" not in str(records[0].to_dict())
