"""Native observation kinds and physical parents survive connector adaptation."""

from __future__ import annotations

import pytest

from agent_bom.otel_ingest import parse_otel_traces
from agent_bom.trace_connectors import fetch_langfuse_traces, fetch_langsmith_traces


class Client:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append(kwargs)
        payload = self.payload

        class Response:
            status_code = 200

            def json(self):
                return payload

        return Response()


@pytest.fixture(autouse=True)
def public_host(monkeypatch):
    monkeypatch.setattr("agent_bom.security.validate_url", lambda *a, **k: None)


def attributes(span):
    return {item["key"]: item["value"]["stringValue"] for item in span["attributes"]}


@pytest.mark.parametrize("kind", ["AGENT", "RETRIEVER", "GENERATION", "SPAN", "EVENT", "TOOL", "FUTURE_KIND"])
def test_langfuse_preserves_native_kind_parent_time_and_scope(kind):
    client = Client(
        {
            "data": [
                {
                    "id": "child",
                    "traceId": "trace",
                    "parentObservationId": "parent",
                    "name": "read_file",
                    "type": kind,
                    "isRootObservation": True,
                    "startTime": "2026-10-11T12:00:00.000001Z",
                    "endTime": "2026-10-11T12:00:00.500001Z",
                    "projectId": "project-a",
                    "environment": "production",
                    "sessionId": "conversation-a",
                    "input": "private-prompt",
                    "output": "private-output",
                    "metadata": {"secret": "private-metadata"},
                }
            ]
        }
    )
    payload = fetch_langfuse_traces(host="https://cloud.example", public_key="pk", secret_key="sk", client=client)
    assert len(payload["spans"]) == 1
    span = payload["spans"][0]
    assert span["parentSpanId"] == "parent"  # Logical root must not erase physical parent.
    assert int(span["endTimeUnixNano"]) - int(span["startTimeUnixNano"]) == 500_000_000
    attrs = attributes(span)
    assert attrs["agent_bom.native_type"] == kind
    assert attrs["agent_bom.native_project_id"] == "project-a"
    assert attrs["agent_bom.native_session_id"] == "conversation-a"
    assert attrs["agent_bom.native_environment"] == "production"
    assert attrs["agent_bom.logical_root"] == "true"
    assert "type" not in client.calls[0]["params"]
    assert [t.span_id for t in parse_otel_traces(payload)] == (["child"] if kind == "TOOL" else [])
    assert "private-" not in repr(payload)


@pytest.mark.parametrize("kind", ["chain", "llm", "retriever", "embedding", "prompt", "parser", "tool"])
def test_langsmith_keeps_non_tool_runs_and_project_distinct_from_session(kind):
    client = Client(
        {
            "runs": [
                {
                    "id": "child",
                    "trace_id": "trace",
                    "parent_run_id": "parent",
                    "session_id": "project-a",
                    "name": "read_file",
                    "run_type": kind,
                    "start_time": "2026-10-11T12:00:00Z",
                    "end_time": "2026-10-11T12:00:01Z",
                    "error": "private-error-with-secret",
                    "inputs": {"prompt": "private-input"},
                }
            ]
        }
    )
    payload = fetch_langsmith_traces(api_key="key", client=client)
    span = payload["spans"][0]
    assert span["parentSpanId"] == "parent"
    assert span["status"]["code"] == 2
    attrs = attributes(span)
    assert attrs["agent_bom.native_type"] == kind
    assert attrs["agent_bom.native_project_id"] == "project-a"
    assert "agent_bom.native_session_id" not in attrs
    assert "run_type" not in client.calls[0]["json"]
    assert [t.span_id for t in parse_otel_traces(payload)] == (["child"] if kind == "tool" else [])
    assert "private-" not in repr(payload)


def test_native_tool_without_success_evidence_remains_unknown():
    client = Client({"data": [{"id": "tool", "traceId": "trace", "name": "invoke_lambda", "type": "TOOL"}]})
    payload = fetch_langfuse_traces(host="https://cloud.example", public_key="pk", secret_key="sk", client=client)
    assert parse_otel_traces(payload)[0].status == "unknown"
