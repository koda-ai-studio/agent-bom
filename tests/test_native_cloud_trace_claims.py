"""Native cloud identifiers remain source claims and never execution proof."""

import pytest

from agent_bom.api.native_trace_import import TraceImportScope, prepare_trace_page
from agent_bom.runtime.native_trace_spans import native_span

ARN = "arn:aws:lambda:us-east-1:111111111111:function:process-invoice:3"
CLAIMS = {
    "cloud.provider": "aws",
    "cloud.account.id": "111111111111",
    "cloud.region": "us-east-1",
    "cloud.resource_id": ARN,
    "faas.invocation_id": "execution-attempt-1",
    "faas.version": "3",
    "aws.request_id": "sdk-request-1",
    "rpc.service": "Lambda",
    "rpc.method": "Invoke",
}


@pytest.mark.parametrize("provider", ["langfuse", "langsmith"])
def test_native_cloud_identifiers_survive_import_without_becoming_outcome(provider):
    metadata = {**CLAIMS, "aws.secret_access_key": "do-not-retain", "payload": "private-input"}
    row = {
        "id": "child",
        "traceId": "trace",
        "trace_id": "trace",
        "name": "Process invoice",
        "type": "TOOL",
        "run_type": "tool",
        "metadata": metadata,
        "extra": {"metadata": metadata},
    }
    converted = native_span(row, provider=provider, include_content=False)
    scope = TraceImportScope(
        "tenant",
        provider,
        "connection",
        "https://traces.example",
        "project",
        environment="production",
        account_id="111111111111",
        cloud_provider="aws",
    )
    page = prepare_trace_page({"spans": [converted]}, scope=scope, collected_at="2026-10-12T06:00:00Z")
    record = page.observations[0]
    assert record.metadata["cloud_trace"] == {
        "basis": "source_reported",
        "execution_proven": False,
        "scope_state": "consistent",
        "attributes": CLAIMS,
    }
    assert record.verdict == "unknown"
    assert "do-not-retain" not in repr(record)
    assert "private-input" not in repr(record)
    assert (
        record.metadata["cloud_trace"]["attributes"]["aws.request_id"] != record.metadata["cloud_trace"]["attributes"]["faas.invocation_id"]
    )


@pytest.mark.parametrize("key,value", [("cloud.account.id", "222222222222"), ("cloud.provider", "azure")])
def test_conflicting_cloud_claim_stays_visible_but_cannot_bind(key, value):
    metadata = {**CLAIMS, key: value}
    converted = native_span(
        {"id": "span", "traceId": "trace", "name": "call", "type": "TOOL", "metadata": metadata}, provider="langfuse", include_content=False
    )
    scope = TraceImportScope(
        "tenant", "langfuse", "connection", "https://traces.example", "project", account_id="111111111111", cloud_provider="aws"
    )
    record = prepare_trace_page({"spans": [converted]}, scope=scope, collected_at="2026-10-12T06:00:00Z").observations[0]
    assert record.metadata["cloud_trace"]["scope_state"] == "conflict"
    assert record.metadata["account_id"] == "111111111111"
    assert record.metadata["cloud_provider"] == "aws"
    assert record.metadata["cloud_trace"]["execution_proven"] is False


@pytest.mark.parametrize("value", ["x" * 501, " request ", "request\nnext", "api_key=super-secret", ["bad"]])
def test_invalid_identifiers_cannot_be_truncated_or_sanitized_into_a_match(value):
    from agent_bom.runtime.cloud_trace_claims import cloud_trace_claims

    result = cloud_trace_claims({**CLAIMS, "aws.request_id": value}, account_id="111111111111", provider="aws")
    assert result["scope_state"] == "invalid"
    assert "aws.request_id" not in result["attributes"]
    assert "super-secret" not in repr(result)


@pytest.mark.parametrize("key,value", [("cloud.resource_id", ARN.replace("111111111111", "222222222222")), ("cloud.region", "eu-west-1")])
def test_arn_scope_conflict_is_not_hidden_by_matching_connection_metadata(key, value):
    from agent_bom.runtime.cloud_trace_claims import cloud_trace_claims

    result = cloud_trace_claims({**CLAIMS, key: value}, account_id="111111111111", provider="aws")
    assert result["scope_state"] == "conflict"


def test_cloud_claims_survive_replay_and_explorer_without_execution_upgrade(tmp_path):
    from agent_bom.api.runtime_event_store import SQLiteRuntimeEventStore
    from agent_bom.api.trace_explorer import build_trace_explorer_payload

    scope = TraceImportScope(
        "tenant", "langfuse", "connection", "https://traces.example", "project", account_id="111111111111", cloud_provider="aws"
    )

    def record(identity):
        metadata = {**CLAIMS, "faas.invocation_id": identity}
        span = native_span(
            {
                "id": identity,
                "traceId": "trace",
                "parentObservationId": "missing-parent",
                "name": "call",
                "type": "TOOL",
                "metadata": metadata,
            },
            provider="langfuse",
            include_content=False,
        )
        return prepare_trace_page({"spans": [span]}, scope=scope, collected_at="2026-10-12T06:00:00Z").observations[0]

    path = str(tmp_path / "runtime.db")
    store = SQLiteRuntimeEventStore(path)
    records = [record("attempt-1"), record("attempt-2")]
    assert store.put_observations_batch(records) == 2
    assert store.put_observations_batch(records) == 0
    store = SQLiteRuntimeEventStore(path)
    rows = [row.to_dict() for row in store.list_observations("tenant")]
    assert len(rows) == 2
    assert store.list_observations("other-tenant") == []
    response = build_trace_explorer_payload(tenant_id="tenant", feed_events=[], findings=[], sessions=[], observations=rows, limit=10)
    spans = response["sessions"][0]["spans"]
    assert {s["cloud_trace"]["attributes"]["faas.invocation_id"] for s in spans} == {"attempt-1", "attempt-2"}
    assert all(s["cloud_trace"]["execution_proven"] is False and s["parent_state"] == "missing" for s in spans)
