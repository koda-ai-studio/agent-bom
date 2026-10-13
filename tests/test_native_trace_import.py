"""Durable native span identity is scoped independently of source metadata."""

from dataclasses import replace

import pytest

from agent_bom.api.native_trace_import import TraceImportScope, prepare_trace_page
from agent_bom.api.runtime_event_store import SQLiteRuntimeEventStore
from agent_bom.runtime.native_trace_spans import native_span

SCOPE = TraceImportScope(
    tenant_id="tenant",
    provider="langfuse",
    connection_id="connection",
    endpoint="https://cloud.example",
    project_id="project",
    environment="prod",
    account_id="account",
)
TIME = "2026-10-11T12:00:00+00:00"


def span(span_id="child", parent="parent", **attributes):
    values = {
        "agent_bom.native_name": "Read file",
        "agent_bom.native_type": "TOOL",
        "agent_bom.native_project_id": "project",
        "agent_bom.native_environment": "prod",
        **attributes,
    }
    return {
        "spanId": span_id,
        "traceId": "trace",
        "parentSpanId": parent,
        "startTimeUnixNano": "1791720000000000000",
        "status": {"code": 0},
        "attributes": [{"key": key, "value": {"stringValue": value}} for key, value in values.items()],
    }


def test_import_replay_and_restart_preserve_parent_and_metadata_only(tmp_path):
    path = str(tmp_path / "runtime.db")
    store = SQLiteRuntimeEventStore(path)
    page = prepare_trace_page(
        {"spans": [span("parent", ""), span(**{"tool.output": "private-output", "tool.input.prompt": "private-prompt"})]},
        scope=SCOPE,
        collected_at=TIME,
    )
    assert len(page.observations) == 2
    assert page.rejected == {}
    assert store.put_observations_batch(page.observations) == 2
    assert store.put_observations_batch(page.observations) == 0
    reopened = SQLiteRuntimeEventStore(path)
    rows = reopened.list_observations("tenant")
    assert len(rows) == 2
    child = next(row for row in rows if row.span_id == "child")
    parent = next(row for row in rows if row.span_id == "parent")
    assert child.metadata["parent_observation_id"] == parent.observation_id
    assert child.metadata["native_type"] == "TOOL"
    assert child.metadata["collected_at"] == TIME
    assert child.verdict == "unknown"
    assert "private-" not in repr(rows)
    assert reopened.get_session("tenant", child.session_id).observation_count == 2
    assert reopened.list_observations("another-tenant") == []


@pytest.mark.parametrize("field", ["tenant_id", "connection_id", "project_id", "environment", "account_id", "endpoint"])
def test_identical_native_ids_cannot_collide_across_scope(field):
    first = prepare_trace_page({"spans": [span()]}, scope=SCOPE, collected_at=TIME).observations[0]
    other_scope = replace(SCOPE, **{field: "other"})
    other_span = span(**{"agent_bom.native_project_id": other_scope.project_id, "agent_bom.native_environment": other_scope.environment})
    second = prepare_trace_page({"spans": [other_span]}, scope=other_scope, collected_at=TIME).observations[0]
    assert first.observation_id != second.observation_id
    assert first.session_id != second.session_id


def test_conflicting_source_scope_is_rejected_without_losing_good_records():
    page = prepare_trace_page(
        {
            "spans": [
                span(),
                span("wrong-project", **{"agent_bom.native_project_id": "another-project"}),
                span("wrong-env", **{"agent_bom.native_environment": "staging"}),
            ]
        },
        scope=SCOPE,
        collected_at=TIME,
    )
    assert len(page.observations) == 1
    assert page.rejected == {"scope_conflict": 2}


def test_missing_parent_does_not_create_a_fabricated_root():
    child = prepare_trace_page({"spans": [span()]}, scope=SCOPE, collected_at=TIME).observations[0]
    assert child.metadata["native_parent_span_id"] == "parent"
    assert child.metadata["parent_observation_id"] != ""
    assert child.metadata["logical_root"] is None


def test_import_retains_end_time_and_redacts_credential_shaped_metadata():
    item = span(**{"agent_bom.native_name": "invoke api_key=super-secret", "agent_bom.native_session_id": "token=super-secret"})
    item["endTimeUnixNano"] = "1791720001000000000"
    record = prepare_trace_page({"spans": [item]}, scope=SCOPE, collected_at=TIME).observations[0]
    assert record.metadata["end_time_unix_nano"] == "1791720001000000000"
    assert "super-secret" not in repr(record)


def test_missing_event_time_is_explicit_and_keeps_collection_time_separate():
    item = span()
    del item["startTimeUnixNano"]
    record = prepare_trace_page({"spans": [item]}, scope=SCOPE, collected_at=TIME).observations[0]
    assert record.metadata["event_time_missing"] is True
    assert record.metadata["start_time_unix_nano"] is None
    assert record.metadata["collected_at"] == TIME


def test_repeated_native_metadata_is_redacted_once_per_page_and_cache_does_not_survive(monkeypatch):
    from agent_bom import security

    calls = []
    original = security._sanitize_sensitive_string

    def observed(value, **kwargs):
        if value == "langfuse" and kwargs.get("key") == "provider":
            calls.append(value)
        return original(value, **kwargs)

    monkeypatch.setattr(security, "_sanitize_sensitive_string", observed)
    scope = TraceImportScope("tenant", "langfuse", "connection", "https://traces.example", "project")
    payload = {
        "spans": [
            native_span(
                {"id": str(i), "traceId": "trace", "name": "api_key=private-value", "type": "TOOL"},
                provider="langfuse",
                include_content=False,
            )
            for i in range(100)
        ]
    }
    first = prepare_trace_page(payload, scope=scope, collected_at="2026-10-12T00:00:00Z")
    assert len(calls) == 1
    second = prepare_trace_page(payload, scope=scope, collected_at="2026-10-12T00:00:00Z")
    assert len(calls) == 2
    assert first == second
    assert "private-value" not in repr(first)


def test_page_redaction_cache_keeps_field_policy_and_raw_payload_exclusion():
    from agent_bom.api.storage.runtime_records import RuntimeMetadataCache, sanitize_runtime_metadata

    cache = RuntimeMetadataCache()
    metadata = {"label": "same-value", "password": "same-value", "prompt": "private-input"}
    expected = sanitize_runtime_metadata(metadata)
    assert expected["label"] == "same-value"
    assert expected["password"] == "***REDACTED***"
    assert "prompt" not in expected
    for _ in range(2):
        assert sanitize_runtime_metadata(metadata, _cache=cache) == expected
    assert len(cache.strings) == 2


def test_repeated_native_display_fields_are_sanitized_once_per_page(monkeypatch):
    from agent_bom import security

    original = security.sanitize_log_label
    calls = []
    name = "api_key=private-native-name"

    def observed(value, max_len=1000):
        if value == name and max_len == 300:
            calls.append(value)
        return original(value, max_len=max_len)

    monkeypatch.setattr(security, "sanitize_log_label", observed)
    payload = {"spans": [span(str(i), **{"agent_bom.native_name": name}) for i in range(100)]}
    first = prepare_trace_page(payload, scope=SCOPE, collected_at=TIME)
    assert len(first.observations) == 100
    assert len(calls) == 1, "repeated display fields must not rerun redaction for every span"
    assert "private-native-name" not in repr(first)
    second = prepare_trace_page(payload, scope=SCOPE, collected_at=TIME)
    assert first == second
    assert len(calls) == 2, "the cache must not survive its page"
    other = prepare_trace_page(payload, scope=replace(SCOPE, tenant_id="other"), collected_at=TIME)
    assert len(calls) == 3
    assert {row.observation_id for row in first.observations}.isdisjoint(row.observation_id for row in other.observations)


def test_page_metadata_field_cache_is_bounded_and_preserves_key_sanitization(monkeypatch):
    from agent_bom.api.storage import runtime_records

    calls = []
    original = runtime_records.sanitize_text

    def observed(value, **kwargs):
        calls.append(value)
        return original(value, **kwargs)

    monkeypatch.setattr(runtime_records, "sanitize_text", observed)
    cache = runtime_records.RuntimeMetadataCache()
    for _ in range(2):
        assert runtime_records.sanitize_runtime_metadata({"provider": "langfuse"}, _cache=cache) == {"provider": "langfuse"}
    assert calls == ["provider"]
    for index in range(100):
        runtime_records.sanitize_runtime_metadata({f"field-{index}": index}, _cache=cache)
    assert len(cache.fields) <= 50
    key = "x" * 200
    assert runtime_records.sanitize_runtime_metadata({key: 1}, _cache=cache) == runtime_records.sanitize_runtime_metadata({key: 1})


def test_page_metadata_reuses_sanitized_scalar_leaves_without_rewalking(monkeypatch):
    from agent_bom.api.storage import runtime_records

    original = runtime_records.sanitize_sensitive_payload
    calls = []

    def observed(value, **kwargs):
        calls.append((kwargs.get("key"), value))
        return original(value, **kwargs)

    metadata = {"provider": "langfuse", "password": "langfuse", "count": 5, "missing": None, "nested": {"token": "secret"}}
    expected = runtime_records.sanitize_runtime_metadata(metadata)
    monkeypatch.setattr(runtime_records, "sanitize_sensitive_payload", observed)
    cache = runtime_records.RuntimeMetadataCache()
    outputs = [runtime_records.sanitize_runtime_metadata(metadata, _cache=cache) for _ in range(100)]
    assert outputs == [expected] * 100
    assert len([key for key, value in calls if key == "provider"]) == 1
    assert len([key for key, value in calls if key == "password"]) == 1
    assert not [key for key, value in calls if key in {"count", "missing"}]
    outputs[0]["nested"]["token"] = "changed"
    assert outputs[1]["nested"] == expected["nested"]
    runtime_records.sanitize_runtime_metadata(metadata, _cache=runtime_records.RuntimeMetadataCache())
    assert len([key for key, value in calls if key == "provider"]) == 2
