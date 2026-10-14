"""Vendor field -> canonical NormalizedTraceEvent field mapping tables."""

from __future__ import annotations

import hashlib
import json
from functools import partial

import pytest

from agent_bom.runtime.normalized_trace import (
    NormalizedTraceEvent,
    coverage_by_source,
    from_langfuse_observation,
    from_langsmith_run,
    from_otlp_span,
    is_weak_principal,
    iter_otlp_spans,
    principal_digest,
)

KEY = b"deployment-key"
DIGEST = partial(principal_digest, "tenant-a", deployment_key=KEY)

PROMPT = "Summarize the account notes for jane.doe@example.com"

# Langfuse public API v2 observation (fields=core,basic,time,metadata,model,usage,io).
LANGFUSE_GENERATION = {
    "id": "obs-gen-1",
    "traceId": "trace-lf-1",
    "parentObservationId": "obs-agent-1",
    "type": "GENERATION",
    "name": "ChatOpenAI",
    "startTime": "2026-10-01T12:00:00.000Z",
    "endTime": "2026-10-01T12:00:02.500Z",
    "level": "DEFAULT",
    "userId": "jane.doe@example.com",
    "sessionId": "session-1",
    "environment": "production",
    "projectId": "proj-1",
    "model": "gpt-4o-2024-08-06",
    "usageDetails": {"input": 812, "output": 96, "total": 908},
    "costDetails": {"input": 0.00203, "output": 0.00096, "total": 0.00299},
    "totalCost": 0.00299,
    "metadata": {"ls_provider": "openai", "agent_name": "billing-agent"},
    "input": json.dumps([{"role": "user", "content": PROMPT}]),
    "output": json.dumps({"role": "assistant", "content": "Notes summarized."}),
}
LANGFUSE_RETRIEVER = {
    "id": "obs-ret-1",
    "traceId": "trace-lf-1",
    "parentObservationId": "obs-agent-1",
    "type": "RETRIEVER",
    "name": "vector-search",
    "startTime": "2026-10-01T11:59:59Z",
    "level": "ERROR",
    "metadata": {"data_source": "SNOWFLAKE.CRM.PUBLIC.NOTES"},
    "output": json.dumps(
        [
            {"page_content": "secret notes", "metadata": {"source": "https://wiki.example.com/hr/jane-doe?id=7"}},
            {"page_content": "more", "metadata": {"source": "https://wiki.example.com/other"}},
        ]
    ),
}
LANGFUSE_AGENT = {
    "id": "obs-agent-1",
    "traceId": "trace-lf-1",
    "type": "AGENT",
    "name": "billing-agent",
    "startTime": "2026-10-01T11:59:58Z",
    "metadata": {"agent_bom.inventory_node_id": "agent:billing-agent"},
}

# LangSmith runs/query run with extra.metadata (ls_* keys) and token/cost columns.
LANGSMITH_LLM = {
    "id": "run-llm-1",
    "trace_id": "run-root-1",
    "parent_run_id": "run-root-1",
    "name": "ChatAnthropic",
    "run_type": "llm",
    "start_time": "2026-10-01T12:00:00.000000",
    "end_time": "2026-10-01T12:00:01.000000+00:00",
    "status": "success",
    "error": None,
    "prompt_tokens": 400,
    "completion_tokens": 50,
    "total_cost": "0.0021",
    "extra": {"metadata": {"ls_provider": "anthropic", "ls_model_name": "claude-model-x", "user_id": "u-42"}},
    "inputs": {"messages": [{"role": "user", "content": PROMPT}]},
}
LANGSMITH_TOOL = {
    "id": "run-tool-1",
    "trace_id": "run-root-1",
    "parent_run_id": "run-root-1",
    "name": "query_crm",
    "run_type": "tool",
    "start_time": "2026-10-01T12:00:01+00:00",
    "status": "error",
    "error": "timeout",
    "extra": {"metadata": {"agent_bom.inventory_node_id": "tool:crm:query_crm", "agent_bom.credential_ref": "CRM_API_KEY"}},
}

# OTLP JSON span using OpenTelemetry GenAI semantic-convention attributes.
OTLP_BODY = {
    "resourceSpans": [
        {
            "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "billing"}}]},
            "scopeSpans": [
                {
                    "spans": [
                        {
                            "traceId": "otel-trace-1",
                            "spanId": "otel-span-1",
                            "parentSpanId": "otel-span-0",
                            "name": "execute_tool query_crm",
                            "startTimeUnixNano": "1790000000000000000",
                            "endTimeUnixNano": "1790000001000000000",
                            "status": {"code": 2},
                            "attributes": [
                                {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}},
                                {"key": "gen_ai.tool.name", "value": {"stringValue": "query_crm"}},
                                {"key": "gen_ai.agent.name", "value": {"stringValue": "billing-agent"}},
                                {"key": "gen_ai.provider.name", "value": {"stringValue": "openai"}},
                                {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4o"}},
                                {"key": "gen_ai.usage.input_tokens", "value": {"intValue": "120"}},
                                {"key": "gen_ai.usage.output_tokens", "value": {"intValue": 7}},
                                {"key": "gen_ai.data_source.id", "value": {"stringValue": "crm-index"}},
                                {"key": "user.id", "value": {"stringValue": "u-42"}},
                                {"key": "mcp.server", "value": {"stringValue": "server:crm"}},
                                {"key": "gen_ai.input.messages", "value": {"stringValue": PROMPT}},
                            ],
                        }
                    ]
                }
            ],
        }
    ]
}


def _digest(value: str) -> str:
    return principal_digest("tenant-a", value, deployment_key=KEY)


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("source", "langfuse"),
        ("source_trace_id", "trace-lf-1"),  # traceId
        ("source_span_id", "obs-gen-1"),  # id
        ("parent_span_id", "obs-agent-1"),  # parentObservationId
        ("started_at", "2026-10-01T12:00:00+00:00"),  # startTime
        ("ended_at", "2026-10-01T12:00:02.500000+00:00"),  # endTime
        ("kind", "llm"),  # type GENERATION
        ("agent_name", "billing-agent"),  # metadata.agent_name
        ("model_provider", "openai"),  # metadata.ls_provider
        ("model_name", "gpt-4o-2024-08-06"),  # model
        ("input_tokens", 812),  # usageDetails.input
        ("output_tokens", 96),  # usageDetails.output
        ("cost_usd", 0.00299),  # totalCost
        ("principal_hash", _digest("jane.doe@example.com")),  # userId, hashed
        ("status", "ok"),  # level != ERROR
        ("match_method", "none"),
    ],
)
def test_langfuse_observation_mapping(field: str, expected: object) -> None:
    event = from_langfuse_observation(LANGFUSE_GENERATION, tenant_id="tenant-a", principal=DIGEST)
    assert getattr(event, field) == expected


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("source", "langsmith"),
        ("source_trace_id", "run-root-1"),  # trace_id
        ("source_span_id", "run-llm-1"),  # id
        ("parent_span_id", "run-root-1"),  # parent_run_id
        ("kind", "llm"),  # run_type llm
        ("model_provider", "anthropic"),  # extra.metadata.ls_provider
        ("model_name", "claude-model-x"),  # extra.metadata.ls_model_name
        ("input_tokens", 400),  # prompt_tokens
        ("output_tokens", 50),  # completion_tokens
        ("cost_usd", 0.0021),  # total_cost (decimal string)
        ("principal_hash", _digest("u-42")),  # extra.metadata.user_id, hashed
        ("ended_at", "2026-10-01T12:00:01+00:00"),
        ("started_at", "2026-10-01T12:00:00+00:00"),  # LangSmith naive timestamps are UTC
    ],
)
def test_langsmith_run_mapping(field: str, expected: object) -> None:
    event = from_langsmith_run(LANGSMITH_LLM, tenant_id="tenant-a", principal=DIGEST)
    assert getattr(event, field) == expected


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("source", "otel"),
        ("source_trace_id", "otel-trace-1"),  # traceId
        ("source_span_id", "otel-span-1"),  # spanId
        ("parent_span_id", "otel-span-0"),  # parentSpanId
        ("kind", "tool"),  # gen_ai.operation.name=execute_tool
        ("tool_name", "query_crm"),  # gen_ai.tool.name
        ("agent_name", "billing-agent"),  # gen_ai.agent.name
        ("model_provider", "openai"),  # gen_ai.provider.name
        ("model_name", "gpt-4o"),  # gen_ai.request.model
        ("input_tokens", 120),  # gen_ai.usage.input_tokens (string intValue)
        ("output_tokens", 7),  # gen_ai.usage.output_tokens
        ("resource_refs", ("crm-index",)),  # gen_ai.data_source.id
        ("principal_hash", _digest("u-42")),  # user.id, hashed
        ("mcp_server_ref", "server:crm"),
        ("status", "error"),  # status.code 2
        ("started_at", "2026-09-21T14:13:20+00:00"),
        ("cost_usd", None),  # OTel GenAI semconv defines no cost attribute
    ],
)
def test_otlp_span_mapping(field: str, expected: object) -> None:
    span, resource = next(iter_otlp_spans(OTLP_BODY))
    event = from_otlp_span(span, tenant_id="tenant-a", resource_attributes=resource, principal=DIGEST)
    assert getattr(event, field) == expected


def test_retrieved_sources_keep_host_only_and_raw_content_is_hashed_never_stored() -> None:
    retriever = from_langfuse_observation(LANGFUSE_RETRIEVER, tenant_id="t")
    assert retriever.kind == "retrieval"
    assert retriever.status == "error"
    assert retriever.resource_refs == ("SNOWFLAKE.CRM.PUBLIC.NOTES", "https://wiki.example.com")
    for event in (
        from_langfuse_observation(LANGFUSE_GENERATION, tenant_id="t"),
        from_langsmith_run(LANGSMITH_LLM, tenant_id="t"),
        from_otlp_span(next(iter_otlp_spans(OTLP_BODY))[0], tenant_id="t"),
    ):
        assert event.content_sha256 and len(event.content_sha256) == 64
        serialized = json.dumps(event.to_dict())
        assert PROMPT not in serialized
        assert "jane.doe@example.com" not in serialized
        assert "u-42" not in serialized


def test_exact_inventory_ids_and_credential_names_only() -> None:
    agent = from_langfuse_observation(LANGFUSE_AGENT, tenant_id="t")
    assert (agent.kind, agent.agent_ref, agent.match_method, agent.match_node_id) == (
        "agent",
        "agent:billing-agent",
        "exact",
        "agent:billing-agent",
    )
    tool = from_langsmith_run(LANGSMITH_TOOL, tenant_id="t")
    assert (tool.kind, tool.tool_name, tool.status) == ("tool", "query_crm", "error")
    assert (tool.match_method, tool.match_node_id, tool.credential_ref) == ("exact", "tool:crm:query_crm", "CRM_API_KEY")
    leaky = {**LANGSMITH_TOOL, "extra": {"metadata": {"agent_bom.credential_ref": "sk-live-abcdef0123456789"}}}
    assert from_langsmith_run(leaky, tenant_id="t").credential_ref is None
    with pytest.raises(ValueError):
        NormalizedTraceEvent(tenant_id="t", source="otel", source_trace_id="x", source_span_id="y", credential_ref="sk-live-1")


def test_round_trip_and_tenant_is_bound_by_caller() -> None:
    event = from_langsmith_run(LANGSMITH_TOOL, tenant_id="")
    bound = event.bind_tenant("tenant-b")
    assert NormalizedTraceEvent.from_dict(bound.to_dict()) == bound
    assert bound.tenant_id == "tenant-b"


def test_invalid_values_are_rejected() -> None:
    with pytest.raises(ValueError):
        NormalizedTraceEvent(tenant_id="t", source="vendor-x", source_trace_id="a", source_span_id="b")
    with pytest.raises(ValueError):
        NormalizedTraceEvent(tenant_id="t", source="otel", source_trace_id="a", source_span_id="b", signals=frozenset({"other"}))
    with pytest.raises(ValueError):
        NormalizedTraceEvent(tenant_id="t", source="otel", source_trace_id="a", source_span_id="b", match_method="exact")


def test_coverage_counts_missing_fields_per_source() -> None:
    events = [
        from_langfuse_observation(LANGFUSE_GENERATION, tenant_id="t"),
        from_langsmith_run(LANGSMITH_LLM, tenant_id="t"),
        from_otlp_span(next(iter_otlp_spans(OTLP_BODY))[0], tenant_id="t"),
    ]
    coverage = coverage_by_source(events)
    assert coverage["langfuse"]["supplied"]["model_name"] == 1
    assert coverage["langfuse"]["supplied"]["cost_usd"] == 1
    assert coverage["otel"]["missing"]["cost_usd"] == 1
    assert coverage["langsmith"]["missing"]["agent_name"] == 1
    assert coverage["langsmith"]["events"] == 1


def test_principal_digest_is_keyed_tenant_scoped_and_flags_weak_fallback() -> None:
    keyed = principal_digest("tenant-a", "jane.doe@example.com", deployment_key=KEY)
    assert keyed.startswith("h1:") and len(keyed) == 3 + 64
    assert keyed.removeprefix("h1:") != hashlib.sha256(b"jane.doe@example.com").hexdigest()
    assert keyed == principal_digest("tenant-a", "jane.doe@example.com", deployment_key=KEY)
    assert keyed != principal_digest("tenant-b", "jane.doe@example.com", deployment_key=KEY)
    assert keyed != principal_digest("tenant-a", "jane.doe@example.com", deployment_key=b"other-key")
    weak = principal_digest("tenant-a", "jane.doe@example.com", deployment_key=None)
    assert weak.startswith("h1w:") and is_weak_principal(weak) and not is_weak_principal(keyed)
    assert weak != principal_digest("tenant-b", "jane.doe@example.com", deployment_key=None)
    with pytest.raises(ValueError):
        principal_digest("", "u", deployment_key=KEY)
    unbound = from_langfuse_observation(LANGFUSE_GENERATION, tenant_id="tenant-a")
    assert unbound.principal_hash is None  # no digest function means no identifier at all, never a plain hash
    weak_event = from_langfuse_observation(
        LANGFUSE_GENERATION, tenant_id="t", principal=partial(principal_digest, "t", deployment_key=None)
    )
    assert coverage_by_source([weak_event])["langfuse"]["weak_principal_hashes"] == 1


def test_naive_timestamps_are_utc_only_for_langsmith() -> None:
    naive = {**LANGFUSE_GENERATION, "startTime": "2026-10-01T12:00:00"}
    assert from_langfuse_observation(naive, tenant_id="t").started_at is None
    assert from_langsmith_run(LANGSMITH_LLM, tenant_id="t").started_at == "2026-10-01T12:00:00+00:00"


def test_mcp_semconv_spans_map_method_and_resource_host_only() -> None:
    def span(uri: str) -> dict:
        attrs = {"mcp.method.name": "resources/read", "mcp.resource.uri": uri, "mcp.session.id": "s-1"}
        return {
            "traceId": "t",
            "spanId": uri[-4:],
            "name": "resources/read",
            "attributes": [{"key": key, "value": {"stringValue": value}} for key, value in attrs.items()],
        }

    remote = from_otlp_span(span("https://docs.example.com/private/jane"), tenant_id="t")
    assert (remote.kind, remote.resource_refs) == ("mcp", ("https://docs.example.com",))
    assert from_otlp_span(span("file:///Users/jane/notes.txt"), tenant_id="t").resource_refs == ()


def test_local_paths_never_survive_normalization() -> None:
    root = "/tmp/abomprobe"
    row = {
        **LANGFUSE_RETRIEVER,
        "name": f"{root}/indexer",
        "metadata": {"data_source": f"{root}/vector.db", "role_name": f"{root}/role", "mcp_server": f"{root}/server.json"},
        "output": json.dumps([{"metadata": {"source": f"file://{root}/doc.txt"}}, {"metadata": {"source": f"{root}/doc2.txt"}}]),
    }
    event = from_langfuse_observation({**row, "type": "TOOL"}, tenant_id="t")
    assert event.tool_name == "<path:indexer>"
    assert event.role_name == "<path:role>"
    assert event.mcp_server_ref is None
    assert from_langfuse_observation(row, tenant_id="t").resource_refs == ()
    assert root not in json.dumps(event.to_dict())
