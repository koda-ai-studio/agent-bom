"""Current GenAI attributes must reach the legacy cost/tool consumers too."""

import pytest

from agent_bom.otel_ingest import parse_ml_api_spans, parse_otel_traces


def payload(attributes, *, name="chat gpt-4o", scope="vendor.instrumentation"):
    span = {
        "traceId": "a" * 32,
        "spanId": "b" * 16,
        "name": name,
        "attributes": [{"key": key, "value": {"stringValue": value}} for key, value in attributes.items()],
    }
    return {"resourceSpans": [{"scopeSpans": [{"scope": {"name": scope}, "spans": [span]}]}]}


@pytest.mark.parametrize("legacy", [False, True])
def test_current_provider_attribute_is_detected_and_preferred(legacy):
    attrs = {
        "gen_ai.provider.name": "openai",
        "gen_ai.operation.name": "chat",
        "gen_ai.request.model": "gpt-4o",
        "gen_ai.usage.input_tokens": "100",
        "gen_ai.usage.output_tokens": "20",
    }
    if legacy:
        attrs["gen_ai.system"] = "old-provider"
    calls = parse_ml_api_spans(payload(attrs))
    assert len(calls) == 1
    assert (calls[0].provider, calls[0].model_name, calls[0].input_tokens, calls[0].output_tokens) == ("openai", "gpt-4o", 100, 20)


@pytest.mark.parametrize("name", ["execute_tool read_file", "adk.tool.old_name"])
@pytest.mark.parametrize("flat", [False, True])
@pytest.mark.parametrize("legacy", [False, True])
def test_current_tool_attribute_is_detected_and_preferred(name, flat, legacy):
    attrs = {"gen_ai.tool.name": "read_file", "mcp.server": "files"}
    if legacy:
        attrs["tool.name"] = "old_name"
    data = payload(attrs, name=name)
    if flat:
        data = {"spans": data["resourceSpans"][0]["scopeSpans"][0]["spans"]}
    traces = parse_otel_traces(data)
    assert len(traces) == 1
    assert (traces[0].tool_name, traces[0].server_name) == ("read_file", "files")


@pytest.mark.parametrize("operation", ["execute_tool", "invoke_agent", "create_agent", "invoke_workflow", "retrieval", "fetch_response"])
def test_non_inference_operations_are_not_cost_calls(operation):
    # Even a known model SDK scope and legacy provider cannot turn an agent or
    # tool wrapper into another billable inference call.
    data = payload(
        {"gen_ai.provider.name": "openai", "gen_ai.system": "openai", "gen_ai.operation.name": operation},
        name=f"{operation} example",
        scope="opentelemetry-instrumentation-openai",
    )
    assert parse_ml_api_spans(data) == []
