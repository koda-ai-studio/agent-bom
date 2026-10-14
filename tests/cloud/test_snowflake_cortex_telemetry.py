"""Cortex observability span -> normalized trace event field mapping.

The fixture row follows the event-table layout GET_AI_OBSERVABILITY_EVENTS
returns: TIMESTAMP / START_TIMESTAMP, TRACE{trace_id, span_id},
RECORD{name, parent_span_id, status}, RESOURCE_ATTRIBUTES (snow.* keys),
RECORD_ATTRIBUTES and VALUE. Identifiers are fictitious.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from agent_bom.canonical_ids import snowflake_cortex_agent_node_id, snowflake_cortex_tool_node_id
from agent_bom.cloud.snowflake_discovery.cortex_agents import parse_agent_spec
from agent_bom.cloud.snowflake_discovery.cortex_telemetry import (
    FIELD_MAP,
    NORMALIZED_FIELDS,
    UNSUPPLIED_FIELDS,
    fetch_cortex_agent_spans,
    normalize_cortex_span,
)

ACCOUNT = "FAKEORG-TEST01"
AGENT = snowflake_cortex_agent_node_id(ACCOUNT, "DB", "AGENTS", "HELPDESK")

ROW = {
    "timestamp": "2026-10-02T08:00:03Z",
    "start_timestamp": "2026-10-02T08:00:01Z",
    "trace": {"trace_id": "4bf92f3577b34da6a3ce929d0e0e4736", "span_id": "00f067aa0ba902b7"},
    "resource_attributes": {
        "snow.user.name": "FAKE_USER",
        "snow.session.role.primary.name": "HELPDESK_ROLE",
        "snow.warehouse.name": "HELPDESK_WH",
        "snow.database.name": "DB",
    },
    "record": {
        "name": "ToolCall",
        "kind": "SPAN_KIND_INTERNAL",
        "parent_span_id": "a3ce929d0e0e4736",
        "status": {"code": "STATUS_CODE_ERROR"},
    },
    "record_attributes": {
        "snow.ai.observability.agent.tool.name": "Search1",
        "snow.ai.observability.agent.planning.model": "fake-model",
        "gen_ai.usage.prompt_tokens": 41,
        "gen_ai.usage.completion_tokens": 7,
        "ai.observability.tool.input": "order 1234 for jane@example.invalid",
    },
    "value": None,
}

# documented event-table field -> expected normalized value
MAPPING = {
    "source_trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "source_span_id": "00f067aa0ba902b7",
    "parent_span_id": "a3ce929d0e0e4736",
    "started_at": "2026-10-02T08:00:01Z",
    "ended_at": "2026-10-02T08:00:03Z",
    "kind": "tool",
    "status": "error",
    "principal_hash": hashlib.sha256(b"FAKE_USER").hexdigest(),
    "role_name": "HELPDESK_ROLE",
    "resource_refs": ["warehouse:HELPDESK_WH"],
    "model_name": "fake-model",
    "agent_name": "DB.AGENTS.HELPDESK",
    "agent_ref": AGENT,
    "tool_name": "Search1",
    "input_tokens": 41,
    "output_tokens": 7,
    "source": "snowflake_cortex",
    "tenant_id": "tenant-from-connection",
    "match_method": "exact",
    "match_node_id": snowflake_cortex_tool_node_id(AGENT, "HELPDESK", "Search1"),
}


def _normalize(row=ROW, declared=frozenset({"Search1"})):
    return normalize_cortex_span(
        {key: json.dumps(value) if isinstance(value, dict) else value for key, value in row.items()},
        account=ACCOUNT,
        database="DB",
        schema="AGENTS",
        agent_name="HELPDESK",
        declared_tools=declared,
        tenant_id="tenant-from-connection",
    )


def test_normalized_event_has_exactly_the_canonical_fields() -> None:
    assert tuple(_normalize()) == NORMALIZED_FIELDS


@pytest.mark.parametrize(("field", "expected"), sorted(MAPPING.items()))
def test_documented_field_maps_to_canonical_field(field: str, expected: object) -> None:
    assert _normalize()[field] == expected


def test_field_coverage_matches_the_documented_mapping() -> None:
    event = _normalize()
    supplied = {field for field, value in event.items() if value not in (None, [], "")}
    assert supplied == set(NORMALIZED_FIELDS) - set(UNSUPPLIED_FIELDS)
    mapped = {target for _source, targets, _status in FIELD_MAP for target in targets.replace(" ", "").split("/")}
    assert supplied - mapped == {"tenant_id", "source", "signals", "match_method", "match_node_id"}


def test_raw_content_becomes_a_digest_only() -> None:
    event = _normalize()
    assert "jane@example.invalid" not in json.dumps(event)
    assert "FAKE_USER" not in json.dumps(event)
    assert len(event["content_sha256"]) == 64
    assert event["signals"] == ["content_hashed", "error"]


def test_undeclared_tool_is_not_matched() -> None:
    event = _normalize(declared=frozenset({"Analyst1"}))
    assert (event["match_method"], event["match_node_id"]) == ("none", None)
    assert "undeclared_tool" in event["signals"]


def test_root_span_without_tool_is_the_agent() -> None:
    row = {**ROW, "record": {"name": "AgentRun", "parent_span_id": "", "status": {"code": "STATUS_CODE_UNSET"}}, "record_attributes": {}}
    event = _normalize(row)
    assert (event["kind"], event["status"], event["match_node_id"]) == ("agent", "ok", AGENT)


def test_fetch_uses_the_documented_per_agent_function() -> None:
    executed: list[str] = []

    class Cursor:
        description = None

        def execute(self, sql: str) -> None:
            executed.append(sql)

        def fetchall(self) -> list:
            return []

        def close(self) -> None:
            pass

    class Conn:
        def cursor(self) -> Cursor:
            return Cursor()

    agent = {"account": ACCOUNT, "database": "DB", "schema": "AGENTS", "name": "it's"}
    assert fetch_cortex_agent_spans(Conn(), agent, 7, []) == []
    [sql] = executed
    assert "SNOWFLAKE.LOCAL.GET_AI_OBSERVABILITY_EVENTS('DB', 'AGENTS', 'it''s', 'CORTEX AGENT')" in sql
    assert "record_type = 'SPAN'" in sql and "DATEADD(day, -7" in sql


def test_agent_spec_declares_tools_and_resources() -> None:
    tools = parse_agent_spec(
        json.dumps(
            {
                "tools": [
                    {"tool_spec": {"type": "cortex_analyst_text_to_sql", "name": "A"}},
                    {"tool_spec": {"type": "web_search", "name": "W"}},
                ],
                "tool_resources": {
                    "A": {"semantic_model_file": "@db.sch.models/m.yaml", "execution_environment": {"warehouse": '"Mixed_WH"'}}
                },
            }
        )
    )
    assert tools == [
        {
            "name": "A",
            "type": "cortex_analyst_text_to_sql",
            "resources": [{"kind": "stage", "fqn": "DB.SCH.MODELS"}, {"kind": "warehouse", "fqn": "Mixed_WH"}],
        },
        {"name": "W", "type": "web_search", "resources": []},
    ]
    assert parse_agent_spec(None) is None and parse_agent_spec("not json") is None
