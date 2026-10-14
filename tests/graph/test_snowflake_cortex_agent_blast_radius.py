"""Cortex Agents end to end: mocked Snowflake cursor -> discovery + governance -> one graph.

SHOW AGENTS / DESCRIBE AGENT / SHOW GRANTS ON AGENT / ACCESS_HISTORY / usage
history / GET_AI_OBSERVABILITY_EVENTS rows are served by a fake connection. The
object-graph and exfil payloads (role grants, sensitivity tags) are supplied as
the dicts those discoverers emit. All identifiers are fictitious.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from agent_bom.canonical_ids import snowflake_cortex_agent_node_id, snowflake_cortex_tool_node_id
from agent_bom.cloud.snowflake_discovery import ai_surfaces, estate
from agent_bom.governance import GovernanceReport
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.edge_evidence import recorded_tier
from agent_bom.graph.types import RelationshipType
from agent_bom.models import AIBOMReport
from agent_bom.output.json_fmt import to_json

ACCOUNT = "FAKEORG-TEST01"
SUPPORT = snowflake_cortex_agent_node_id(ACCOUNT, "ANALYTICS_DB", "AGENTS", "SUPPORT_AGENT")
FINANCE = snowflake_cortex_agent_node_id(ACCOUNT, "ANALYTICS_DB", "AGENTS", "FINANCE_AGENT")
PII_TABLE = "data_store:snowflake:ANALYTICS_DB.SUPPORT.CUSTOMERS_PII"
LEDGER_TABLE = "data_store:snowflake:FINANCE_DB.LEDGER.ENTRIES"
RAW_SECRET = "SSN 078-05-1120 belongs to customer"
SPAN_USER = "SPAN_ONLY_USER_7Q"

SUPPORT_SPEC = {
    "models": {"orchestration": "auto"},
    "tools": [
        {"tool_spec": {"type": "cortex_analyst_text_to_sql", "name": "Analyst1"}},
        {"tool_spec": {"type": "cortex_search", "name": "Search1"}},
        {"tool_spec": {"type": "generic", "name": "refund_lookup"}},
    ],
    "tool_resources": {
        "Analyst1": {
            "semantic_view": "analytics_db.semantic.support_view",
            "execution_environment": {"type": "warehouse", "warehouse": "AGENT_WH"},
        },
        "Search1": {"search_service": "ANALYTICS_DB.SEARCH.TICKETS_SVC"},
        "refund_lookup": {
            "type": "procedure",
            "identifier": "ANALYTICS_DB.TOOLS.REFUND_LOOKUP",
            "execution_environment": {"type": "warehouse", "warehouse": "AGENT_WH"},
        },
    },
}
FINANCE_SPEC = {
    "tools": [{"tool_spec": {"type": "generic", "name": "Ledger"}}],
    "tool_resources": {"Ledger": {"type": "function", "identifier": "FINANCE_DB.TOOLS.LEDGER_SUM"}},
}


def _span(
    span_id: str, name: str, *, parent: str = "", attrs: dict[str, Any] | None = None, ts: str = "2026-10-01T10:00:01Z"
) -> dict[str, Any]:
    return {
        "timestamp": ts,
        "start_timestamp": "2026-10-01T10:00:00Z",
        "trace": json.dumps({"trace_id": "trace-1", "span_id": span_id}),
        "resource_attributes": json.dumps(
            {"snow.user.name": SPAN_USER, "snow.session.role.primary.name": "SUPPORT_ROLE", "snow.warehouse.name": "AGENT_WH"}
        ),
        "record": json.dumps(
            {"name": name, "kind": "SPAN_KIND_INTERNAL", "parent_span_id": parent, "status": {"code": "STATUS_CODE_UNSET"}}
        ),
        "record_attributes": json.dumps(attrs or {}),
        "value": None,
    }


SUPPORT_SPANS = [
    _span("s0", "AgentRun"),
    _span("s1", "AgentV2RequestResponseInfo.planning", parent="s0", attrs={"snow.ai.observability.agent.planning.model": "fake-model"}),
    _span(
        "s2",
        "ToolCall",
        parent="s0",
        attrs={"snow.ai.observability.agent.tool.name": "Analyst1", "ai.observability.tool.input": RAW_SECRET},
    ),
    _span("s3", "ToolCall", parent="s0", attrs={"snow.ai.observability.agent.tool.name": "Search1"}, ts="2026-10-01T10:00:02Z"),
    _span("s4", "ToolCall", parent="s0", attrs={"snow.ai.observability.agent.tool.name": "Search1"}, ts="2026-10-01T10:00:05Z"),
    # Ledger belongs to FINANCE_AGENT; on SUPPORT_AGENT it is undeclared and must not attach.
    _span(
        "s5", "ToolCall", parent="s0", attrs={"snow.ai.observability.agent.tool.name": "Ledger", "ai.observability.tool.output": RAW_SECRET}
    ),
]


def _result(columns: list[str], rows: list[dict[str, Any]]) -> tuple[list[str], list[tuple[Any, ...]]]:
    return columns, [tuple(row.get(col) for col in columns) for row in rows]


_SPAN_COLS = ["timestamp", "start_timestamp", "trace", "resource_attributes", "record", "record_attributes", "value"]
_GRANT_COLS = ["privilege", "granted_on", "name", "granted_to", "grantee_name"]
RESPONSES: list[tuple[str, tuple[list[str], list[tuple[Any, ...]]]]] = [
    (
        "SHOW AGENTS IN ACCOUNT",
        _result(
            ["name", "database_name", "schema_name", "owner", "profile", "is_secure"],
            [
                {
                    "name": n,
                    "database_name": "ANALYTICS_DB",
                    "schema_name": "AGENTS",
                    "owner": "AGENT_ADMIN",
                    "profile": None,
                    "is_secure": "false",
                }
                for n in ("SUPPORT_AGENT", "FINANCE_AGENT")
            ],
        ),
    ),
    (
        'DESCRIBE AGENT "ANALYTICS_DB"."AGENTS"."SUPPORT_AGENT"',
        _result(
            ["name", "owner", "agent_spec"], [{"name": "SUPPORT_AGENT", "owner": "AGENT_ADMIN", "agent_spec": json.dumps(SUPPORT_SPEC)}]
        ),
    ),
    (
        'DESCRIBE AGENT "ANALYTICS_DB"."AGENTS"."FINANCE_AGENT"',
        _result(
            ["name", "owner", "agent_spec"], [{"name": "FINANCE_AGENT", "owner": "AGENT_ADMIN", "agent_spec": json.dumps(FINANCE_SPEC)}]
        ),
    ),
    (
        'SHOW GRANTS ON AGENT "ANALYTICS_DB"."AGENTS"."SUPPORT_AGENT"',
        _result(
            _GRANT_COLS,
            [
                {"privilege": "USAGE", "granted_on": "AGENT", "granted_to": "ROLE", "grantee_name": "SUPPORT_ROLE"},
                {"privilege": "MONITOR", "granted_on": "AGENT", "granted_to": "ROLE", "grantee_name": "AUDITOR_ROLE"},
            ],
        ),
    ),
    (
        'SHOW GRANTS ON AGENT "ANALYTICS_DB"."AGENTS"."FINANCE_AGENT"',
        _result(_GRANT_COLS, [{"privilege": "USAGE", "granted_on": "AGENT", "granted_to": "ROLE", "grantee_name": "FINANCE_ROLE"}]),
    ),
    ("GET_AI_OBSERVABILITY_EVENTS('ANALYTICS_DB', 'AGENTS', 'SUPPORT_AGENT', 'CORTEX AGENT')", _result(_SPAN_COLS, SUPPORT_SPANS)),
    ("GET_AI_OBSERVABILITY_EVENTS('ANALYTICS_DB', 'AGENTS', 'FINANCE_AGENT', 'CORTEX AGENT')", _result(_SPAN_COLS, [])),
    (
        "CORTEX_AGENT_USAGE_HISTORY",
        _result(
            ["agent_name", "agent_database_name", "agent_schema_name", "user_name", "tokens", "token_credits", "metadata"],
            [{"agent_name": "SUPPORT_AGENT", "agent_database_name": "ANALYTICS_DB", "agent_schema_name": "AGENTS", "tokens": 120}],
        ),
    ),
    ("INFORMATION_SCHEMA.FUNCTIONS", ([], [("LEDGER_SUM", "()", "NUMBER", "SQL"), ("UNRELATED_UDF", "()", "VARCHAR", "PYTHON")])),
    ("INFORMATION_SCHEMA.PROCEDURES", ([], [("REFUND_LOOKUP", "()", "VARCHAR", "SQL")])),
]


class _Cursor:
    def __init__(self, log: list[str]) -> None:
        self.log = log
        self.description: list[tuple[str]] | None = None
        self._rows: list[tuple[Any, ...]] = []

    def execute(self, sql: str, *args: Any) -> None:
        self.log.append(sql)
        for needle, (columns, rows) in RESPONSES:
            if needle in sql:
                self.description = [(col,) for col in columns]
                self._rows = rows
                return
        raise RuntimeError("not available in fixture")

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows

    def close(self) -> None:
        pass


class _Conn:
    def __init__(self) -> None:
        self.log: list[str] = []

    def cursor(self) -> _Cursor:
        return _Cursor(self.log)

    def close(self) -> None:
        pass


def _object_graph() -> dict[str, Any]:
    return {
        "status": "ok",
        "account": ACCOUNT,
        "objects": [
            {"fqn": "ANALYTICS_DB.SUPPORT.CUSTOMERS_PII", "object_type": "table"},
            {"fqn": "FINANCE_DB.LEDGER.ENTRIES", "object_type": "table"},
        ],
        "grants": [
            {"role": "SUPPORT_ROLE", "privilege": "SELECT", "object_fqn": "ANALYTICS_DB.SUPPORT.CUSTOMERS_PII", "object_type": "TABLE"},
            {"role": "FINANCE_ROLE", "privilege": "SELECT", "object_fqn": "FINANCE_DB.LEDGER.ENTRIES", "object_type": "TABLE"},
        ],
    }


def _exfil() -> dict[str, Any]:
    return {"status": "ok", "account": ACCOUNT, "sensitive_objects": [{"fqn": "ANALYTICS_DB.SUPPORT.CUSTOMERS_PII", "sensitivity": "PII"}]}


@pytest.fixture(scope="module")
def scanned() -> dict[str, Any]:
    conn = _Conn()
    agents: list[Any] = []
    warnings: list[str] = []
    ai_surfaces._discover_ai_surfaces(conn, ACCOUNT, None, None, agents, warnings)
    governance = GovernanceReport(account=ACCOUNT)
    ai_surfaces._mine_governance_report(conn, 30, governance)
    report = AIBOMReport(agents=agents)
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("agent_bom.cloud.snowflake.discover_governance", lambda **_: governance)
        estate._estate_governance(report, ACCOUNT)
    report.snowflake_object_graph_data = _object_graph()
    report.snowflake_exfil_graph_data = _exfil()
    out = to_json(report)
    return {"out": out, "graph": build_unified_graph_from_report(out), "agents": agents, "sql": conn.log}


def _declared_tools(graph: Any, agent_id: str) -> set[str]:
    return {graph.nodes[e.target].label for e in graph.edges_from(agent_id) if e.relationship is RelationshipType.REACHES_TOOL}


def test_one_canonical_node_per_cortex_agent(scanned: dict[str, Any]) -> None:
    graph = scanned["graph"]
    support_nodes = [nid for nid, node in graph.nodes.items() if node.entity_type.value == "agent" and "SUPPORT_AGENT" in nid]
    assert support_nodes == [SUPPORT]
    node = graph.nodes[SUPPORT]
    # Discovery inventory, DESCRIBE AGENT and usage history all landed on it.
    assert node.attributes["source"] == "snowflake-cortex-agent"
    assert node.label == "cortex-agent:SUPPORT_AGENT"
    assert node.attributes["cortex_spec_status"] == "described"
    assert node.attributes["call_count"] == 1
    assert node.attributes["execution_model"] == "caller_role"
    assert not any(nid.startswith("agent:cortex-agent:") for nid in graph.nodes)


def test_agents_carry_only_their_declared_tools(scanned: dict[str, Any]) -> None:
    graph = scanned["graph"]
    assert _declared_tools(graph, SUPPORT) == {"Analyst1", "Search1", "refund_lookup"}
    assert _declared_tools(graph, FINANCE) == {"Ledger"}
    by_agent = {a.name: {t.name for s in a.mcp_servers for t in s.tools} for a in scanned["agents"]}
    assert by_agent["cortex-agent:SUPPORT_AGENT"] == {"Analyst1", "Search1", "refund_lookup"}
    assert by_agent["cortex-agent:FINANCE_AGENT"] == {"Ledger"}
    # Account UDFs/procedures are inventoried once, never pinned onto every agent.
    assert by_agent[f"snowflake-tools:{ACCOUNT}"] == {"LEDGER_SUM", "UNRELATED_UDF", "REFUND_LOOKUP"}
    procedure = "cloud_resource:snowflake:procedure:ANALYTICS_DB.TOOLS.REFUND_LOOKUP"
    refund_tool = snowflake_cortex_tool_node_id(SUPPORT, "SUPPORT_AGENT", "refund_lookup")
    assert [e.target for e in graph.edges_from(refund_tool) if e.relationship is RelationshipType.CAN_ACCESS] == [
        procedure,
        "cloud_resource:snowflake:warehouse:AGENT_WH",
    ]
    analyst = snowflake_cortex_tool_node_id(SUPPORT, "SUPPORT_AGENT", "Analyst1")
    assert "data_store:snowflake:ANALYTICS_DB.SEMANTIC.SUPPORT_VIEW" in {e.target for e in graph.edges_from(analyst)}


def test_execution_roles_reach_sensitive_tables_without_crossing_agents(scanned: dict[str, Any]) -> None:
    graph = scanned["graph"]
    assumes = {e.target: e for e in graph.edges_from(SUPPORT) if e.relationship is RelationshipType.ASSUMES}
    # MONITOR does not let a role run the agent.
    assert set(assumes) == {"role:snowflake:SUPPORT_ROLE"}
    support_role = assumes["role:snowflake:SUPPORT_ROLE"].evidence
    assert support_role["execution_model"] == "caller_role"
    assert recorded_tier(support_role) == "modeled_infrastructure"
    # The span-observed session role merges onto the grant edge without replacing its basis.
    assert support_role["basis"] == "agent_grant_caller_context"
    assert support_role["observed"]["source"] == "snowflake-cortex-observability"
    assert support_role["observed"]["event_count"] == 6
    support_reach = graph.reachable_from(SUPPORT, traversable_only=True)
    finance_reach = graph.reachable_from(FINANCE, traversable_only=True)
    assert PII_TABLE in support_reach and LEDGER_TABLE not in support_reach
    assert LEDGER_TABLE in finance_reach and PII_TABLE not in finance_reach
    assert graph.nodes[PII_TABLE].attributes["sensitivity"] == "PII"
    assert SUPPORT in graph.impact_of(PII_TABLE)["affected_nodes"]
    assert FINANCE not in graph.impact_of(PII_TABLE)["affected_nodes"]


def test_telemetry_edges_aggregate_on_the_canonical_node(scanned: dict[str, Any]) -> None:
    graph = scanned["graph"]
    invoked = {graph.nodes[e.target].label: e for e in graph.edges_from(SUPPORT) if e.relationship is RelationshipType.INVOKED}
    assert set(invoked) == {"Analyst1", "Search1"}
    assert invoked["Search1"].evidence["observed"]["event_count"] == 2
    assert invoked["Search1"].evidence["observed"]["first_seen"] == "2026-10-01T10:00:00Z"
    assert invoked["Search1"].evidence["observed"]["last_seen"] == "2026-10-01T10:00:05Z"
    assert recorded_tier(invoked["Search1"].evidence) == "runtime_observed"
    accessed = [e for e in graph.edges_from(SUPPORT) if e.relationship is RelationshipType.ACCESSED]
    assert [e.target for e in accessed] == ["cloud_resource:snowflake:warehouse:AGENT_WH"]
    assert accessed[0].evidence["observed"]["event_count"] == 6
    assert graph.nodes[SUPPORT].attributes["cortex_telemetry"]["unmatched_tool_events"] == 1
    assert not any(e.relationship is RelationshipType.INVOKED for e in graph.edges_from(FINANCE))
    events = scanned["out"]["snowflake_governance"]["cortex_events"]
    assert {e["agent_ref"] for e in events} == {SUPPORT}
    assert [e["match_method"] for e in events if e["tool_name"] == "Ledger"] == ["none"]


def test_no_raw_tool_content_or_principal_is_stored(scanned: dict[str, Any]) -> None:
    stored = json.dumps(scanned["out"], default=str) + json.dumps(scanned["graph"].to_dict(), default=str)
    assert RAW_SECRET not in stored
    assert SPAN_USER not in stored
    events = scanned["out"]["snowflake_governance"]["cortex_events"]
    assert all(e["content_sha256"] for e in events if e["source_span_id"] in {"s2", "s5"})
    assert all(len(e["principal_hash"]) == 64 for e in events)


def test_reads_are_read_only(scanned: dict[str, Any]) -> None:
    for sql in scanned["sql"]:
        assert sql.lstrip().split()[0].upper() in {"SHOW", "DESCRIBE", "SELECT"}, sql


def test_discovery_and_spec_tools_are_one_node_each(scanned: dict[str, Any]) -> None:
    graph = scanned["graph"]
    for label in ("Analyst1", "Search1", "refund_lookup", "Ledger"):
        assert len([n for n in graph.nodes.values() if n.entity_type.value == "tool" and n.label == label]) == 1, label


def test_same_agent_name_in_two_accounts_stays_two_nodes() -> None:
    def governance(account: str) -> dict[str, Any]:
        agent = {"account": account, "database": "DB", "schema": "S", "name": "HELPER", "tools": [], "execution_roles": []}
        event = {"agent_ref": snowflake_cortex_agent_node_id(account, "DB", "S", "HELPER"), "match_method": "exact", "role_name": "R"}
        return {"status": "ok", "account": account, "cortex_agents": [agent], "cortex_events": [event]}

    report = {
        "snowflake_governance": governance("FAKEORG-ACCT_A"),
        "snowflake_object_graph": {"status": "ok", "account": "FAKEORG-ACCT_B", "grants": [{"role": "R", "object_fqn": "DB.S.T"}]},
    }
    report["snowflake_activity"] = {"status": "ok", "account": "FAKEORG-ACCT_B", "summary": {}}
    graph = build_unified_graph_from_report(report)
    agent_a = snowflake_cortex_agent_node_id("FAKEORG-ACCT_A", "DB", "S", "HELPER")
    assert agent_a in graph.nodes
    # Two account scopes rescope the account-local role; the qualified agent id is kept
    # and its edges follow the rescoped role of its own account only.
    [assumed] = [e.target for e in graph.edges_from(agent_a) if e.relationship is RelationshipType.ASSUMES]
    assert graph.nodes[assumed].attributes["account_id"] == "FAKEORG-ACCT_A"
    assert assumed != "role:snowflake:R"


def test_events_for_unknown_agents_are_counted_not_attached() -> None:
    stray = snowflake_cortex_agent_node_id("FAKEORG-TEST01", "DB", "S", "GONE")
    report = {
        "snowflake_governance": {
            "status": "ok",
            "account": "FAKEORG-TEST01",
            "cortex_agents": [],
            "cortex_events": [{"agent_ref": stray, "match_method": "exact", "match_node_id": stray, "role_name": "R"}],
        }
    }
    graph = build_unified_graph_from_report(report)
    assert stray not in graph.nodes
    assert graph.nodes["account:snowflake:FAKEORG-TEST01"].attributes["cortex_telemetry_summary"] == {"events": 1, "unmatched_agent": 1}
