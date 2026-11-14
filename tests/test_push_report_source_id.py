"""A saved report and a direct push from one host scope agents to the same graph node."""

from __future__ import annotations

import copy

from agent_bom.canonical_ids import agent_graph_id_for
from agent_bom.cli.agents.scan_pipeline.report_source_ids import with_endpoint_source_ids
from agent_bom.push import sanitize_results

_AGENT = {
    "name": "project:projA",
    "canonical_id": "87f4e602-305c-589e-8f92-ccf8a5e2c407",
    "stable_id": "87f4e602-305c-589e-8f92-ccf8a5e2c407",
    "agent_type": "custom",
    "config_path": "<path:.mcp.json>",
    "source": "project-config",
    "previous_graph_ids": ["agent:legacy"],
    "mcp_servers": [],
}


def test_saved_report_agent_takes_the_direct_push_graph_id(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_PUSH_SOURCE_ID", "host-a")
    report = {"agents": [copy.deepcopy(_AGENT)]}
    before = copy.deepcopy(report)

    saved = with_endpoint_source_ids(report)
    pushed = sanitize_results(report)

    assert report == before
    agent = saved["agents"][0]
    assert agent["source_id"] == "host-a"
    assert agent_graph_id_for(agent) == agent_graph_id_for(pushed["agents"][0]) == "agent:host-a:project%3AprojA"
    assert agent["canonical_id"] == _AGENT["canonical_id"]
    # The id the saved report used to give this agent stays resolvable.
    assert agent_graph_id_for(_AGENT).startswith("agent:cfg-")
    assert agent["previous_graph_ids"] == ["agent:legacy", agent_graph_id_for(_AGENT)]


def test_existing_scope_and_non_agent_rows_are_left_alone(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_PUSH_SOURCE_ID", "host-a")
    scoped = {**_AGENT, "source_id": "fleet-device-7"}
    report = {"agents": [scoped, "not-an-agent"]}
    assert with_endpoint_source_ids(report)["agents"] == [scoped, "not-an-agent"]
    assert with_endpoint_source_ids({"findings": []}) == {"findings": []}
