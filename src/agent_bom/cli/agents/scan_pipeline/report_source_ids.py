"""Give a saved scan report the endpoint scope a direct push would give it."""

from __future__ import annotations

from typing import Any

from agent_bom.canonical_ids import agent_graph_id_for
from agent_bom.push import generate_source_id


def with_endpoint_source_ids(report: dict[str, Any], source_id: str = "") -> dict[str, Any]:
    """The report with ``source_id`` (default: this machine's) on every agent that lacks one.

    ``push.sanitize_results`` stamps the same value before a direct push, so a
    saved report POSTed later from this host scopes its agents to the same
    graph nodes. Agent canonical ids are unchanged, the id a saved report used
    to give the agent stays a ``previous_graph_ids`` alias, and the input is
    not mutated.
    """
    agents = report.get("agents")
    if not isinstance(agents, list):
        return report
    source_id = source_id or generate_source_id()
    return {**report, "agents": [_with_source_id(agent, source_id) for agent in agents]}


def endpoint_scoped_report(report: dict[str, Any], *, demo: bool) -> tuple[str, dict[str, Any]]:
    """This host's endpoint scope and the report stamped with it; demo agents are fictional and get neither."""
    if demo:
        return "", report
    source_id = generate_source_id()
    return source_id, with_endpoint_source_ids(report, source_id)


def _with_source_id(agent: Any, source_id: str) -> Any:
    if not isinstance(agent, dict) or agent.get("source_id"):
        return agent
    stamped = {**agent, "source_id": source_id}
    former, current = agent_graph_id_for(agent), agent_graph_id_for(stamped)
    previous = [value for value in agent.get("previous_graph_ids") or [] if isinstance(value, str)]
    if former != current and former not in previous:
        stamped["previous_graph_ids"] = [*previous, former]
    return stamped


__all__ = ["endpoint_scoped_report", "with_endpoint_source_ids"]
