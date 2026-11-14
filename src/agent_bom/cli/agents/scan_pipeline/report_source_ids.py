"""Give a saved scan report the endpoint scope a direct push would give it."""

from __future__ import annotations

from typing import Any

from agent_bom.canonical_ids import agent_graph_id_for
from agent_bom.push import generate_source_id


def with_endpoint_source_ids(report: dict[str, Any]) -> dict[str, Any]:
    """The report with this machine's ``source_id`` on every agent that lacks one.

    ``push.sanitize_results`` stamps the same value before a direct push, so a
    saved report POSTed later from this host scopes its agents to the same
    graph nodes. Agent canonical ids are unchanged, the id a saved report used
    to give the agent stays a ``previous_graph_ids`` alias, and the input is
    not mutated.
    """
    agents = report.get("agents")
    if not isinstance(agents, list):
        return report
    source_id = generate_source_id()
    return {**report, "agents": [_with_source_id(agent, source_id) for agent in agents]}


def _with_source_id(agent: Any, source_id: str) -> Any:
    if not isinstance(agent, dict) or agent.get("source_id"):
        return agent
    stamped = {**agent, "source_id": source_id}
    former, current = agent_graph_id_for(agent), agent_graph_id_for(stamped)
    previous = [value for value in agent.get("previous_graph_ids") or [] if isinstance(value, str)]
    if former != current and former not in previous:
        stamped["previous_graph_ids"] = [*previous, former]
    return stamped


__all__ = ["with_endpoint_source_ids"]
