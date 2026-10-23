"""Local review of what coding agents did: a view over session spans plus discovery.

Usage and unused-server judgements come from the shared runtime trace
projection over the discovery graph, so the same exact-binding rules apply as
for any imported trace. Nothing leaves the machine unless ``check_packages``
asks the existing vulnerability check to look installed packages up.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agent_bom.canonical_ids import agent_graph_id_for
from agent_bom.models import AgentType, AIBOMReport
from agent_bom.runtime.agent_sessions import PROVIDER_AGENT_TYPES, SessionBounds
from agent_bom.runtime.agent_sessions.bindings import SessionBindings
from agent_bom.runtime.agent_sessions.findings import LowSignalWrites, installed_packages, risky_actions
from agent_bom.runtime.agent_sessions.package_checks import check_installed_packages
from agent_bom.runtime.agent_sessions.projection import project_session_spans
from agent_bom.runtime.agent_sessions.provider import default_since, fetch_local_session_traces
from agent_bom.runtime.agent_sessions.spans import redact_path
from agent_bom.runtime.agent_sessions.summary import build_summary
from agent_bom.runtime.agent_sessions.views import CallView, call_views, later

SCHEMA_VERSION = "agent_activity.v1"
_AGENT_TYPES = set(PROVIDER_AGENT_TYPES.values())


def discover_session_agents(project: str | None = None) -> list[Any]:
    """Reuse discovery for the clients whose history is read (Claude Code, Codex)."""
    from agent_bom.discovery import discover_global_configs, discover_project_configs

    agents = discover_global_configs([AgentType.CLAUDE_CODE, AgentType.CODEX_CLI], quiet=True)
    agents.extend(discover_project_configs(project) if project else [])
    return [agent for agent in agents if agent.agent_type.value in _AGENT_TYPES]


def _window(since: datetime, until: datetime, project: str | None) -> dict[str, Any]:
    days = max(1, round((until - since).total_seconds() / 86400))
    label = f"Last {days} days ({since.date().isoformat()} to {until.date().isoformat()})"
    return {"since": since.isoformat(), "until": until.isoformat(), "days": days, "label": label, "project": project}


def _usage(views: list[CallView]) -> tuple[dict[tuple[str, str], dict[str, Any]], dict[tuple[str, str], dict[str, Any]]]:
    servers: dict[tuple[str, str], dict[str, Any]] = {}
    builtin: dict[tuple[str, str], dict[str, Any]] = {}
    for view in views:
        if view.server:
            row = servers.setdefault((view.agent, view.server), {"calls": 0, "last_used": "", "tools": {}})
            tool = row["tools"].setdefault(view.tool, {"tool": view.tool, "calls": 0, "last_used": ""})
            tool["calls"] += 1
            tool["last_used"] = later(tool["last_used"], view.timestamp)
        else:
            row = builtin.setdefault((view.agent, view.tool), {"calls": 0, "last_used": ""})
        row["calls"] += 1
        row["last_used"] = later(row["last_used"], view.timestamp)
    return servers, builtin


def _server_rows(servers: dict, bindings: SessionBindings, graph: Any) -> list[dict[str, Any]]:
    rows = []
    for (agent, name), usage in sorted(servers.items()):
        binding = bindings.server(agent, name)
        node = graph.get_node(binding.server_id) if binding else None
        observed = bool(node is not None and node.attributes.get("runtime_trace_use"))
        rows.append(
            {
                "agent": agent,
                "server": name,
                "configured": bool(bindings.servers.get((agent, name))),
                "usage_basis": "exact" if observed else "name_only",
                "server_id": binding.server_id if binding else None,
                "calls": usage["calls"],
                "last_used": usage["last_used"],
                "tools": sorted(usage["tools"].values(), key=lambda tool: (-tool["calls"], tool["tool"])),
            }
        )
    return rows


def _unused(bindings: SessionBindings, servers: dict, history: dict[str, bool], agents: Iterable[Any]) -> list[dict[str, Any]]:
    config_by_agent = {agent_id: getattr(agent, "config_path", "") for agent in agents if (agent_id := _agent_id(agent))}
    rows = []
    for agent_type in sorted(agent for agent, found in history.items() if found):
        for binding in bindings.configured(agent_type):
            if (agent_type, binding.name) in servers:
                continue
            rows.append(
                {
                    "agent": agent_type,
                    "server": binding.name,
                    "server_id": binding.server_id,
                    "config_path": redact_path(str(config_by_agent.get(binding.agent_id) or "")),
                    "reason": "configured but never called in the window",
                }
            )
    return rows


def _agent_id(agent: Any) -> str:
    return agent_graph_id_for(agent)


def _graph(agents: list[Any], spans: list[dict[str, Any]], since: datetime, until: datetime) -> tuple[Any, Any]:
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.output.json_fmt import to_json

    graph = build_unified_graph_from_report(to_json(AIBOMReport(agents=agents)), tenant_id="local")
    return graph, project_session_spans(graph, spans, window_start=since, window_end=until)


def build_activity_report(
    *,
    home: Path | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    project: str | None = None,
    agents: list[Any] | None = None,
    check_packages: bool = False,
    bounds: SessionBounds | None = None,
) -> dict[str, Any]:
    until = until or datetime.now(timezone.utc)
    since = since or default_since()
    relevant = [a for a in (discover_session_agents(project) if agents is None else agents) if a.agent_type.value in _AGENT_TYPES]
    bindings = SessionBindings.from_agents(relevant)
    sources, spans = {}, []
    for provider in PROVIDER_AGENT_TYPES:
        payload = fetch_local_session_traces(provider, home=home, since=since, project=project, bindings=bindings, bounds=bounds)
        sources[provider] = payload["read"]
        spans.extend(payload["spans"])
    views = list(call_views(spans))
    graph, projection = _graph(relevant, spans, since, until)
    servers, builtin = _usage(views)
    history = {PROVIDER_AGENT_TYPES[p]: bool(stats["history_found"] and stats["files_read"]) for p, stats in sources.items()}
    packages = installed_packages(views)
    low_signal = LowSignalWrites()
    risky_rows, risky_totals = risky_actions(views, low_signal=low_signal)
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "window": _window(since, until, project),
        "sources": sources,
        "totals": {
            "sessions": len({(view.provider, view.session_id) for view in views}),
            "tool_calls": len(views),
            "mcp_calls": sum(1 for view in views if view.server),
            "builtin_calls": sum(1 for view in views if not view.server),
        },
        "mcp_servers": _server_rows(servers, bindings, graph),
        "builtin_tools": [
            {"agent": a, "tool": t, **row} for (a, t), row in sorted(builtin.items(), key=lambda kv: (-kv[1]["calls"], kv[0]))
        ],
        "unused_servers": _unused(bindings, servers, history, relevant),
        "risky_actions": risky_rows,
        "risky_action_totals": risky_totals,
        "low_signal_writes": low_signal.to_dict(),
        "risky_actions_truncated": any(row["shown"] < row["distinct"] for row in risky_totals.values()),
        "installed_packages": packages,
        "package_checks": _check(packages) if check_packages else None,
        "graph": {"runtime_edges": projection.edges, "observed": dict(projection.observed)},
        "truncated": any(stats["truncated"] for stats in sources.values()),
    }
    report["summary"] = build_summary(report)
    report["risk_counts"] = {level: sum(total[level] for total in risky_totals.values()) for level in ("high", "medium", "low")}
    return report


def _check(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return check_installed_packages(packages)
