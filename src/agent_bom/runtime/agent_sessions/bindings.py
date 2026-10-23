"""Exact inventory refs for session calls, resolved from agent-bom's own discovery.

A session names an MCP server by its config key. That key binds only when one
discovered config of the same client declares it; a name found in several
configs stays unbound so it is counted, never drawn as an edge.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agent_bom.canonical_ids import agent_graph_id_for, mcp_server_graph_id_for


@dataclass(frozen=True)
class ServerBinding:
    agent_id: str
    server_id: str
    name: str
    tools: frozenset[str] = frozenset()

    def tool_node(self, tool: str) -> str | None:
        return f"tool:{self.server_id}:{tool}" if tool in self.tools else None


@dataclass
class SessionBindings:
    agents: dict[str, set[str]] = field(default_factory=dict)
    servers: dict[tuple[str, str], dict[str, ServerBinding]] = field(default_factory=dict)

    @classmethod
    def from_agents(cls, agents: Iterable[Any]) -> SessionBindings:
        bindings = cls()
        for agent in agents:
            agent_type = str(getattr(getattr(agent, "agent_type", None), "value", "") or "")
            agent_id = agent_graph_id_for(agent)
            bindings.agents.setdefault(agent_type, set()).add(agent_id)
            for server in getattr(agent, "mcp_servers", None) or []:
                name = str(getattr(server, "name", "") or "")
                if not name:
                    continue
                tools = frozenset(str(tool.name) for tool in getattr(server, "tools", None) or [] if getattr(tool, "name", None))
                binding = ServerBinding(agent_id=agent_id, server_id=mcp_server_graph_id_for(server, agent), name=name, tools=tools)
                bindings.servers.setdefault((agent_type, name), {})[binding.server_id] = binding
        return bindings

    def agent_ref(self, agent_type: str) -> str | None:
        ids = self.agents.get(agent_type) or set()
        return next(iter(ids)) if len(ids) == 1 else None

    def server(self, agent_type: str, name: str | None) -> ServerBinding | None:
        matches = self.servers.get((agent_type, name or "")) or {}
        return next(iter(matches.values())) if len(matches) == 1 else None

    def configured(self, agent_type: str) -> list[ServerBinding]:
        return sorted(
            (binding for (kind, _), matches in self.servers.items() if kind == agent_type for binding in matches.values()),
            key=lambda binding: (binding.name, binding.server_id),
        )
