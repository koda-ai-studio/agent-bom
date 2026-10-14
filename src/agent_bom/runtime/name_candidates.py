"""Response-only name candidates; never inventory bindings or graph evidence."""

from __future__ import annotations

from collections.abc import Iterable


def normalized_name(value: object) -> str:
    return str(value or "").strip().lower()


def candidate_name_basis(
    *,
    agent: str = "",
    tool: str = "",
    server: str = "",
    package: str = "",
    agents: Iterable[str] = (),
    tools: Iterable[str] = (),
    servers: Iterable[str] = (),
    package_name: str = "",
) -> str | None:
    """Match explicit names, with package substrings only as a candidate fallback.

    A named agent constrains the match when the finding also names agents.
    Agent-only findings cannot match an arbitrary tool. Names, even exact ones,
    carry no scope, version or execution proof.
    """
    agent, tool, server, package = map(normalized_name, (agent, tool, server, package))
    agent_names = {normalized_name(name) for name in agents if normalized_name(name)}
    if agent and agent_names and agent not in agent_names:
        return None
    if tool and tool in {normalized_name(name) for name in tools}:
        return "tool"
    if server and server in {normalized_name(name) for name in servers}:
        return "server"
    package_name = normalized_name(package_name)
    if package_name:
        if package and package == package_name:
            return "package"
        if not package and tool and (package_name in tool or tool in package_name):
            return "package"
    if not (tool or server or package) and agent and agent in agent_names:
        return "agent"
    return None
