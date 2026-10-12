"""Immutable path authority state."""

from dataclasses import dataclass

from agent_bom.graph.consequence.contracts import SessionBinding


@dataclass(frozen=True)
class PathState:
    nodes: tuple[str, ...]
    edges: tuple[str, ...] = ()
    sessions: tuple[SessionBinding, ...] = ()
