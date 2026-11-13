"""Agent harness model: how a multi-agent harness maps onto the graph.

A harness is a tree of framework agents that take part in declared delegation
(``delegated_to``) or membership (``shares_server``) edges. Nothing here adds
node or edge types; each participant agent is placed by what its source
declares:

- **parent**: the enclosing construct discovery recorded (``parent_id``: a
  LangGraph node's graph, a subgraph's wrapping node, a prebuilt supervisor's
  members), else the ``Crew``/``GroupChat`` that lists it in ``agents=[...]``.
- **harness**: the root of that parent chain; ``harness_id`` is its node id.
- **layer**: depth below the root (the root is layer 0).
- **role**: ``harness`` for the root, ``subgraph`` for a compiled graph a node
  wraps, ``orchestrator`` for an agent that routes (conditionally, by handoff
  or by fan-out) to two or more distinct agents in its own or the next layer,
  else ``sub_agent``. A root that routes that way is the ``orchestrator``.
- **entry**: an agent a harness or subgraph starts at (``START``, entry point,
  swarm active agent).

Every edge keeps the ``declared`` provenance discovery gave it; its flow kind
(:func:`flow_kind`) is read from the recorded evidence only. Agents that take
part in no delegation are not placed, unless a placed agent declares them as
its parent: no harness or role is invented for them.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

HARNESS_MODEL_VERSION = "agent-harness.v1"
ROLES = ("harness", "orchestrator", "subgraph", "sub_agent")
FLOW_KINDS = ("entry", "sequential", "conditional", "handoff", "fan_out", "subgraph", "finish", "member", "peer")
_ROUTING_KINDS = frozenset({"conditional", "handoff", "fan_out"})
_STRUCTURAL_KINDS = frozenset({"entry", "finish", "subgraph", "fan_out"})
_MEMBERSHIP_PREFIXES = ("Crew(", "GroupChat(")
_HANDOFF_PREFIXES = ("Command(", "create_handoff_tool", "create_supervisor(")
# Nesting deeper than this is not modelled as a real harness layer; placements past it are flagged.
MAX_LAYER_DEPTH = 32


@dataclass(frozen=True)
class HarnessEdge:
    """One declared edge between two participant agents, as the graph records it."""

    source: str
    target: str
    relationship: str
    evidence: str = ""
    kind: str = ""
    branches: tuple[str, ...] = ()

    @property
    def flow(self) -> str:
        return flow_kind(self.relationship, self.evidence, self.kind, self.branches)

    @property
    def conditional(self) -> bool:
        return bool(self.branches) or "conditional" in self.evidence


@dataclass(frozen=True)
class HarnessPlacement:
    harness_id: str
    role: str
    layer: int
    entry: bool
    parent_id: str
    # True when the agent sits deeper than ``MAX_LAYER_DEPTH`` below its root.
    depth_exceeded: bool = False

    def attributes(self) -> dict[str, Any]:
        return {
            "harness_model": HARNESS_MODEL_VERSION,
            "harness_id": self.harness_id,
            "harness_role": self.role,
            "harness_layer": self.layer,
            "harness_entry": self.entry,
            "harness_parent_id": self.parent_id,
        }


def flow_kind(relationship: str, evidence: str, kind: str, branches: Iterable[str]) -> str:
    """The flow kind of one recorded edge, from its relationship, evidence and discovery kind."""
    if relationship == "shares_server":
        return "peer"
    if kind in _STRUCTURAL_KINDS:
        return kind
    if evidence.startswith(_HANDOFF_PREFIXES):
        return "handoff"
    if evidence.startswith(_MEMBERSHIP_PREFIXES):
        return "member"
    if tuple(branches) or "conditional" in evidence:
        return "conditional"
    return "sequential"


def derive_placements(declared_parents: dict[str, str], edges: Iterable[HarnessEdge]) -> dict[str, HarnessPlacement]:
    """Place every agent in ``declared_parents`` (participant id → declared parent id) in its harness."""
    participants = set(declared_parents)
    edge_list = [edge for edge in edges if edge.source in participants and edge.target in participants]
    parents = _effective_parents(declared_parents, edge_list)
    roots, layers = _roots_and_layers(participants, parents)
    entries = {edge.target for edge in edge_list if edge.flow == "entry"}
    wrapped = {edge.target for edge in edge_list if edge.flow == "subgraph"}
    routes = _routing_targets(edge_list, parents)
    placements: dict[str, HarnessPlacement] = {}
    for agent_id in sorted(participants):
        layer = layers[agent_id]
        if len(routes.get(agent_id, ())) >= 2:
            role = "orchestrator"
        elif layer == 0:
            role = "harness"
        elif agent_id in wrapped:
            role = "subgraph"
        else:
            role = "sub_agent"
        parent = parents.get(agent_id, "") if layer else ""
        placements[agent_id] = HarnessPlacement(
            roots[agent_id], role, layer, agent_id in entries, parent, depth_exceeded=layer > MAX_LAYER_DEPTH
        )
    return placements


def placements_from_framework_agents(framework_agents: Any) -> dict[str, HarnessPlacement]:
    """Placements for discovery output (``ai_inventory.framework_agents``)."""
    items = [item for item in framework_agents if isinstance(item, dict)] if isinstance(framework_agents, list) else []
    edges = [
        HarnessEdge(
            source=str(edge.get("source_id") or ""),
            target=str(edge.get("target_id") or ""),
            relationship=str(edge.get("relationship") or "delegated_to"),
            evidence=str(edge.get("evidence") or ""),
            kind=str(edge.get("kind") or ""),
            branches=(str(edge["branch"]),) if edge.get("branch") else (),
        )
        for item in items
        for edge in item.get("topology_edges") or []
        if isinstance(edge, dict)
    ]
    participants = {edge.source for edge in edges} | {edge.target for edge in edges}
    participants.discard("")
    declared = {str(item.get("stable_id") or ""): str(item.get("parent_id") or "") for item in items}
    declared.pop("", None)
    return derive_placements(with_declared_ancestors(participants, declared), edges)


def with_declared_ancestors(participants: Iterable[str], declared_parents: dict[str, str]) -> dict[str, str]:
    """Participants plus every declared ancestor that is itself a known agent, each mapped to its declared parent.

    A LangGraph builder with no ``START``/``END`` edge takes part in no edge,
    yet its nodes declare it as their parent; it still roots their harness.
    """
    out: dict[str, str] = {}
    pending = [agent_id for agent_id in participants if agent_id]
    while pending:
        agent_id = pending.pop()
        if agent_id in out:
            continue
        parent = declared_parents.get(agent_id, "")
        out[agent_id] = parent
        if parent and parent in declared_parents and parent not in out:
            pending.append(parent)
    return out


def _effective_parents(declared_parents: dict[str, str], edges: list[HarnessEdge]) -> dict[str, str]:
    parents = {agent_id: parent for agent_id, parent in declared_parents.items() if parent in declared_parents and parent != agent_id}
    for edge in sorted(edges, key=lambda item: (item.source, item.target)):
        if edge.flow == "member" and edge.target not in parents and edge.source != edge.target:
            parents[edge.target] = edge.source
    return parents


def _roots_and_layers(participants: set[str], parents: dict[str, str]) -> tuple[dict[str, str], dict[str, int]]:
    """Each agent's true root and depth; an agent whose parent chain loops stands alone at layer 0."""
    resolved: dict[str, tuple[str, int, bool]] = {}  # agent -> (root, depth, in or below a cycle)
    for start in participants:
        path: list[str] = []
        on_path: set[str] = set()
        current = start
        cyclic = False
        while current not in resolved:
            if current in on_path:
                cyclic = True
                break
            path.append(current)
            on_path.add(current)
            if current not in parents:
                resolved[current] = (current, 0, False)
                path.pop()
                break
            current = parents[current]
        for agent_id in reversed(path):
            above = resolved.get(parents.get(agent_id, ""))
            if cyclic or above is None or above[2]:
                resolved[agent_id] = (agent_id, 0, True)
            else:
                resolved[agent_id] = (above[0], above[1] + 1, False)
    roots = {agent_id: resolved[agent_id][0] for agent_id in participants}
    layers = {agent_id: resolved[agent_id][1] for agent_id in participants}
    return roots, layers


def _routing_targets(edges: list[HarnessEdge], parents: dict[str, str]) -> dict[str, set[str]]:
    """Distinct agents each agent routes to among its siblings and its own children."""
    targets: dict[str, set[str]] = {}
    for edge in edges:
        if edge.flow not in _ROUTING_KINDS or edge.source == edge.target:
            continue
        target_parent = parents.get(edge.target, "")
        if target_parent in {parents.get(edge.source, ""), edge.source}:
            targets.setdefault(edge.source, set()).add(edge.target)
    return targets


__all__ = [
    "FLOW_KINDS",
    "HARNESS_MODEL_VERSION",
    "ROLES",
    "HarnessEdge",
    "HarnessPlacement",
    "derive_placements",
    "flow_kind",
    "placements_from_framework_agents",
    "with_declared_ancestors",
]
