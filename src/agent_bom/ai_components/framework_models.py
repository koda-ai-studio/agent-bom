"""Framework-agent models shared by the discovery passes.

``FrameworkAgent`` is a non-MCP framework-native agent (a LangGraph graph or
node, a CrewAI agent, an AutoGen agent, ...). ``FrameworkTopologyEdge`` is a
static relationship between two of them read from source, and
``FrameworkCapability`` a tool registered to one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import cached_property
from typing import Any

from agent_bom.finding import stable_id


@dataclass(frozen=True)
class FrameworkCapability:
    """A capability registered to a framework-native agent."""

    name: str
    source: str
    line_number: int
    confidence: str = "medium"
    dynamic: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source": self.source,
            "line_number": self.line_number,
            "confidence": self.confidence,
            "dynamic": self.dynamic,
        }


@dataclass(frozen=True)
class FrameworkTopologyEdge:
    """A static relationship observed between framework-native agents."""

    source_id: str
    source_name: str
    target_id: str
    target_name: str
    relationship: str
    file_path: str
    line_number: int
    framework: str
    evidence: str
    confidence: str = "medium"
    # Branch label of a conditional route ("" for unconditional edges) and how
    # the edge is known: "declared" means it is written in the source.
    branch: str = ""
    provenance: str = "declared"
    # Structural role: "entry" (graph to its first node), "finish" (a node
    # returning control to its graph), "subgraph" (a node wrapping a compiled
    # graph); "" for a plain delegation.
    kind: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_name": self.source_name,
            "target_id": self.target_id,
            "target_name": self.target_name,
            "relationship": self.relationship,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "framework": self.framework,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "branch": self.branch,
            "provenance": self.provenance,
            "kind": self.kind,
        }


@dataclass(frozen=True)
class FrameworkAgent:
    """A non-MCP framework agent with relationship evidence."""

    framework: str
    name: str
    file_path: str
    line_number: int
    capabilities: list[FrameworkCapability] = field(default_factory=list)
    model_refs: list[str] = field(default_factory=list)
    credential_refs: list[str] = field(default_factory=list)
    topology_edges: list[FrameworkTopologyEdge] = field(default_factory=list)
    dynamic_edges: bool = False
    confidence: str = "medium"
    # Nesting: a graph node's parent is its graph, a subgraph's parent is the
    # node that wraps it. Empty for top-level constructs.
    parent_id: str = ""
    # Routes the parser saw but could not resolve statically; each entry names
    # the construct, its line and why. Never silently dropped.
    unresolved_routes: list[dict[str, Any]] = field(default_factory=list)
    # The project the source belongs to (the scanned root's name, as the
    # project agent is named), so same-layout projects keep distinct agents.
    scope: str = ""

    @cached_property
    def stable_id(self) -> str:
        parts = ("framework_agent", self.framework, self.name, self.file_path, str(self.line_number))
        return stable_id(*parts, self.scope) if self.scope else stable_id(*parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "stable_id": self.stable_id,
            "kind": "framework_agent",
            "framework": self.framework,
            "name": self.name,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "confidence": self.confidence,
            "capabilities": [capability.to_dict() for capability in self.capabilities],
            "model_refs": list(self.model_refs),
            "credential_refs": list(self.credential_refs),
            "topology_edges": [edge.to_dict() for edge in self.topology_edges],
            "dynamic_edges": self.dynamic_edges,
            "parent_id": self.parent_id,
            "scope": self.scope,
            "unresolved_routes": [dict(route) for route in self.unresolved_routes],
            "provenance": {
                "source": "source-ast",
                "language": "python",
                "relationship_model": "non-mcp-framework",
            },
        }
