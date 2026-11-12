"""Core data models for AI-BOM inventory."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Optional

from agent_bom.canonical_ids import (
    canonical_agent_id,
    previous_agent_canonical_ids,
    previous_agent_graph_ids,
)
from agent_bom.core.packages import normalize_package_name as normalize_package_name
from agent_bom.core.severity import Severity as Severity
from agent_bom.domain.inventory_types import AgentStatus, AgentType, _utc_now_iso
from agent_bom.domain.mcp_model import MCPServer, agent_is_repository_inventory
from agent_bom.package_utils import parse_debian_source_name as parse_debian_source_name  # noqa: F401

__all__ = [
    "Agent",
    "Severity",
    "agent_is_installed_unconfigured",
    "agent_record_counts_as_agent",
    "classify_agent_kind",
    "normalize_package_name",
    "parse_debian_source_name",
]


def agent_is_installed_unconfigured(status: object, has_servers: bool) -> bool:
    """The one judgement for a client found on this machine with nothing to inventory.

    Works for an :class:`AgentStatus` or its serialized string value, so live
    discovery and saved reports count agents identically.
    """
    return str(getattr(status, "value", status)) == AgentStatus.INSTALLED_NOT_CONFIGURED.value and not has_servers


def agent_record_counts_as_agent(record: Mapping[str, Any]) -> bool:
    """The public agent-count judgement for a serialized agent, as ``Agent.counts_as_agent``."""
    servers = [server for server in record.get("mcp_servers") or [] if isinstance(server, Mapping)]
    if agent_is_installed_unconfigured(record.get("status"), bool(servers)):
        return False
    return not agent_is_repository_inventory(
        record.get("source"), [(server.get("surface"), server.get("command")) for server in servers], record.get("metadata")
    )


@dataclass
class Agent:
    """An AI agent (client) that connects to MCP servers."""

    name: str
    agent_type: AgentType
    config_path: str
    mcp_servers: list[MCPServer] = field(default_factory=list)
    version: Optional[str] = None
    source: Optional[str] = None  # Inventory source (e.g. "snowflake", "aws", "local")
    status: AgentStatus = AgentStatus.CONFIGURED
    discovered_at: str = field(default_factory=_utc_now_iso)
    last_seen: Optional[str] = None
    parent_agent: Optional[str] = None  # Parent agent name (for spawn tree / delegation)
    metadata: dict[str, object] = field(default_factory=dict)  # Extra config data (permissions, hooks, etc.)
    automation_settings: list[Any] = field(default_factory=list)  # Risky automation settings (scheduled tasks, etc.)
    discovery_provenance: Optional[dict[str, Any]] = None  # Sanitized discovery provenance contract for this agent asset
    # Per-run discovery envelope (#2083): trust contract for THIS scan run
    # -- scan_mode, discovery_scope, permissions_used, redaction_status.
    # Stored as a dict so the model stays JSON-friendly without dragging
    # `discovery_envelope.DiscoveryEnvelope` into the import path; producers
    # populate via `DiscoveryEnvelope.to_dict()` and consumers can re-hydrate
    # via `DiscoveryEnvelope.from_dict()`.
    discovery_envelope: Optional[dict[str, Any]] = None
    # Strong external/device identities are distinct from ``source``, which is
    # only collector/provider provenance (for example ``aws-bedrock``).
    source_id: Optional[str] = None
    device_fingerprint: Optional[str] = None
    # Location that identifies the agent when it differs from the displayed
    # ``config_path``: an inventory agent with no location of its own shows the
    # inventory file it was read from but sets this to "", so moving or copying
    # that file does not change its id. ``None`` means ``config_path``.
    identity_config_path: Optional[str] = None

    def __post_init__(self) -> None:
        """Backfill lifecycle fields for legacy Agent construction paths."""
        if not self.discovered_at:
            self.discovered_at = _utc_now_iso()
        if not self.last_seen:
            self.last_seen = self.discovered_at

    @property
    def is_installed_unconfigured(self) -> bool:
        """A client found on this machine with no MCP configuration to inventory."""
        return agent_is_installed_unconfigured(self.status, bool(self.mcp_servers))

    @property
    def stable_id(self) -> str:
        """Deterministic ID for this agent.

        Device evidence wins over an explicit endpoint/source ID. Otherwise,
        identity is agent_type + name + install location. Collector provenance
        is deliberately excluded because one provider scan returns many agents.
        """
        return canonical_agent_id(
            self.agent_type.value,
            self.name,
            source_id=self.source_id or "",
            device_fingerprint=self.device_fingerprint or "",
            config_path=self.config_path if self.identity_config_path is None else self.identity_config_path,
        )

    @property
    def previous_graph_ids(self) -> list[str]:
        """Graph compatibility receipts computed before config-path redaction."""
        return previous_agent_graph_ids(self)

    @property
    def previous_canonical_ids(self) -> list[str]:
        """Explicit old-version receipts; consumers must reject ambiguous matches."""
        return previous_agent_canonical_ids(self)

    @property
    def canonical_id(self) -> str:
        """Canonical alias for stable_id used by report and graph consumers."""
        return self.stable_id

    @property
    def total_packages(self) -> int:
        return sum(len(s.packages) for s in self.mcp_servers)

    @property
    def counts_as_agent(self) -> bool:
        """An agent in the public count: not an idle client, and not a repository's scan inventory."""
        if self.is_installed_unconfigured:
            return False
        return not agent_is_repository_inventory(self.source, [(s.surface, s.command) for s in self.mcp_servers], self.metadata)

    @property
    def total_mcp_servers(self) -> int:
        return sum(1 for server in self.mcp_servers if server.counts_as_mcp_server)

    @property
    def total_vulnerabilities(self) -> int:
        return sum(s.total_vulnerabilities for s in self.mcp_servers)

    @property
    def affected_servers(self) -> list[MCPServer]:
        return [s for s in self.mcp_servers if s.vulnerable_packages]

    @property
    def servers_with_credentials(self) -> list[MCPServer]:
        return [s for s in self.mcp_servers if s.has_credentials]


def classify_agent_kind(agent: "Agent") -> str:
    """Display-only classification of a discovered agent record.

    Distinguishes what "agent" actually means to avoid overstating autonomy:

    - ``"client"`` — an AI **client/host** application discovered from config
      (Cursor, Claude Desktop, VS Code/Copilot, Codex CLI, …). Signalled by a
      specific ``agent_type`` (not ``CUSTOM``).
    - ``"background"`` — a **framework/service agent** *definition* discovered
      from code (CrewAI/LangChain/LangGraph, ``agent_type == CUSTOM`` with a
      ``source``/name shaped like ``"langchain:orders"``).
    - ``"synthetic"`` — an SBOM/image ingest wrapper (``agent_type == CUSTOM``
      with a ``sbom:``/``image:`` name), not a real agent at all.

    Layers vocabulary on top of the existing ``agent_type`` field; changes no
    stored data, enum value, route, or API key.
    """
    if agent.agent_type != AgentType.CUSTOM:
        return "client"
    if (agent.name or "").startswith(("sbom:", "image:")):
        return "synthetic"
    return "background"
