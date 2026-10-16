"""Scoped discovery identity and conservative fleet migration matching."""

from __future__ import annotations

from typing import Any

from agent_bom.api.fleet_models import FleetAgent


def discovered_fleet_identity(agent: Any) -> dict[str, Any]:
    kind = agent.agent_type
    return {
        "canonical_id": str(getattr(agent, "canonical_id", "") or ""),
        "agent_type": kind.value if hasattr(kind, "value") else str(kind),
        "name": agent.name,
        "config_path": agent.config_path or "",
        "previous_canonical_ids": list(getattr(agent, "previous_canonical_ids", []) or []),
        "source_id": str(getattr(agent, "source_id", "") or ""),
        "device_fingerprint": str(getattr(agent, "device_fingerprint", "") or ""),
    }


def fleet_agent_natural_key(agent_type: str, name: str, config_path: str) -> tuple[str, str, str]:
    """Compatibility key for upgrading scanner-owned fleet rows in place."""
    return (
        (agent_type or "").strip().lower(),
        (name or "").strip(),
        (config_path or "").strip(),
    )


def match_discovered_fleet_agent(
    existing_agents: list[FleetAgent],
    *,
    canonical_id: str,
    agent_type: str,
    name: str,
    config_path: str,
    previous_canonical_ids: list[str] | None = None,
    source_id: str = "",
    device_fingerprint: str = "",
    claimed_agent_ids: set[str] | None = None,
) -> FleetAgent | None:
    """Match a discovery row across canonical-ID schema upgrades.

    Compatibility never overrides conflicting source evidence. Device identity
    permits relocation; source identity also requires the same agent name.
    Unqualified discovery cannot inherit a scoped row's approval or lifecycle.
    Legacy aliases are accepted only within that compatible identity scope.
    """
    claimed = claimed_agent_ids if claimed_agent_ids is not None else set()
    natural_key = fleet_agent_natural_key(agent_type, name, config_path)

    def compatible(agent: FleetAgent) -> bool:
        if agent.agent_type.strip().lower() != natural_key[0]:
            return False
        if device_fingerprint or agent.device_fingerprint:
            return bool(device_fingerprint) and device_fingerprint == agent.device_fingerprint
        if source_id or agent.source_id:
            return bool(source_id) and source_id == agent.source_id and agent.name.strip() == natural_key[1]
        return fleet_agent_natural_key(agent.agent_type, agent.name, agent.config_path) == natural_key

    available = [agent for agent in existing_agents if agent.agent_id not in claimed and compatible(agent)]
    current = [agent for agent in available if canonical_id and agent.canonical_id == canonical_id]
    if current:
        return current[0] if len(current) == 1 else None
    # Two compatible persisted occurrences are ambiguous, even if a lossy old
    # alias happens to identify just one of them. Preserve both for resolution.
    return available[0] if len(available) == 1 else None
