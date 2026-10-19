"""Api pipeline fleet helpers."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

from agent_bom.api.pipeline_events import (
    _now as _now,
)

# ─── Fleet sync ──────────────────────────────────────────────────────────────


def sync_scan_agents_to_fleet(agents: list, tenant_id: str, *, get_fleet_store: Callable[[], Any]) -> None:
    """Sync discovered agents from a scan into the fleet registry.

    Creates new FleetAgent entries for previously unseen agents and updates
    counts/trust scores for existing ones.  This ensures the fleet table is
    always populated after every scan — closing the gap where scan_jobs had
    data but fleet_agents stayed empty.
    """
    from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, discovered_fleet_identity, match_discovered_fleet_agent
    from agent_bom.fleet.trust_scoring import compute_trust_score

    store = get_fleet_store()
    now = _now()

    # Collect all agents for a single batch upsert (atomicity)
    to_upsert: list[FleetAgent] = []

    existing_agents = store.list_by_tenant(tenant_id)
    claimed_agent_ids: set[str] = set()

    for agent in agents:
        agent_type = agent.agent_type.value if hasattr(agent.agent_type, "value") else str(agent.agent_type)
        canonical_id = _optional_str(getattr(agent, "canonical_id", ""))
        existing = match_discovered_fleet_agent(
            existing_agents,
            **discovered_fleet_identity(agent),
            claimed_agent_ids=claimed_agent_ids,
        )
        server_count = len(agent.mcp_servers)
        pkg_count = sum(len(s.packages) for s in agent.mcp_servers)
        cred_count = sum(len(s.credential_names) for s in agent.mcp_servers)
        vuln_count = sum(s.total_vulnerabilities for s in agent.mcp_servers)

        score, factors = compute_trust_score(agent)

        if existing:
            claimed_agent_ids.add(existing.agent_id)
            existing.canonical_id = canonical_id
            existing.name = agent.name
            existing.agent_type = agent_type
            existing.config_path = agent.config_path or ""
            existing.source_id = _optional_str(getattr(agent, "source_id", "")) or existing.source_id
            existing.device_fingerprint = _optional_str(getattr(agent, "device_fingerprint", "")) or existing.device_fingerprint
            existing.server_count = server_count
            existing.package_count = pkg_count
            existing.credential_count = cred_count
            existing.vuln_count = vuln_count
            existing.trust_score = score
            existing.trust_factors = factors
            existing.updated_at = now
            to_upsert.append(existing)
        else:
            fleet_agent = FleetAgent(
                agent_id=str(uuid.uuid4()),
                canonical_id=canonical_id,
                device_fingerprint=_optional_str(getattr(agent, "device_fingerprint", "")),
                name=agent.name,
                agent_type=agent_type,
                config_path=agent.config_path or "",
                source_id=_optional_str(getattr(agent, "source_id", "")),
                lifecycle_state=FleetLifecycleState.DISCOVERED,
                trust_score=score,
                trust_factors=factors,
                server_count=server_count,
                package_count=pkg_count,
                credential_count=cred_count,
                vuln_count=vuln_count,
                tenant_id=tenant_id,
                last_discovery=now,
                created_at=now,
                updated_at=now,
            )
            to_upsert.append(fleet_agent)

    if to_upsert:
        store.batch_put(to_upsert)


def _optional_str(value: object) -> str:
    return value if isinstance(value, str) else ""
