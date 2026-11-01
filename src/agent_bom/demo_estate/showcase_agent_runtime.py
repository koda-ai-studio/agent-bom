"""Every showcase agent with its platform, its kind and a fictional host it runs on.

The host ids and names are demo-only and match no real estate; without them the
hero path read "Agent kind not recorded · Host not recorded" because the agent
context derives the kind from ``agent_type`` and the host from ``hosted_on``.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agent_bom.demo_estate.showcase_constants import SHOWCASE_AGENT_RUNTIME, SHOWCASE_AGENTS
from agent_bom.demo_estate.showcase_ids import showcase_agent_id
from agent_bom.graph.types import EntityType, RelationshipType

SHOWCASE_RUNTIME_HOSTS: tuple[tuple[str, str, str], ...] = (
    ("cloud:dev-workstation", "dev-workstation-01 (macOS endpoint)", "endpoint"),
    ("cloud:agent-runtime", "agent-runtime (EKS deployment)", "eks_deployment"),
)


def seed_showcase_agents(node: Callable[..., str], edge: Callable[..., None], provider: str) -> None:
    for host_id, label, resource_type in SHOWCASE_RUNTIME_HOSTS:
        node(host_id, EntityType.CLOUD_RESOURCE, label, resource_type=resource_type, fictional=True)
    for aid, label in SHOWCASE_AGENTS.items():
        agent_type, host = SHOWCASE_AGENT_RUNTIME.get(aid, ("custom", "cloud:agent-runtime"))
        node(showcase_agent_id(aid), EntityType.AGENT, label, environment="production", agent_type=agent_type)
        edge(provider, showcase_agent_id(aid), RelationshipType.PLATFORM_FOR, traversable=False)
        edge(showcase_agent_id(aid), host, RelationshipType.HOSTED_ON, traversable=False)


__all__: list[Any] = ["SHOWCASE_RUNTIME_HOSTS", "seed_showcase_agents"]
