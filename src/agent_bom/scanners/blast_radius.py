"""Compatibility boundary for inventory-only scanner blast-radius inputs."""

from __future__ import annotations

from agent_bom.models import Agent, BlastRadius


def expand_blast_radius_hops(
    blast_radii: list[BlastRadius],
    agents: list[Agent],
    max_depth: int = 1,
) -> None:
    """Preserve direct findings without inventing cross-agent delegation.

    These inputs describe configured inventory, not directed delegation or
    credential-use receipts. Even an identical remote endpoint does not prove
    that one client can reach another client or its credentials. The retired
    shared-name traversal therefore cannot qualify additional hops or risk.

    Keep the callable for existing scanner integrations. Historical fields
    already supplied by a caller remain intact; this function does not rewrite
    stored evidence. Typed graph queries own evidence-backed path analysis.
    """
    return None
