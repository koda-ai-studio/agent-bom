"""Credential nodes for the hand-built showcase servers.

The graph links each showcase server to every credential its scanned config
holds, so the exploit story and the agent's blast radius count one set. Each
credential carries the id the graph builder gives that server's env var.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agent_bom.demo_estate.showcase_constants import SHOWCASE_SERVERS
from agent_bom.demo_estate.showcase_ids import showcase_credential_id, showcase_ids, showcase_server_id
from agent_bom.graph.types import EntityType, RelationshipType


def showcase_server_credentials() -> list[tuple[str, str]]:
    """(server, env var) for every credential the demo scan records on a showcase server."""
    return sorted(key for key in showcase_ids().credentials if key[0] in SHOWCASE_SERVERS)


def seed_showcase_credentials(node: Callable[..., Any], edge: Callable[..., Any]) -> None:
    """Add a credential node and EXPOSES_CRED edge for each server's scanned env var."""
    for server, env_var in showcase_server_credentials():
        cid = showcase_credential_id(server, env_var)
        node(cid, EntityType.CREDENTIAL, env_var)
        edge(showcase_server_id(server), cid, RelationshipType.EXPOSES_CRED)
