"""Credential nodes for the hand-built showcase servers.

The graph links each showcase server to every credential its scanned config
holds, so the exploit story and the agent's blast radius count one set. The
named ids are kept stable because the hero chains point at them.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agent_bom.demo_estate.showcase_constants import SHOWCASE_SERVERS
from agent_bom.graph.types import EntityType, RelationshipType

_NAMED_CREDENTIALS: dict[str, tuple[str, str]] = {
    "cred:aws-secret": ("AWS_SECRET_ACCESS_KEY", "shell-runner-server"),
    "cred:openai-key": ("OPENAI_API_KEY", "llm-orchestrator-server"),
    "cred:db-url": ("DATABASE_URL", "vector-db-server"),
    "cred:jwt-secret": ("JWT_SECRET", "helpdesk-server"),
    "cred:snowflake-pw": ("SNOWFLAKE_PASSWORD", "warehouse-server"),
    "cred:gcs-key": ("GCS_SERVICE_ACCOUNT_KEY", "etl-server"),
    "cred:github-token": ("GITHUB_TOKEN", "github-server"),
    "cred:slack-token": ("SLACK_BOT_TOKEN", "team-chat-server"),
}


def showcase_server_credentials() -> list[tuple[str, str]]:
    """(server, env var) for every credential the demo scan records on a showcase server."""
    from agent_bom.demo import DEMO_INVENTORY

    return sorted(
        (server["name"], env_var)
        for agent in DEMO_INVENTORY["agents"]
        for server in agent["mcp_servers"]
        if server["name"] in SHOWCASE_SERVERS
        for env_var in (server.get("env") or {})
    )


def seed_showcase_credentials(node: Callable[..., Any], edge: Callable[..., Any]) -> None:
    """Add a credential node and EXPOSES_CRED edge for each server's scanned env var."""
    for cid, (label, sid) in _NAMED_CREDENTIALS.items():
        node(cid, EntityType.CREDENTIAL, label)
        edge(f"server:{sid}", cid, RelationshipType.EXPOSES_CRED)
    named = set(_NAMED_CREDENTIALS.values())
    for sid, env_var in showcase_server_credentials():
        if (env_var, sid) not in named:
            cid = f"cred:{sid}:{env_var.lower().replace('_', '-')}"
            node(cid, EntityType.CREDENTIAL, env_var)
            edge(f"server:{sid}", cid, RelationshipType.EXPOSES_CRED)
