"""Registry existence check for ``agent-bom check``.

An explicit pin that matches no advisory may simply not exist (a typo, a
hallucinated version, or a malware package the registry removed). The MCP
``check`` tool confirms the version is published before calling it clean; this
module gives the CLI the same answer from the same lookups.
"""

from __future__ import annotations

import asyncio

from agent_bom.http_client import create_client
from agent_bom.mcp_tools import check_lookup
from agent_bom.mcp_tools.check_lookup import version_published

REGISTRY_ECOSYSTEMS = frozenset({"npm", "pypi"})


async def _lookup(name: str, version: str, ecosystem: str) -> tuple[bool, str | None]:
    async with create_client(timeout=15.0) as client:
        published = await version_published(name, version, ecosystem, client)
        reason = await check_lookup.unpublished_malware_reason(published, name, version, ecosystem, client)
    return published, reason


def unpublished_pin(name: str, version: str, ecosystems: list[str]) -> tuple[str, str | None] | None:
    """Return ``(ecosystem, malware_reason)`` when the pin is not published, else ``None``.

    Fails open: a registry or network error counts as published, so a transient
    failure never turns a genuine clean result into "unknown".
    """
    for ecosystem in ecosystems:
        if ecosystem not in REGISTRY_ECOSYSTEMS:
            continue
        published, reason = asyncio.run(_lookup(name, version, ecosystem))
        if not published:
            return ecosystem, reason
    return None
