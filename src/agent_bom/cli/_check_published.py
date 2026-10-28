"""Registry existence check for ``agent-bom check``.

An explicit pin that matches no advisory may simply not exist (a typo, a
hallucinated version, or a malware package the registry removed). The MCP
``check`` tool confirms the version is published before calling it clean; this
module gives the CLI the same answer from the same lookups.
"""

from __future__ import annotations

import asyncio

from agent_bom import http_client, resolver
from agent_bom.http_client import create_client
from agent_bom.mcp_tools import check_lookup
from agent_bom.mcp_tools.check_lookup import version_published
from agent_bom.models import Package
from agent_bom.resolvers.latest_stable import CHECK_LATEST_DEADLINE, check_latest_budget

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


async def _resolve_latest(pkgs: list[Package]) -> tuple[Package | None, str | None]:
    async with http_client.create_client(timeout=CHECK_LATEST_DEADLINE) as client:
        with check_latest_budget():
            for pkg in pkgs:
                if await resolver.resolve_package_version(pkg, client):
                    return pkg, None
        for pkg in pkgs:
            reason = await check_lookup.resolution_malware_reason(False, pkg.name, pkg.ecosystem, client)
            if reason:
                return None, reason
    return None, None


def resolve_latest(pkgs: list[Package]) -> tuple[Package | None, str | None]:
    """Resolve the latest stable published version, as the MCP ``check`` tool does.

    Returns ``(package, None)`` for the first package that resolved, or
    ``(None, malware_reason)`` when none did; the reason is set only when the
    unresolvable name is a known-malicious package. The lookup is bounded by
    the registry-latest time budget, so a rate-limited registry yields an
    unresolved result instead of a long wait.
    """
    return asyncio.run(_resolve_latest(pkgs))
