"""Time budget and coverage warnings for registry-latest version lookups.

A latest-version lookup only refines a scan that has its own time budget (an
MCP tool call has 30 s in all), so it never waits out a long ``Retry-After``
or a hung connection: it gives up after ``REGISTRY_LATEST_DEADLINE`` seconds,
leaves the version unresolved, and records one warning per registry so the
scan says which versions it could not resolve and why.
"""

from __future__ import annotations

import asyncio
import threading
from collections import defaultdict
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

import httpx

from agent_bom.http_client import REGISTRY_LOOKUP_MAX_WAIT, request_with_retry

REGISTRY_LATEST_DEADLINE = REGISTRY_LOOKUP_MAX_WAIT
RESOLVE_ALL_TIMEOUT = 8.0
_REGISTRY_HOSTS = {"npm": "registry.npmjs.org", "pypi": "pypi.org", "conda": "pypi.org", "go": "proxy.golang.org", "cargo": "crates.io"}
_LOCK = threading.Lock()
_DEGRADED: dict[str, str] = {}
_UNRESOLVED: dict[str, set[str]] = defaultdict(set)


def registry_host(ecosystem: str) -> str:
    return _REGISTRY_HOSTS.get(ecosystem.lower(), f"the {ecosystem} registry")


def record_registry_degraded(host: str, reason: str, package_name: str) -> None:
    with _LOCK:
        _DEGRADED.setdefault(host, reason)
        _UNRESOLVED[host].add(package_name)


def record_registry_timeout(ecosystem: str, package_name: str, seconds: float) -> None:
    record_registry_degraded(registry_host(ecosystem), f"did not answer within {seconds:.0f}s", package_name)


def reset_registry_degradation() -> None:
    with _LOCK:
        _DEGRADED.clear()
        _UNRESOLVED.clear()


def consume_registry_warnings() -> list[str]:
    """Return and clear one coverage warning per registry that rate-limited or timed out."""
    with _LOCK:
        warnings = [
            f"{len(_UNRESOLVED[host])} package version(s) unresolved: {host} {reason}; "
            "versions were left unresolved or taken from the bundled registry, so findings for them may be incomplete"
            for host, reason in sorted(_DEGRADED.items())
        ]
        _DEGRADED.clear()
        _UNRESOLVED.clear()
    return warnings


async def registry_latest_get(
    client: httpx.AsyncClient,
    url: str,
    package_name: str,
    request: Callable[..., Awaitable[httpx.Response | None]] = request_with_retry,
) -> httpx.Response | None:
    """GET a registry-latest document within ``REGISTRY_LATEST_DEADLINE`` seconds."""
    host = urlparse(url).hostname or url
    try:
        async with asyncio.timeout(REGISTRY_LATEST_DEADLINE):
            response = await request(client, "GET", url, max_wait=REGISTRY_LATEST_DEADLINE)
    except TimeoutError:
        record_registry_degraded(host, f"did not answer within {REGISTRY_LATEST_DEADLINE:.0f}s", package_name)
        return None
    if response is None:
        record_registry_degraded(host, "was unreachable or timed out", package_name)
    elif response.status_code == 429:
        record_registry_degraded(host, "rate-limited the lookup (HTTP 429)", package_name)
    elif response.status_code >= 500:
        record_registry_degraded(host, f"returned HTTP {response.status_code}", package_name)
    return response
