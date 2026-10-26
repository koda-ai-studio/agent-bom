"""Registry-latest lookups stay inside an MCP tool's time budget.

When registry.npmjs.org rate-limits with a long ``Retry-After`` (224 s was
observed), waiting it out exceeds the 30 s MCP tool budget and the whole tool
call times out. Version lookups must give up within a few seconds, keep the
package as unresolved (or bundled-registry fallback) and say so in a warning.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from agent_bom import http_client, resolver
from agent_bom.models import Package
from agent_bom.resolvers.registry_budget import consume_registry_warnings

TOOL_BUDGET_SECONDS = 30.0
WITHIN_BUDGET_SECONDS = 6.0


def _rate_limited_transport(retry_after: str, calls: list[str]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(429, headers={"Retry-After": retry_after}, json={"error": "rate limited"})

    return httpx.MockTransport(handler)


@pytest.fixture(autouse=True)
def _fresh_registry_state(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("agent_bom.security.validate_url", lambda *_a, **_k: None)
    resolver.reset_performance_stats()
    resolver._NPM_LATEST_CACHE.clear()
    resolver._PYPI_INFO_CACHE.clear()
    http_client.reset_rate_limit_breaker()
    yield
    resolver.reset_performance_stats()
    resolver._NPM_LATEST_CACHE.clear()
    resolver._PYPI_INFO_CACHE.clear()
    http_client.reset_rate_limit_breaker()


def _patch_clients(monkeypatch: pytest.MonkeyPatch, transport: httpx.MockTransport) -> None:
    def _client(*_args: Any, **_kwargs: Any) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=transport)

    monkeypatch.setattr(resolver, "create_client", _client)
    monkeypatch.setattr(http_client, "create_client", _client)


@pytest.mark.parametrize("retry_after", ["30", "224"])
def test_request_with_retry_never_sleeps_past_max_wait(retry_after: str) -> None:
    calls: list[str] = []
    slept: list[float] = []

    async def _record_sleep(seconds: float) -> None:
        slept.append(seconds)

    async def _run() -> httpx.Response | None:
        async with httpx.AsyncClient(transport=_rate_limited_transport(retry_after, calls)) as client:
            with patch("agent_bom.http_client.asyncio.sleep", new=_record_sleep):
                return await http_client.request_with_retry(client, "GET", "https://registry.npmjs.org/x/latest", max_wait=2.5)

    response = asyncio.run(_run())
    assert response is not None and response.status_code == 429
    assert sum(slept) <= 2.5
    assert all(s <= 2.5 for s in slept)


@pytest.mark.parametrize("retry_after", ["30", "224"])
def test_resolver_latest_lookup_returns_within_budget_on_429(monkeypatch: pytest.MonkeyPatch, retry_after: str) -> None:
    calls: list[str] = []
    _patch_clients(monkeypatch, _rate_limited_transport(retry_after, calls))
    pkg = Package(name="some-unlisted-mcp-server", version="latest", ecosystem="npm")

    started = time.monotonic()
    asyncio.run(resolver.resolve_all_versions([pkg], quiet=True, enrich_license_metadata=False))
    elapsed = time.monotonic() - started

    assert calls, "the registry should have been asked once"
    assert elapsed < WITHIN_BUDGET_SECONDS, f"version lookup took {elapsed:.1f}s against a {TOOL_BUDGET_SECONDS:.0f}s budget"
    assert pkg.version == "latest"
    warnings = consume_registry_warnings()
    assert any("registry.npmjs.org" in w and "unresolved" in w for w in warnings), warnings


def test_resolver_latest_lookup_bounded_when_registry_hangs(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _hang(request: httpx.Request) -> httpx.Response:
        await asyncio.sleep(60)
        return httpx.Response(200, json={"version": "9.9.9"})

    _patch_clients(monkeypatch, httpx.MockTransport(_hang))
    pkg = Package(name="slow-pypi-pkg", version="latest", ecosystem="pypi")

    started = time.monotonic()
    asyncio.run(resolver.resolve_all_versions([pkg], quiet=True, enrich_license_metadata=False))
    elapsed = time.monotonic() - started

    assert elapsed < WITHIN_BUDGET_SECONDS
    assert pkg.version == "latest"
    assert any("pypi.org" in w for w in consume_registry_warnings())


@pytest.mark.parametrize("retry_after", ["30", "224"])
def test_mcp_scan_tool_returns_within_budget_with_coverage_warning(monkeypatch: pytest.MonkeyPatch, retry_after: str) -> None:
    pytest.importorskip("mcp")
    from mcp import Client

    from agent_bom.mcp_server import create_mcp_server

    calls: list[str] = []
    _patch_clients(monkeypatch, _rate_limited_transport(retry_after, calls))
    monkeypatch.delenv("AGENT_BOM_OFFLINE", raising=False)
    monkeypatch.delenv("AGENT_BOM_VULN_DB_OFFLINE", raising=False)

    async def _run() -> str:
        server = create_mcp_server(profile="full")
        async with Client(server) as client:
            result = await client.call_tool("scan", {"package": "some-unlisted-mcp-server", "ecosystem": "npm"})
            return result.content[0].text  # type: ignore[union-attr]

    started = time.monotonic()
    with (
        patch("agent_bom.scanners.package_scan.query_osv_batch", new=AsyncMock(return_value={})),
        patch("agent_bom.graph.scan_findings.surface_graph_derived_findings", return_value=None),
    ):
        text = asyncio.run(_run())
    elapsed = time.monotonic() - started

    assert elapsed < WITHIN_BUDGET_SECONDS, f"MCP scan took {elapsed:.1f}s against a {TOOL_BUDGET_SECONDS:.0f}s budget"
    assert any("registry.npmjs.org" in url for url in calls)
    payload = json.loads(text)
    warnings = json.dumps(payload.get("warnings", [])) + json.dumps(payload.get("coverage_warnings", []))
    assert "registry.npmjs.org" in warnings, payload.keys()
