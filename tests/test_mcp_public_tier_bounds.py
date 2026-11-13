"""Bounds on the anonymous public tier: network buckets, a reserved budget, concurrency, sessions and proxy trust."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from starlette.datastructures import Headers
from starlette.testclient import TestClient

from agent_bom.mcp_server import create_mcp_server
from agent_bom.mcp_tools import public_tier
from agent_bom.mcp_tools.public_tier import PUBLIC_CALLER_PREFIX, anonymous_caller_key, check_public_rate_limit

_ACCEPT = {"Accept": "application/json, text/event-stream"}
_INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "bounds", "version": "1"}},
}
_ENVS = (
    public_tier.PUBLIC_READONLY_ENV,
    public_tier.FORWARDED_HOP_COUNT_ENV,
    public_tier.TRUSTED_PROXY_CIDRS_ENV,
    public_tier.PUBLIC_CALLER_RATE_LIMIT_ENV,
    public_tier.PUBLIC_TOTAL_RATE_LIMIT_ENV,
    public_tier.PUBLIC_CALLER_CONCURRENCY_ENV,
    "AGENT_BOM_MCP_BEARER_TOKEN",
)


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT", (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat())
    for name in _ENVS:
        monkeypatch.delenv(name, raising=False)
    public_tier.reset_public_rate_windows()
    yield
    public_tier.reset_public_rate_windows()


def _context(peer: str, forwarded: str | None = None) -> SimpleNamespace:
    raw = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    return SimpleNamespace(request=SimpleNamespace(client=SimpleNamespace(host=peer), headers=Headers(raw=raw)))


def _event(response):
    for line in response.text.splitlines():
        if line.startswith("data: "):
            return json.loads(line[6:])
    return response.json()


# ── Network buckets ────────────────────────────────────────────────────────


def test_ipv6_callers_are_bucketed_by_64_and_ipv4_by_address():
    same_64 = {anonymous_caller_key(_context(f"2001:db8:aa:bb:{n:x}::1")) for n in range(50)}
    assert same_64 == {f"{PUBLIC_CALLER_PREFIX}2001:db8:aa:bb::/64"}
    assert anonymous_caller_key(_context("2001:db8:aa:bc::1")) == f"{PUBLIC_CALLER_PREFIX}2001:db8:aa:bc::/64"
    assert anonymous_caller_key(_context("198.51.100.7")) == f"{PUBLIC_CALLER_PREFIX}198.51.100.7"
    assert anonymous_caller_key(_context("198.51.100.8")) == f"{PUBLIC_CALLER_PREFIX}198.51.100.8"
    assert anonymous_caller_key(_context("::ffff:198.51.100.7")) == f"{PUBLIC_CALLER_PREFIX}198.51.100.7"


def test_rotating_addresses_in_one_64_share_one_budget(monkeypatch):
    monkeypatch.setenv(public_tier.PUBLIC_CALLER_RATE_LIMIT_ENV, "3")
    results = [
        check_public_rate_limit(anonymous_caller_key(_context(f"2001:db8:1:2::{n:x}")), window_seconds=60, now=100.0) for n in range(1, 6)
    ]
    assert [result is None for result in results] == [True, True, True, False, False]
    assert check_public_rate_limit(anonymous_caller_key(_context("2001:db8:1:3::1")), window_seconds=60, now=100.0) is None


def test_a_first_seen_caller_is_admitted_after_heavy_callers_drain_the_shared_budget(monkeypatch):
    monkeypatch.setenv(public_tier.PUBLIC_TOTAL_RATE_LIMIT_ENV, "100")
    monkeypatch.setenv(public_tier.PUBLIC_CALLER_RATE_LIMIT_ENV, "30")
    admitted = 0
    # One heavy network: a /48 rotating through twenty of its /64s.
    for prefix in range(20):
        caller = anonymous_caller_key(_context(f"2001:db8:1:{prefix:x}::1"))
        admitted += sum(check_public_rate_limit(caller, window_seconds=60, now=100.0) is None for _ in range(30))
    assert admitted < 100, "heavy callers must not consume the reserved share"

    newcomers = [anonymous_caller_key(_context(f"203.0.113.{n}")) for n in range(1, 4)]
    assert all(check_public_rate_limit(caller, window_seconds=60, now=100.0) is None for caller in newcomers)
    # The reserve admits a newcomer's first calls only, never a full per-caller budget.
    repeat = [check_public_rate_limit(newcomers[0], window_seconds=60, now=100.0) for _ in range(30)]
    assert any(result is not None for result in repeat)


def test_the_reserved_share_is_itself_bounded(monkeypatch):
    monkeypatch.setenv(public_tier.PUBLIC_TOTAL_RATE_LIMIT_ENV, "100")
    admitted = sum(
        check_public_rate_limit(anonymous_caller_key(_context(f"2001:db8:{n:x}::1")), window_seconds=60, now=100.0) is None
        for n in range(500)
    )
    assert admitted == 100


# ── Concurrency per bucket ─────────────────────────────────────────────────


def _public_ctx(peer: str, method: str = "tools/call") -> SimpleNamespace:
    token = public_tier.AccessToken(token="x", client_id=public_tier.PUBLIC_CLIENT_ID, scopes=[public_tier.PUBLIC_SCOPE], expires_at=None)
    scope = {"user": AuthenticatedUser(token)}
    request = SimpleNamespace(client=SimpleNamespace(host=peer), headers=Headers(raw=[]), scope=scope)
    params = {"name": "check", "arguments": {"package": "flask", "ecosystem": "pypi"}}
    return SimpleNamespace(request=request, method=method, params=params)


def test_concurrent_calls_per_bucket_are_capped_and_another_bucket_is_admitted(monkeypatch):
    monkeypatch.setenv(public_tier.PUBLIC_CALLER_CONCURRENCY_ENV, "2")

    async def scenario():
        release = asyncio.Event()

        async def slow(_ctx):
            await release.wait()
            return {"content": [], "isError": False}

        held = [asyncio.create_task(public_tier.public_tier_guard(_public_ctx(f"2001:db8:5:5::{n}"), slow)) for n in (1, 2)]
        await asyncio.sleep(0)
        # Without a cap this third call would wait on the release like the first two.
        refused = await asyncio.wait_for(public_tier.public_tier_guard(_public_ctx("2001:db8:5:5::3"), slow), 2)
        other = asyncio.create_task(public_tier.public_tier_guard(_public_ctx("198.51.100.9"), slow))
        await asyncio.sleep(0)
        assert not other.done()
        release.set()
        results = await asyncio.gather(*held, other)
        after = await public_tier.public_tier_guard(_public_ctx("2001:db8:5:5::4"), slow)
        return refused, results, after

    refused, results, after = asyncio.run(scenario())
    assert refused["isError"] is True
    assert json.loads(refused["content"][0]["text"])["rate_limited"] is True
    assert all(result["isError"] is False for result in results)
    assert after["isError"] is False


# ── Sessions ───────────────────────────────────────────────────────────────


def test_anonymous_initialize_is_metered_per_bucket(monkeypatch):
    monkeypatch.setenv(public_tier.PUBLIC_READONLY_ENV, "1")
    monkeypatch.setenv(public_tier.PUBLIC_CALLER_RATE_LIMIT_ENV, "2")
    monkeypatch.setenv(public_tier.FORWARDED_HOP_COUNT_ENV, "1")
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token="full-access-credential", profile="scan")
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        heavy = {**_ACCEPT, "X-Forwarded-For": "2001:db8:9:9::1"}
        outcomes = []
        for n in range(3):
            heavy["X-Forwarded-For"] = f"2001:db8:9:9::{n + 1}"
            outcomes.append("error" in _event(client.post("/mcp", headers=heavy, json=_INIT)))
        assert outcomes == [False, False, True]
        other = _event(client.post("/mcp", headers={**_ACCEPT, "X-Forwarded-For": "198.51.100.40"}, json=_INIT))
        assert "result" in other


def test_public_profile_serves_streamable_http_without_sessions(monkeypatch):
    monkeypatch.setenv(public_tier.PUBLIC_READONLY_ENV, "1")
    server = create_mcp_server(host="0.0.0.0", port=8000, bearer_token=None, profile="public")
    app = server.streamable_http_app()
    with TestClient(app, base_url="http://localhost:8000") as client:
        init = client.post("/mcp", headers=_ACCEPT, json=_INIT)
        assert init.status_code == 200
        assert "mcp-session-id" not in init.headers
        with patch("agent_bom.mcp_tools.intel.intel_lookup_impl", new=AsyncMock(return_value=json.dumps({"found": False}))):
            call = client.post(
                "/mcp",
                headers={**_ACCEPT, "mcp-protocol-version": "2025-11-25"},
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": "intel_lookup", "arguments": {"advisory_id": "CVE-2024-0001"}},
                },
            )
        assert call.status_code == 200
        assert "result" in _event(call)


def test_mixed_public_tier_keeps_sessions_for_bearer_callers(monkeypatch):
    monkeypatch.setenv(public_tier.PUBLIC_READONLY_ENV, "1")
    server = create_mcp_server(host="127.0.0.1", port=8000, bearer_token="full-access-credential", profile="scan")
    with TestClient(server.streamable_http_app(), base_url="http://localhost:8000") as client:
        init = client.post("/mcp", headers={**_ACCEPT, "Authorization": "Bearer full-access-credential"}, json=_INIT)
        assert init.status_code == 200
        assert init.headers.get("mcp-session-id")


# ── Trusted proxy networks ─────────────────────────────────────────────────


def test_forwarded_header_is_trusted_only_from_a_configured_proxy_network(monkeypatch):
    monkeypatch.setenv(public_tier.FORWARDED_HOP_COUNT_ENV, "1")
    monkeypatch.setenv(public_tier.TRUSTED_PROXY_CIDRS_ENV, "10.0.0.0/8, fd00::/8")
    assert anonymous_caller_key(_context("10.1.2.3", "198.51.100.7")) == f"{PUBLIC_CALLER_PREFIX}198.51.100.7"
    assert anonymous_caller_key(_context("fd00::5", "198.51.100.7")) == f"{PUBLIC_CALLER_PREFIX}198.51.100.7"
    assert anonymous_caller_key(_context("203.0.113.50", "198.51.100.7")) == f"{PUBLIC_CALLER_PREFIX}203.0.113.50"


def test_an_unparseable_proxy_network_list_trusts_no_forwarded_header(monkeypatch):
    monkeypatch.setenv(public_tier.FORWARDED_HOP_COUNT_ENV, "1")
    monkeypatch.setenv(public_tier.TRUSTED_PROXY_CIDRS_ENV, "10.0.0.0/8,not-a-network")
    assert anonymous_caller_key(_context("10.1.2.3", "198.51.100.7")) == f"{PUBLIC_CALLER_PREFIX}10.1.2.3"


def test_hops_without_proxy_networks_keeps_the_old_behaviour_and_warns_at_start(monkeypatch, caplog):
    monkeypatch.setenv(public_tier.PUBLIC_READONLY_ENV, "1")
    monkeypatch.setenv(public_tier.FORWARDED_HOP_COUNT_ENV, "1")
    assert anonymous_caller_key(_context("203.0.113.50", "198.51.100.7")) == f"{PUBLIC_CALLER_PREFIX}198.51.100.7"
    with caplog.at_level(logging.WARNING, logger="agent_bom.mcp_tools.public_tier"):
        create_mcp_server(host="127.0.0.1", port=8000, bearer_token=None, profile="public")
    assert public_tier.TRUSTED_PROXY_CIDRS_ENV in caplog.text

    caplog.clear()
    monkeypatch.setenv(public_tier.TRUSTED_PROXY_CIDRS_ENV, "10.0.0.0/8")
    with caplog.at_level(logging.WARNING, logger="agent_bom.mcp_tools.public_tier"):
        create_mcp_server(host="127.0.0.1", port=8000, bearer_token=None, profile="public")
    assert public_tier.TRUSTED_PROXY_CIDRS_ENV not in caplog.text
