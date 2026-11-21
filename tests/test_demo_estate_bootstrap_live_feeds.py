"""Demo-estate live feeds: agent inventory fallback, gateway feed, KPIs, identity tile and runtime index.

These read in-memory stores the per-test global reset clears, so each test
needs a seed booted for the test itself.
"""

from __future__ import annotations

from collections import Counter

import pytest
from starlette.testclient import TestClient

from tests._demo_estate_fixtures import VIEWER


def test_demo_estate_agents_fall_back_to_demo_inventory(demo_estate_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """On a hosted server local discovery is empty; the demo estate falls back to
    the curated inventory so /v1/agents + /v1/agents/mesh are non-empty and
    correlated with the graph agents."""
    import agent_bom.discovery as discovery_mod

    monkeypatch.setattr(discovery_mod, "discover_all", lambda: [])
    from agent_bom.api.routes.discovery import _clear_agents_response_cache_for_tests

    _clear_agents_response_cache_for_tests()

    agents = demo_estate_client.get("/v1/agents", headers=VIEWER).json()
    names = {a.get("name") for a in agents.get("agents", [])}
    assert agents.get("count", 0) >= 5, agents
    assert {"cursor", "langchain-service", "support-copilot"} <= names, names

    mesh = demo_estate_client.get("/v1/agents/mesh", headers=VIEWER).json()
    assert len(mesh.get("nodes") or []) >= 5, mesh

    detail = demo_estate_client.get("/v1/agents/support-copilot", headers=VIEWER)
    assert detail.status_code == 200, detail.text
    assert detail.json()["agent"]["name"] == "support-copilot"

    lifecycle = demo_estate_client.get("/v1/agents/support-copilot/lifecycle", headers=VIEWER)
    assert lifecycle.status_code == 200, lifecycle.text


def test_demo_estate_agents_no_fallback_without_demo_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Env unset ⇒ live discovery only; the demo inventory is never injected."""
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    import agent_bom.discovery as discovery_mod
    from agent_bom.api.routes.discovery import _discover_agents_with_demo_fallback

    monkeypatch.setattr(discovery_mod, "discover_all", lambda: [])
    assert _discover_agents_with_demo_fallback() == []


# The gateway feed, KPIs and identity tile read in-memory stores that the
# per-test global reset clears, so they need a seed booted for the test itself.
def test_demo_estate_gateway_feed_shows_the_ai_firewall(demo_estate_client: TestClient) -> None:
    """The gateway live feed renders authorized / blocked / shadow / redacted
    tool-call events on the demo — the AI-firewall differentiator."""
    feed = demo_estate_client.get("/v1/gateway/feed")
    assert feed.status_code == 200, feed.text
    payload = feed.json()
    events = payload.get("events") or []
    assert len(events) >= 12, f"expected a dense gateway feed, got {len(events)}"

    by_action = Counter(e.get("action_type") for e in events)
    # A believable mix mirroring a real AI-firewall feed.
    assert by_action["tool_call_authorized"] >= 5, by_action
    assert by_action["tool_call_blocked"] >= 5, by_action
    assert by_action["data_filter_applied"] >= 2, by_action

    # Shadow / undeclared-agent blocks are labeled as such.
    shadow = [e for e in events if e.get("shadow")]
    assert len(shadow) >= 2, "expected shadow/undeclared-agent blocks in the feed"
    assert any("shadow" in (e.get("agent") or "").lower() for e in shadow)

    # Attribution uses the showcase graph's real agent names.
    agents = {e.get("agent") for e in events}
    assert {"Cursor", "Claude Desktop", "Data Pipeline"} & agents

    # Feed is time-ordered newest-first and redaction-safe (metadata only).
    ts_values = [e.get("ts") for e in events]
    assert ts_values == sorted(ts_values, reverse=True)
    for e in events:
        assert "arguments" not in e and "response" not in e


def test_demo_estate_gateway_feed_kpis_populated(demo_estate_client: TestClient) -> None:
    kpis = demo_estate_client.get("/v1/gateway/feed/kpis").json()
    assert kpis.get("calls_today", 0) >= 12, kpis
    assert kpis.get("blocked_today", 0) >= 5, kpis
    assert kpis.get("shadow_ai_blocked", 0) >= 2, kpis
    assert kpis.get("data_filters_applied", 0) >= 2, kpis
    assert kpis.get("uptime_seconds", 0) > 0, kpis


def test_demo_estate_overview_identity_tile_populated(demo_estate_client: TestClient) -> None:
    """The Overview NHI/Identity tile reads the live identity store, which the
    demo seed populates, so it is no longer 0/idle."""
    overview = demo_estate_client.get("/v1/overview").json()
    identity = overview["domains"]["identity"]
    assert identity["metric"] >= 5, identity
    assert identity["detail"]["managed_identities"] >= 5, identity
    assert identity["status"] != "idle", identity


# Reads the in-memory runtime index, which the autouse reset clears between tests.
def test_demo_estate_runtime_production_index_has_traffic(demo_estate_client: TestClient) -> None:
    idx = demo_estate_client.get("/v1/runtime/production-index", headers=VIEWER).json()
    assert idx.get("status") == "ok", idx
    traffic = idx.get("traffic") or {}
    assert traffic.get("total_tool_calls", 0) > 100, traffic
    assert traffic.get("blocked_tool_calls", 0) > 0, traffic
    assert traffic.get("uptime_seconds", 0) > 0, traffic
    trace = (idx.get("authorization_trace") or {}).get("recent") or []
    assert trace, "expected recent authorization-trace events"
