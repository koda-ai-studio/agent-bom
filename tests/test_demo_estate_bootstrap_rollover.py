"""Demo-estate daily evidence: idempotent gateway and catalog seeds and the UTC day rollover."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient


def test_demo_estate_gateway_feed_is_idempotent(demo_estate_client: TestClient) -> None:
    first = len(demo_estate_client.get("/v1/gateway/feed").json().get("events") or [])
    from agent_bom.demo_estate.showcase_gateway import seed_showcase_gateway_events

    again = seed_showcase_gateway_events()
    assert again.get("seeded") is False and again.get("reason") == "already_present"
    second = len(demo_estate_client.get("/v1/gateway/feed").json().get("events") or [])
    assert second == first


def test_demo_estate_catalog_is_idempotent(demo_estate_client: TestClient) -> None:
    from agent_bom.demo_estate.showcase_catalog import seed_showcase_catalog_if_empty

    again = seed_showcase_catalog_if_empty()
    assert again.get("seeded") is False and again.get("reason") == "catalog_present"


# ── UTC day rollover ────────────────────────────────────────────────────────
#
# CI caught this the hard way: a run whose demo bootstrap landed at 23:59 and
# whose request landed at 00:00:04 read ``calls_today: 0`` and failed
# ``assert 0 >= 12``. The same clock makes the hosted demo claim no traffic on
# an estate the tile beside it describes as busy, and left the seeded LLM spend
# permanently invisible — its guard treated "any records exist" as "already
# seeded", so it never re-seeded at all.
#
# Running these once proves nothing, so nothing below reads the wall clock for
# the behaviour under test: evidence is seeded against an explicit yesterday and
# is read back through the real ``[UTC midnight, now]`` window.


def _seed_only_yesterdays_evidence() -> datetime:
    """Reset the day-scoped stores and leave them holding yesterday's demo data.

    Covers both halves of the rollover: the gateway feed (which the maintenance
    loop reseeds, so it was merely late) and the seeded LLM spend (which was
    guarded on "any records exist" and so never came back at all).
    """
    from agent_bom.api import cost_store
    from agent_bom.api import stores as api_stores
    from agent_bom.api.gateway_activity_store import get_gateway_activity_store
    from agent_bom.api.routes.proxy import _reset_proxy_runtime_for_tests
    from agent_bom.demo_estate.bootstrap import reset_daily_evidence_day
    from agent_bom.demo_estate.showcase_gateway import seed_showcase_gateway_events
    from agent_bom.demo_estate.showcase_governance import _seed_cost_records

    _reset_proxy_runtime_for_tests()
    api_stores._get_firewall_decision_store().reset()
    reset_gateway_activity = getattr(get_gateway_activity_store(), "reset", None)
    if callable(reset_gateway_activity):
        reset_gateway_activity()
    # The client uses SQLite. Clearing the singleton would reopen its seeded
    # database, including today's records, instead of establishing yesterday's
    # pre-state. Keep this simulated rollover isolated from persisted boot data.
    cost_store.set_cost_store(cost_store.InMemoryCostStore())
    reset_daily_evidence_day()

    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    seeded = seed_showcase_gateway_events(now=yesterday)
    assert seeded.get("seeded") is True, seeded
    assert _seed_cost_records(tenant_id="default", now=yesterday) > 0
    records = cost_store.get_cost_store().list_records("default", limit=5000)
    assert max(record.observed_at[:10] for record in records) == yesterday.date().isoformat()
    return yesterday


def test_yesterdays_gateway_evidence_is_outside_todays_kpi_window() -> None:
    """The mechanism itself: day-scoped evidence goes dark when the day turns.

    Pinned separately from the fix so a future change that stops scoping the
    seed to a single UTC day fails here loudly rather than quietly making the
    rollover test below tautological.
    """
    from agent_bom.demo_estate.showcase_gateway import _event_time

    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    todays_window_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    for minutes_ago in (0, 1, 20):
        assert _event_time(yesterday, minutes_ago) < todays_window_start


def test_yesterday_fixture_replaces_persisted_cost_evidence(demo_estate_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Resetting a singleton must not reopen the boot day's SQLite evidence."""
    from agent_bom.api import cost_store
    from agent_bom.demo_estate.showcase_governance import _seed_cost_records

    class Midnight(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 9, 15, 0, 0, 2, tzinfo=timezone.utc)

    monkeypatch.setattr(f"{__name__}.datetime", Midnight)
    yesterday = Midnight.now(timezone.utc) - timedelta(days=1)
    _seed_cost_records(tenant_id="default", now=yesterday)

    _seed_only_yesterdays_evidence()

    records = cost_store.get_cost_store().list_records("default", limit=5000)
    assert records
    assert max(record.observed_at[:10] for record in records) == yesterday.date().isoformat()


def test_gateway_kpis_recover_after_a_utc_day_rollover(demo_estate_client: TestClient) -> None:
    """A request landing on the far side of midnight still reports the estate."""
    _seed_only_yesterdays_evidence()

    # Pre-state: the stores hold demo evidence, but none of it is inside the
    # window the KPI header reports on. This is precisely what CI saw.
    from agent_bom.api.routes.proxy import _load_proxy_alerts

    today = datetime.now(timezone.utc).date().isoformat()
    assert not [alert for alert in _load_proxy_alerts("default") if str(alert.get("ts") or "").startswith(today)]

    kpis = demo_estate_client.get("/v1/gateway/feed/kpis").json()

    assert kpis.get("calls_today", 0) >= 12, kpis
    assert kpis.get("blocked_today", 0) >= 5, kpis
    assert kpis.get("shadow_ai_blocked", 0) >= 2, kpis
    assert kpis.get("data_filters_applied", 0) >= 2, kpis
    # The spend half of the same rollover: this one never self-healed.
    assert kpis.get("llm_calls", 0) > 0, kpis


def test_daily_refresh_does_not_reseed_twice_in_one_day(demo_estate_client: TestClient) -> None:
    """The per-request hook must cost one comparison, not a reseed each time."""
    from agent_bom.demo_estate.bootstrap import refresh_demo_daily_evidence

    _seed_only_yesterdays_evidence()
    demo_estate_client.get("/v1/gateway/feed/kpis")

    assert refresh_demo_daily_evidence() == {
        "refreshed": False,
        "reason": "current",
        "day": datetime.now(timezone.utc).date().isoformat(),
    }


def test_daily_refresh_is_a_no_op_outside_demo_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every deployment pays for this hook; only the demo may act on it."""
    from agent_bom.demo_estate.bootstrap import refresh_demo_daily_evidence, reset_daily_evidence_day

    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    reset_daily_evidence_day()

    assert refresh_demo_daily_evidence() == {"refreshed": False, "reason": "disabled"}
