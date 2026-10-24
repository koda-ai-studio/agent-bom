"""Fleet trust scores share one 0-100 scale across producer, consumers and demo.

``compute_trust_score`` returns 0-100 and the UI renders the value as a
percentage, while ``/v1/fleet/stats`` and the overview identity snapshot count
``trust_score < 50`` as low trust. The demo seeder wrote 0.55-0.95, so every
one of its 48 agents was counted as low trust.
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def seeded_fleet(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "demo.db"))
    monkeypatch.setenv("AGENT_BOM_GRAPH_DB", str(tmp_path / "graph.db"))
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path))

    from agent_bom.api import stores as api_stores
    from agent_bom.api.stores import _get_fleet_store
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT, seed_showcase_fleet_and_runtime

    api_stores._store = None
    seed_showcase_fleet_and_runtime(tenant_id=SHOWCASE_TENANT)
    return _get_fleet_store().list_by_tenant(SHOWCASE_TENANT)


def test_low_trust_threshold_sits_on_the_scoring_scale() -> None:
    from agent_bom.fleet.trust_scoring import LOW_TRUST_THRESHOLD, TRUST_SCORE_MAX

    assert TRUST_SCORE_MAX == 100.0
    assert 0 < LOW_TRUST_THRESHOLD < TRUST_SCORE_MAX


def test_demo_trust_scores_use_the_0_to_100_scale(seeded_fleet) -> None:
    from agent_bom.fleet.trust_scoring import LOW_TRUST_THRESHOLD, TRUST_SCORE_MAX

    scores = [a.trust_score for a in seeded_fleet]
    assert len(scores) == 48
    assert all(1.0 < s <= TRUST_SCORE_MAX for s in scores), scores
    low = [a for a in seeded_fleet if a.trust_score < LOW_TRUST_THRESHOLD]
    assert 0 < len(low) < len(scores) // 2, [a.trust_score for a in low]


def test_quarantined_demo_agents_are_low_trust_and_approved_are_not(seeded_fleet) -> None:
    from agent_bom.api.fleet_store import FleetLifecycleState
    from agent_bom.fleet.trust_scoring import LOW_TRUST_THRESHOLD

    quarantined = [a for a in seeded_fleet if a.lifecycle_state == FleetLifecycleState.QUARANTINED]
    approved = [a for a in seeded_fleet if a.lifecycle_state == FleetLifecycleState.APPROVED]
    assert quarantined and approved
    assert all(a.trust_score < LOW_TRUST_THRESHOLD for a in quarantined)
    assert all(a.trust_score >= LOW_TRUST_THRESHOLD for a in approved)


def test_fleet_stats_and_overview_agree_on_low_trust(seeded_fleet) -> None:
    from types import SimpleNamespace
    from unittest.mock import patch

    from agent_bom.api.fleet_stats import fleet_stats_payload
    from agent_bom.api.overview_projection import _identity_snapshot
    from agent_bom.fleet.trust_scoring import LOW_TRUST_THRESHOLD

    expected = sum(1 for a in seeded_fleet if a.trust_score < LOW_TRUST_THRESHOLD)
    stats = fleet_stats_payload(seeded_fleet)
    assert stats["low_trust_count"] == expected
    assert stats["low_trust_count"] < stats["total"]

    request = SimpleNamespace(state=SimpleNamespace())
    with (
        patch("agent_bom.api.overview_projection._tenant_id", return_value=seeded_fleet[0].tenant_id),
    ):
        snapshot = _identity_snapshot(request)  # type: ignore[arg-type]
    assert snapshot["low_trust_agents"] == expected
