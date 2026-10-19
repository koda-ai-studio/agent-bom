"""Sample trends use normal bounded finding history and preserve uncertainty."""

import pytest

from agent_bom.api.trend_comparison import public_trend_point
from agent_bom.baseline import InMemoryTrendStore
from agent_bom.demo_estate.bootstrap import _seed_showcase_posture_trends


@pytest.mark.parametrize("outcome,status", [("complete", "comparable"), ("partial", "unavailable")])
def test_sample_history_preserves_finding_identity_and_collection_status(monkeypatch, outcome, status):
    store = InMemoryTrendStore()
    monkeypatch.setattr("agent_bom.api.stores._get_trend_store", lambda: store)
    monkeypatch.setattr("agent_bom.api.exec_posture.tenant_headline_posture", lambda _: {"grade": "C", "score": 65})
    monkeypatch.setattr("agent_bom.api.stores._get_graph_store", lambda: pytest.fail("finding history must not read graph snapshots"))
    report = {
        "posture_scorecard": {"grade": "C", "score": 65},
        "scan_run": {"outcome": outcome, "scopes": []},
        "scan_sources": ["demo-estate"],
        "findings": [{"canonical_id": "finding:curated", "severity": "high"}],
    }
    assert _seed_showcase_posture_trends(report, tenant_id="demo") == 2
    current, previous = store.get_history(tenant_id="demo")
    public = public_trend_point(current, previous)
    assert public["comparison"]["status"] == status
    if status == "comparable":
        assert public["comparison"]["still_open"] == 1
        assert public["comparison"]["new_findings"] == 0
        assert public["comparison"]["no_longer_detected"] == 0
    else:
        assert public["comparison"]["reason"] == "incomplete_collection"
    assert current.posture_score == previous.posture_score == 65
    assert public["verified_remediations"] is None
    assert _seed_showcase_posture_trends(report, tenant_id="demo") == 2
    assert len(store.get_history(tenant_id="demo")) == 2
    assert store.get_history(tenant_id="other") == []
