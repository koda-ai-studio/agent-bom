"""Sample trends use normal bounded finding history and preserve uncertainty."""

import pytest

from agent_bom.api.trend_comparison import public_trend_point
from agent_bom.baseline import InMemoryTrendStore
from agent_bom.demo_estate import bootstrap
from agent_bom.demo_estate.showcase_history import history_stages


@pytest.mark.parametrize("outcome,status", [("complete", "comparable"), ("partial", "unavailable")])
def test_sample_history_preserves_finding_identity_and_collection_status(monkeypatch, outcome, status):
    store = InMemoryTrendStore()
    issues = {
        "critical": 1,
        "high": 2,
        "medium": 0,
        "low": 0,
        "unrated": 0,
        "total": 3,
        "kev": 0,
        "approximate": False,
        "basis": "issue_groups",
    }
    monkeypatch.setattr("agent_bom.api.stores._get_trend_store", lambda: store)
    monkeypatch.setattr("agent_bom.api.trend_recording.tenant_headline_posture", lambda _: {"grade": "C", "score": 65})
    monkeypatch.setattr("agent_bom.api.trend_recording.tenant_issue_counts", lambda _: issues)
    monkeypatch.setattr("agent_bom.api.stores._get_graph_store", lambda: pytest.fail("finding history must not read graph snapshots"))
    stored: list[str] = []
    monkeypatch.setattr(bootstrap, "_store_demo_scan_job", lambda report, **kwargs: stored.append(kwargs["job_id"]) or kwargs["job_id"])
    report = {
        "posture_scorecard": {"grade": "C", "score": 65},
        "scan_run": {"outcome": outcome, "scopes": []},
        "scan_sources": ["demo-estate"],
        "findings": [{"canonical_id": "finding:curated", "vulnerability_id": "CVE-2020-14343", "severity": "high"}],
    }
    earlier = len(history_stages()) - 1
    assert bootstrap._seed_showcase_history_stages(report, tenant_id="demo") == earlier
    assert stored == [stage.job_id for stage in history_stages()[:-1]]
    history = sorted(store.get_history(tenant_id="demo"), key=lambda point: point.timestamp)
    current, previous = history[-1], history[-2]
    public = public_trend_point(current, previous)
    assert public["comparison"]["status"] == status
    assert public["issues"] == issues
    if status == "comparable":
        assert public["comparison"]["still_open"] == 1
        assert public["comparison"]["new_findings"] == 0
        assert public["comparison"]["no_longer_detected"] == 0
    else:
        assert public["comparison"]["reason"] == "incomplete_collection"
    assert public["verified_remediations"] is None
    assert bootstrap._seed_showcase_history_stages(report, tenant_id="demo") == earlier
    assert len(store.get_history(tenant_id="demo")) == earlier
    assert store.get_history(tenant_id="other") == []
