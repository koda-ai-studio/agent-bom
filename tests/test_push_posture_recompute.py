"""Pushed scans get a server-derived posture, record trends, and agree with /v1/posture."""

from __future__ import annotations

import copy
import json

import pytest
from starlette.testclient import TestClient

from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import _get_trend_store, set_trend_store
from agent_bom.baseline import InMemoryTrendStore


@pytest.fixture(scope="module")
def demo_report_text(tmp_path_factory) -> str:
    from click.testing import CliRunner

    from agent_bom.cli import main

    out = tmp_path_factory.mktemp("push-posture") / "demo.json"
    CliRunner().invoke(
        main,
        ["scan", "--offline", "--no-auto-update-db", "--quiet", "--demo", "--format", "json", "--output", str(out)],
        catch_exceptions=False,
    )
    return out.read_text(encoding="utf-8")


@pytest.fixture
def demo_report(demo_report_text) -> dict:
    return json.loads(demo_report_text)


@pytest.fixture
def isolated_stores():
    original_trends = _get_trend_store()
    trends = InMemoryTrendStore()
    set_trend_store(trends)
    set_job_store(InMemoryJobStore())
    try:
        yield trends
    finally:
        set_trend_store(original_trends)


def test_serialized_posture_matches_cli_scorecard(demo_report):
    from agent_bom.api.posture_recompute import compute_posture_scorecard_from_result

    report = demo_report
    expected = report["posture_scorecard"]
    recomputed = compute_posture_scorecard_from_result(report).to_dict()
    assert recomputed["grade"] == expected["grade"]
    assert recomputed["score"] == expected["score"]
    assert {k: v["score"] for k, v in recomputed["dimensions"].items()} == {k: v["score"] for k, v in expected["dimensions"].items()}


def test_push_recomputes_posture_and_ignores_forged_client_grade(isolated_stores, demo_report):
    client = TestClient(app)
    report = demo_report
    expected = copy.deepcopy(report["posture_scorecard"])
    forged = copy.deepcopy(report)
    forged["posture_scorecard"] = {"grade": "A", "score": 99.9, "summary": "forged", "dimensions": {}}
    forged["source_id"] = "laptop-a"

    response = client.post("/v1/results/push", json=forged)
    assert response.status_code == 201, response.text

    posture = client.get("/v1/posture").json()
    assert posture["grade"] != "N/A"
    assert posture.get("no_data") is False
    assert posture["scan_scorecard"]["score"] == expected["score"]
    assert posture["scan_scorecard"]["summary"] != "forged"

    overview = client.get("/v1/overview").json()["posture"]
    assert (posture["grade"], posture["score"]) == (overview["grade"], overview["score"])


def test_three_pushes_record_three_trend_points_matching_posture(isolated_stores, demo_report):
    client = TestClient(app)
    report = demo_report
    for index in range(3):
        payload = copy.deepcopy(report)
        payload["scan_id"] = f"push-trend-{index}"
        payload["generated_at"] = f"2026-10-1{index}T00:00:00+00:00"
        payload["source_id"] = "laptop-a"
        assert client.post("/v1/results/push", json=payload).status_code == 201

    trends = client.get("/v1/trends").json()
    assert trends["count"] == 3
    posture = client.get("/v1/posture").json()
    latest = trends["data_points"][0]
    assert latest["posture_grade"] == posture["grade"]
    assert latest["posture_score"] == posture["score"]
