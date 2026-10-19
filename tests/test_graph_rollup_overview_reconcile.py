"""The roll-up's estate issue total reconciles with the overview on one scan.

A scope card's "contained critical / high" and the overview headline are read
side by side. On the same data — one scan's findings and the graph built from
that scan — the roll-up's estate-wide issue histogram must equal the overview's
open-issue counts, and the root scope must not exceed them.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner
from starlette.testclient import TestClient

from agent_bom.cli import main
from agent_bom.graph.builder import build_unified_graph_from_report
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

TENANT = "rollup-overview-reconcile"
SCAN_ID = "rollup-overview-reconcile-scan"
_BANDS = ("critical", "high", "medium", "low")


def _demo_report(tmp_path: Path) -> dict:
    out = tmp_path / "report.json"
    CliRunner().invoke(main, ["scan", "--offline", "--demo", "-f", "json", "-q", "-o", str(out)])
    assert out.is_file()
    return json.loads(out.read_text())


@pytest.fixture
def reconciled_client(tmp_path: Path):
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.server import _get_store, app
    from agent_bom.api.stores import _graph_store as original_graph_store
    from agent_bom.api.stores import set_graph_store

    report = _demo_report(tmp_path)
    # API-run scans store their graph under the job id.
    report["scan_id"] = SCAN_ID
    now = datetime.now(timezone.utc).isoformat()
    job = ScanJob(
        job_id=SCAN_ID,
        tenant_id=TENANT,
        request=ScanRequest(),
        status=JobStatus.DONE,
        created_at=now,
        completed_at=now,
        result=report,
    )
    _get_store().put(job)
    graph = build_unified_graph_from_report(copy.deepcopy(report), scan_id=SCAN_ID, tenant_id=TENANT)
    store = SQLiteGraphStore(str(tmp_path / "graph.db"))
    store.save_graph(graph)
    set_graph_store(store)
    enable_trusted_proxy_env()
    try:
        yield TestClient(app), report
    finally:
        disable_trusted_proxy_env()
        set_graph_store(original_graph_store)  # type: ignore[arg-type]
        _get_store().delete(SCAN_ID, TENANT)


def test_root_rollup_issue_totals_equal_overview_counts(reconciled_client) -> None:
    client, report = reconciled_client
    headers = proxy_headers(tenant=TENANT)

    counts = client.get("/v1/posture/counts", headers=headers)
    overview = client.get("/v1/overview", headers=headers)
    rollup = client.get("/v1/graph/rollup", headers=headers, params={"scan_id": SCAN_ID})
    assert counts.status_code == overview.status_code == rollup.status_code == 200, (counts.text, overview.text, rollup.text)
    issues = counts.json()["issues"]
    headline = overview.json()["headline"]
    body = rollup.json()

    summary = body["summary"]
    assert summary["issue_count"] > 0, summary
    assert summary["severity_basis"] == "issue_groups"
    rolled = summary["issue_severity_counts"]
    assert {band: rolled[band] for band in _BANDS} == {band: issues[band] for band in _BANDS}, (rolled, issues)
    assert (rolled["critical"], rolled["high"]) == (headline["critical"], headline["high"])

    # No scope can claim more issues than the tenant holds.
    for entry in body["top_level"]:
        for band in _BANDS:
            assert entry["aggregate"]["severity_counts"][band] <= issues[band], entry["id"]
    assert report["findings"], "scenario must produce findings"
