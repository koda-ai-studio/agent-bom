"""A ``--demo`` report stays labelled as demo data through push and persistence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from starlette.testclient import TestClient

from agent_bom.api import audit_log, stores
from agent_bom.api.audit_log import SQLiteAuditLog
from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.api.idempotency_store import SQLiteIdempotencyStore
from agent_bom.api.models import PushPayload
from agent_bom.api.push_evidence import normalize_pushed_report
from agent_bom.api.server import app
from agent_bom.api.store import SQLiteJobStore
from agent_bom.cli import main


def _push_body(**extra) -> dict:
    return {
        "source_id": "runner",
        "agents": [{"name": "agent", "type": "custom", "mcp_servers": [{"name": "srv", "command": "node", "packages": []}]}],
        **extra,
    }


def test_demo_scan_report_carries_demo_source(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    CliRunner().invoke(main, ["scan", "--demo", "--offline", "-f", "json", "-q", "-o", str(out)])
    report = json.loads(out.read_text())
    assert "demo" in report["scan_sources"]


def test_real_scan_report_has_no_demo_source(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    CliRunner().invoke(main, ["scan", "--offline", "--no-scan", "--no-discover", "-f", "json", "-q", "-p", str(tmp_path), "-o", str(out)])
    report = json.loads(out.read_text())
    assert not any("demo" in source for source in report["scan_sources"])


def test_push_keeps_demo_source() -> None:
    report = normalize_pushed_report(PushPayload(**_push_body(scan_sources=["agent_discovery", "demo"])), fallback_scan_id="r")
    assert "demo" in report["scan_sources"]


def test_push_labels_bundled_demo_advisory_report_from_older_clients() -> None:
    body = _push_body(scan_sources=["agent_discovery", "iac"], vuln_data_freshness={"mode": "bundled-demo", "sources": ["DEMO"]})
    report = normalize_pushed_report(PushPayload(**body), fallback_scan_id="r")
    assert "demo" in report["scan_sources"]
    assert "agent_discovery" in report["scan_sources"]


def test_push_does_not_label_real_reports() -> None:
    body = _push_body(scan_sources=["agent_discovery"], vuln_data_freshness={"mode": "local-db"})
    report = normalize_pushed_report(PushPayload(**body), fallback_scan_id="r")
    assert report["scan_sources"] == ["agent_discovery"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(stores, "_store", SQLiteJobStore(tmp_path / "jobs.db"))
    monkeypatch.setattr(stores, "_graph_store", SQLiteGraphStore(tmp_path / "graph.db"))
    monkeypatch.setattr(stores, "_idempotency_store", SQLiteIdempotencyStore(tmp_path / "idempotency.db"))
    audit = SQLiteAuditLog(str(tmp_path / "audit.db"))
    monkeypatch.setattr(audit_log, "get_audit_log", lambda: audit)
    return TestClient(app, raise_server_exceptions=False)


def test_pushed_demo_report_reaches_the_counts_the_ui_banner_reads(client) -> None:
    body = _push_body(scan_sources=["agent_discovery", "iac"], vuln_data_freshness={"mode": "bundled-demo"})
    assert client.post("/v1/results/push", json=body).status_code in (201, 202)
    counts = client.get("/v1/posture/counts")
    assert counts.status_code == 200, counts.text
    assert "demo" in counts.json()["scan_sources"]
