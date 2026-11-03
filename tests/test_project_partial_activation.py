"""Partial project evidence must be usable without becoming a successful verdict."""

import json
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from tests.test_project_activation import project, scan  # noqa: F401


@pytest.mark.parametrize("report_content", [None, "{invalid json", "[]", '{"scan_run": "partial"}'])
def test_failed_scan_without_valid_partial_report_has_no_activation(project, tmp_path, scan, monkeypatch, report_content):  # noqa: F811
    persisted = []

    def run(args, **kwargs):
        if report_content is not None:
            Path(args[args.index("-o") + 1]).write_text(report_content)
        return subprocess.CompletedProcess(args, 1)

    monkeypatch.setattr("agent_bom.cli._quickstart.subprocess.run", run)
    monkeypatch.setattr("agent_bom.cli._quickstart._persist_completed_scan", lambda *args, **kwargs: persisted.append(kwargs))
    destination = tmp_path / "invalid-partial"
    result = CliRunner().invoke(main, ["quickstart", "--run", "--project", str(project), "--evidence-dir", str(destination)])
    assert result.exit_code == 1
    assert "no activation receipt was issued" in result.output
    assert not (destination / "activation.json").exists()
    assert not persisted
    if report_content is not None:
        assert (destination / "report.json").read_text() == report_content


@pytest.mark.parametrize(
    ("outcome", "code", "activated"), [("partial", 1, True), ("failed", 1, False), ("complete", 1, False), ("partial", 2, False)]
)
def test_partial_handoff_preserves_verdict(project, tmp_path, scan, monkeypatch, outcome, code, activated):  # noqa: F811
    payload = {"scan_id": "selected /scan?", "scan_run": {"outcome": outcome}, "coverage_warnings": ["Terraform coverage incomplete"]}
    persisted = []

    def run(args, **kwargs):
        Path(args[args.index("-o") + 1]).write_text(json.dumps(payload))
        return subprocess.CompletedProcess(args, code)

    monkeypatch.setattr("agent_bom.cli._quickstart.subprocess.run", run)
    monkeypatch.setattr("agent_bom.cli._quickstart._persist_completed_scan", lambda *args, **kwargs: persisted.append(kwargs))
    destination = tmp_path / "partial"
    result = CliRunner().invoke(main, ["quickstart", "--run", "--project", str(project), "--evidence-dir", str(destination)])
    assert result.exit_code == code if activated else result.exit_code != 0
    assert (destination / "activation.json").exists() is activated
    assert json.loads((destination / "report.json").read_text()) == payload
    if activated:
        receipt = json.loads((destination / "activation.json").read_text())
        assert receipt["scan_outcome"] == "partial"
        assert "Partial evidence activated" in result.output
        assert "Project activation complete" not in result.output
        assert "Findings:" in result.output and "coverage_warnings" in result.output
        assert persisted == [{"allow_partial": True}]
    else:
        assert not persisted


def test_partial_evidence_requires_exact_graph_and_preserves_database_outcome(tmp_path, monkeypatch):
    from datetime import datetime, timezone

    import click

    from agent_bom.api.store import SQLiteJobStore
    from agent_bom.cli._quickstart import _persist_completed_scan, _verify_persisted_graph
    from agent_bom.db.graph_store import open_graph_db, save_graph
    from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedGraph, UnifiedNode

    monkeypatch.setenv("AGENT_BOM_TENANT_ID", "partial-test")
    started = datetime.now(timezone.utc)
    graph = UnifiedGraph(scan_id="partial-scan", tenant_id="partial-test", created_at=started.isoformat())
    graph.add_node(UnifiedNode(id="agent:a", entity_type=EntityType.AGENT, label="agent"))
    graph.add_node(UnifiedNode(id="server:s", entity_type=EntityType.SERVER, label="server"))
    graph.add_edge(UnifiedEdge(source="agent:a", target="server:s", relationship=RelationshipType.USES))
    graph_db = tmp_path / "graph.db"
    with open_graph_db(graph_db) as connection:
        save_graph(connection, graph)
    report = tmp_path / "report.json"
    payload = {"scan_id": "partial-scan", "scan_run": {"outcome": "partial"}, "coverage_warnings": ["collector unavailable"]}
    report.write_text(json.dumps(payload))
    with pytest.raises(click.ClickException):
        _verify_persisted_graph(report_path=report, graph_db=graph_db, scan_started_at=started)
    verified = _verify_persisted_graph(report_path=report, graph_db=graph_db, scan_started_at=started, allow_partial=True)
    assert verified == {"scan_id": "partial-scan", "nodes": 2, "edges": 1}
    database = tmp_path / "control.db"
    _persist_completed_scan(report, database, "partial-scan", started, allow_partial=True)
    store = SQLiteJobStore(str(database))
    assert store.get("partial-scan", tenant_id="partial-test").result == payload
    assert store.get("partial-scan", tenant_id="other") is None
    with pytest.raises(click.ClickException):
        _persist_completed_scan(report, database, "wrong-scan", started, allow_partial=True)
