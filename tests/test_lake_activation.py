"""Installed-package activation and evidence-bearing import completion."""

import json
import shlex
import stat

import pytest
from click.testing import CliRunner

from agent_bom.cli._ingest_group import ingest_group
from agent_bom.cli._lake_activation import emit_lake_push_receipt
from tests.test_lake_evidence_ingest import fixture


def test_packaged_sample_generates_private_files_and_runnable_next_command(tmp_path):
    directory = tmp_path / "sample with spaces"
    runner = CliRunner()
    result = runner.invoke(ingest_group, ["lake-sample", "--directory", str(directory)])
    assert result.exit_code == 0, result.output
    assert "Synthetic sample" in result.output
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for name in ("findings.json", "mapping.json"):
        assert stat.S_IMODE((directory / name).stat().st_mode) == 0o600
    command = next(line.removeprefix("Next: ") for line in result.output.splitlines() if line.startswith("Next: "))
    args = shlex.split(command)
    assert args[:3] == ["agent-bom", "ingest", "lake"]
    imported = runner.invoke(ingest_group, args[2:])
    assert imported.exit_code == 0, imported.output
    report = json.loads((directory / "report.json").read_text())
    assert len(report["findings"]) >= 2
    assert all("sample" in row["title"].lower() for row in report["findings"])
    assert all(row["environment"] == "sample" for row in report["findings"])
    assert "Report saved:" in imported.output and str(directory / "report.json") in imported.output


@pytest.mark.parametrize("existing", ["directory", "symlink"])
def test_sample_refuses_existing_paths_without_overwriting(tmp_path, existing):
    target = tmp_path / "retained"
    target.mkdir()
    (target / "findings.json").write_text("retained evidence")
    destination = target
    if existing == "symlink":
        destination = tmp_path / "link"
        destination.symlink_to(target, target_is_directory=True)
    result = CliRunner().invoke(ingest_group, ["lake-sample", "--directory", str(destination)])
    assert result.exit_code != 0
    assert (target / "findings.json").read_text() == "retained evidence"
    assert not (target / "mapping.json").exists()


@pytest.mark.parametrize("destination", ["https://cp.example.com/team", "https://cp.example.com/team/v1/results/push"])
def test_push_completion_links_use_returned_scopes_and_deployment_prefix(tmp_path, monkeypatch, destination):
    rows, mapping = fixture()
    source, config, output = [tmp_path / name for name in ("rows.json", "mapping.json", "report.json")]
    source.write_text(json.dumps(rows))
    config.write_text(json.dumps(mapping))
    monkeypatch.setenv("AGENT_BOM_PUSH_API_KEY", "test-" + "placeholder")
    monkeypatch.setattr(
        "agent_bom.cli._lake_ingest.push_json",
        lambda *args, **kwargs: {
            "job_id": "job one",
            "graph_persistence": {"status": "persisted", "scan_id": "graph/one", "nodes": 3, "edges": 2},
        },
    )
    result = CliRunner().invoke(ingest_group, ["lake", str(source), "--mapping", str(config), "-o", str(output), "--push", destination])
    assert result.exit_code == 0, result.output
    assert "Graph persisted: 3 nodes, 2 relationships" in result.output
    assert "https://cp.example.com/team/findings?scan=job+one" in result.output
    assert "https://cp.example.com/team/security-graph?scan=graph%2Fone" in result.output
    assert "coverage remains unknown" in result.output


@pytest.mark.parametrize("receipt", [None, {}, {"status": "failed"}, {"status": "persisted", "nodes": 0, "edges": 0}])
def test_missing_or_empty_graph_receipt_is_explicit_and_does_not_claim_useful_graph(tmp_path, monkeypatch, receipt):
    rows, mapping = fixture()
    source, config, output = [tmp_path / name for name in ("rows.json", "mapping.json", "report.json")]
    source.write_text(json.dumps(rows))
    config.write_text(json.dumps(mapping))
    monkeypatch.setenv("AGENT_BOM_PUSH_API_KEY", "test-" + "placeholder")
    monkeypatch.setattr(
        "agent_bom.cli._lake_ingest.push_json", lambda *args, **kwargs: {"job_id": "stored-job", "graph_persistence": receipt}
    )
    result = CliRunner().invoke(
        ingest_group,
        ["lake", str(source), "--mapping", str(config), "-o", str(output), "--push", "https://cp.example.com"],
    )
    assert result.exit_code == 0, result.output
    assert "Graph evidence" in result.output
    assert "Investigation:" not in result.output
    assert "Findings: https://cp.example.com/findings?scan=stored-job" in result.output
    assert output.exists()


def test_receipt_links_drop_destination_credentials_and_private_query(capsys):
    emit_lake_push_receipt(
        {"job_id": "scan one", "graph_persistence": {"status": "persisted", "scan_id": "scan one", "nodes": 3, "edges": 2}},
        "https://operator:private-value@cp.example.com/team?token=private-query#private-fragment",
    )
    output = capsys.readouterr().out
    assert "private-" not in output and "operator:" not in output
    assert "https://cp.example.com/team/findings?scan=scan+one" in output


def test_public_push_receipt_omits_untrusted_details_and_invalid_counts():
    from agent_bom.api.observability_push_receipts import _public_graph_receipt

    graph = {"status": "persisted", "scan_id": "scan-one", "nodes": True, "edges": -1, "error": "private-backend-detail"}
    assert _public_graph_receipt({"graph_persistence": graph}) == {"status": "persisted", "scan_id": "scan-one"}
    assert _public_graph_receipt({"graph_persistence": {"status": "failed", "error": "private-detail"}}) == {"status": "unknown"}
