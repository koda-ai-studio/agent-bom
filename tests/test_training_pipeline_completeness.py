"""Unreadable optional training metadata must remain visible as coverage gaps."""

from pathlib import Path

import pytest

from agent_bom.parsers.training_pipeline import scan_training_pipelines


@pytest.mark.parametrize(
    ("primary", "content", "sibling"),
    [
        ("meta.yaml", "run_id: fixture\n", "params/rate"),
        ("meta.yaml", "run_id: fixture\n", "metrics/accuracy"),
        ("meta.yaml", "run_id: fixture\n", "tags/mlflow.source.git.commit"),
        ("MLmodel", "model_uuid: fixture\n", "requirements.txt"),
        ("MLmodel", "model_uuid: fixture\n", "conda.yaml"),
        ("wandb-metadata.json", '{"program": "train.py"}', "config.yaml"),
        ("wandb-metadata.json", '{"program": "train.py"}', "wandb-summary.json"),
    ],
)
def test_unreadable_sibling_is_reported_without_exposing_error(tmp_path, monkeypatch, primary, content, sibling):
    source = tmp_path / primary
    source.write_text(content)
    unreadable = tmp_path / sibling
    unreadable.parent.mkdir(parents=True, exist_ok=True)
    unreadable.write_text("fixture")
    original = Path.read_text

    def read(path, *args, **kwargs):
        if path == unreadable:
            raise PermissionError("private-fixture-connection-string")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    payload = scan_training_pipelines([source]).to_dict()
    assert payload["total_runs"] == 1
    assert payload["warnings"], "A partial training inventory must expose its coverage gap"
    assert payload["training_runs"][0]["warnings"]
    assert "private-fixture-connection-string" not in str(payload)


@pytest.mark.parametrize("value", ["timestamp not-a-number 0", "timestamp NaN 0", "timestamp inf 0", ""])
def test_invalid_metric_is_a_gap_not_a_valid_measurement(tmp_path, value):
    source = tmp_path / "meta.yaml"
    source.write_text("run_id: fixture\n")
    metrics = tmp_path / "metrics"
    metrics.mkdir()
    (metrics / "accuracy").write_text(value)
    payload = scan_training_pipelines([source]).to_dict()
    assert payload["warnings"]
    assert "accuracy" not in payload["training_runs"][0].get("metrics", {})


def test_absent_optional_siblings_do_not_report_read_failures(tmp_path):
    source = tmp_path / "meta.yaml"
    source.write_text("run_id: fixture\n")
    payload = scan_training_pipelines([source]).to_dict()
    assert payload["warnings"] == []
    assert "warnings" not in payload["training_runs"][0]
    assert payload["training_runs"][0]["security_flags"][0]["type"] == "MISSING_PROVENANCE"


def test_cli_preserves_training_coverage_warnings(tmp_path):
    from types import SimpleNamespace
    from unittest.mock import Mock

    from agent_bom.cli.agents.scan_pipeline.late import _scan_training_pipelines
    from agent_bom.models import AIBOMReport

    (tmp_path / "MLmodel").write_text("model_uuid: fixture\n")
    (tmp_path / "requirements.txt").write_bytes(b"\xff")
    opts = SimpleNamespace(skill_only=False, no_discover=True, training_dirs=(str(tmp_path),))
    state = SimpleNamespace(con=Mock(), report=AIBOMReport(), scan_sources=[])
    _scan_training_pipelines(opts, state)
    assert state.report.training_pipelines["warnings"]
    assert state.report.training_pipelines["training_runs"][0]["warnings"]
