"""Training auto-detection shares the scanner's bounded discovery scope."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from agent_bom.cli.agents.scan_pipeline.late import _scan_training_pipelines
from agent_bom.models import AIBOMReport


def _detect(project):
    opts = SimpleNamespace(skill_only=False, no_discover=False, training_dirs=(), project=str(project))
    state = SimpleNamespace(con=Mock(), report=AIBOMReport(), scan_sources=[])
    _scan_training_pipelines(opts, state)
    return opts, state


def test_auto_detection_never_materializes_recursive_globs(tmp_path, monkeypatch):
    (tmp_path / "MLmodel").write_text("model_uuid: fixture\n")

    def forbidden(*args, **kwargs):
        pytest.fail("Auto-detection must use bounded, pruned traversal, not recursive globs")

    monkeypatch.setattr(Path, "rglob", forbidden)
    opts, state = _detect(tmp_path)
    assert opts.training_dirs == (str(tmp_path),)
    assert state.report.training_pipelines["total_runs"] == 1


@pytest.mark.parametrize("directory", ["node_modules", ".venv", ".next"])
def test_ignored_training_artifacts_do_not_trigger_a_scan(tmp_path, directory):
    excluded = tmp_path / directory
    excluded.mkdir()
    (excluded / "MLmodel").write_text("model_uuid: excluded\n")
    opts, state = _detect(tmp_path)
    assert opts.training_dirs == ()
    assert "training_pipelines" not in state.scan_sources


def test_pipeline_yaml_triggers_the_same_discovery_as_explicit_scan(tmp_path):
    (tmp_path / "training-pipeline.yaml").write_text("pipelineInfo:\n  name: fixture\n")
    opts, state = _detect(tmp_path)
    assert opts.training_dirs == (str(tmp_path),)
    assert state.report.training_pipelines["total_runs"] == 1
