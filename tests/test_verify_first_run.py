"""First-use qualification must reject incomplete or unrelated evidence."""

from __future__ import annotations

import pytest

from scripts import verify_first_run
from scripts.verify_first_run import validate_graph, validate_report


def report(**updates):
    return {"scan_id": "sample-1", "scan_run": {"outcome": "complete"}, "agents": [{"name": "sample"}], **updates}


def test_first_run_rejects_partial_report_even_when_inventory_exists():
    with pytest.raises(ValueError, match="complete"):
        validate_report(report(scan_run={"outcome": "partial"}))


@pytest.mark.parametrize("field", ["scan_id", "agents"])
def test_first_run_requires_inventory_and_snapshot_identity(field):
    with pytest.raises(ValueError):
        validate_report(report(**{field: None}))


def test_first_run_does_not_require_cves_from_offline_inventory():
    assert validate_report(report()) == "sample-1"


@pytest.mark.parametrize(
    "graph",
    [
        {"scan_id": "other", "nodes": [{"id": "a"}], "edges": [{"source": "a", "target": "a"}]},
        {"scan_id": "sample-1", "nodes": [], "edges": []},
        {"scan_id": "sample-1", "nodes": [{"id": "a"}], "edges": []},
        {"scan_id": "sample-1", "nodes": [{"id": "a"}], "edges": [{"source": "a", "target": "missing"}]},
    ],
)
def test_first_run_rejects_wrong_empty_or_dangling_graph(graph):
    with pytest.raises(ValueError):
        validate_graph(graph, "sample-1")


def test_first_run_accepts_connected_snapshot():
    graph = {"scan_id": "sample-1", "nodes": [{"id": "a"}, {"id": "b"}], "edges": [{"source": "a", "target": "b"}]}
    assert validate_graph(graph, "sample-1") == {"nodes": 2, "edges": 1}


def test_failed_run_keeps_receipt_and_cannot_overwrite_evidence(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace

    monkeypatch.setattr(verify_first_run.importlib.metadata, "distribution", lambda _: SimpleNamespace(version="0.0.1"))
    output = tmp_path / "run"
    with pytest.raises(ValueError, match="version"):
        verify_first_run.run(output, "0.0.2")
    original = (output / "receipt.json").read_bytes()
    assert json.loads(original)["status"] == "failed"
    with pytest.raises(FileExistsError):
        verify_first_run.run(output, "0.0.2")
    assert (output / "receipt.json").read_bytes() == original


def _release_selection():
    from pathlib import Path

    import yaml

    workflow = yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/first-run.yml").read_text())
    return next(step for step in workflow["jobs"]["journey"]["steps"] if step.get("name", "").startswith("Select published release"))


@pytest.mark.parametrize("requested,tag,expected", [("", "", "0.108.4"), ("0.108.3", "", "0.108.3"), ("", "v0.108.2", "0.108.2")])
def test_release_selection_authenticates_only_the_fixed_github_lookup(monkeypatch, tmp_path, requested, tag, expected):
    import io
    import urllib.request

    step = _release_selection()
    monkeypatch.setenv("REQUESTED_VERSION", requested)
    monkeypatch.setenv("RELEASE_TAG", tag)
    monkeypatch.setenv("GH_TOKEN", "fixture-read-token")
    monkeypatch.setenv("GITHUB_ENV", str(tmp_path / "env"))
    calls = []

    def urlopen(request, *, timeout):
        assert isinstance(request, urllib.request.Request), "latest-release lookup must authenticate its GitHub request"
        assert request.full_url == "https://api.github.com/repos/koda-ai-studio/agent-bom/releases/latest"
        assert request.get_header("Authorization") == "Bearer fixture-read-token"
        assert timeout == 30
        calls.append(request)
        return io.BytesIO(b'{"tag_name":"v0.108.4"}')

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    script = step["run"].split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    # On the old combined step, stop before installation; selection itself is executable.
    script = script.split('root = pathlib.Path(os.environ["RUNNER_TEMP"])', 1)[0]
    namespace = {}
    exec(compile(script, "first-run-release-selection", "exec"), namespace)
    assert namespace["version"] == expected
    assert len(calls) == (0 if requested or tag else 1)


def test_first_run_setup_uses_selected_python_and_scopes_the_lookup_token():
    from pathlib import Path

    import yaml

    workflow = yaml.safe_load((Path(__file__).parents[1] / ".github/workflows/first-run.yml").read_text())
    steps = workflow["jobs"]["journey"]["steps"]
    selection = _release_selection()
    assert selection["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert selection["run"].startswith("uv run --no-project --python 3.13 python")
    install = next(step for step in steps if step.get("name") == "Install published package into a clean environment")
    assert install["run"].startswith("uv run --no-project --python 3.13 python")
    assert "GH_TOKEN" not in install.get("env", {})
    assert "GH_TOKEN" not in workflow["jobs"]["journey"].get("env", {})
