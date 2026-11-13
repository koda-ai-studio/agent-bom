"""Contract tests for the generated product-metrics snapshot."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, cast
from unittest import mock

import pytest

from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "product_metrics_snapshot.py"
METRICS_JSON = ROOT / "docs" / "PRODUCT_METRICS.json"
METRICS_MARKDOWN = ROOT / "docs" / "PRODUCT_METRICS.md"


def _load_metrics_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("product_metrics_snapshot", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_proxy_detector_metric_survives_session_extraction() -> None:
    snapshot = _load_metrics_script().build_snapshot()
    metric = next(item for item in snapshot["metrics"] if item["name"] == "Proxy inline detectors")

    assert metric["value"] == 7
    assert metric["source"] == "src/agent_bom/runtime/proxy_session.py"


def test_compliance_metric_uses_the_canonical_framework_count() -> None:
    module = _load_metrics_script()
    snapshot = module.build_snapshot()
    metrics = cast(list[dict[str, object]], snapshot["metrics"])
    compliance = next(metric for metric in metrics if metric["name"] == "Compliance surfaces")
    tag_mapped_count = len(TAG_MAPPED_FRAMEWORKS)

    assert tag_mapped_count == 15
    assert compliance["value"] == tag_mapped_count + 1
    assert compliance["notes"] == f"{tag_mapped_count} tag-mapped frameworks plus the OWASP AISVS benchmark surface."

    # The committed values are a release-time snapshot (the --release tests
    # below keep that strict); between releases only the shape must agree.
    checked_in = json.loads(METRICS_JSON.read_text(encoding="utf-8"))
    assert checked_in["version"] == snapshot["version"]
    assert [metric["name"] for metric in checked_in["metrics"]] == [metric["name"] for metric in metrics]
    assert "| Compliance surfaces |" in METRICS_MARKDOWN.read_text(encoding="utf-8")


def test_counts_survive_git_being_unusable():
    """CI's Alpine job runs where git refuses to operate on the checkout.

    `git -C <root> ls-files` exits 128 inside that container — git declines a
    repository whose ownership it considers dubious. `_tracked_files` used
    check=True, so the whole metrics snapshot raised CalledProcessError and the
    job failed for a reason unrelated to any metric.

    A pristine CI checkout has no untracked or ignored files, so a filesystem
    walk yields the same set. Fall back to it rather than failing the build.
    """
    snapshot = _load_metrics_script()

    real_run = subprocess.run

    def _git_refuses(cmd, *args, **kwargs):
        if cmd and cmd[0] == "git":
            raise subprocess.CalledProcessError(128, cmd, stderr="detected dubious ownership")
        return real_run(cmd, *args, **kwargs)

    with mock.patch.object(subprocess, "run", _git_refuses):
        workflows = snapshot._count_workflows()
        tests = snapshot._count_test_files()
        routes = snapshot._count_api_route_modules()

    assert workflows > 0, "workflow count must not silently collapse to zero"
    assert tests > 0
    assert routes > 0


def test_git_and_fallback_agree_on_a_clean_checkout():
    """The fallback must not quietly report a different number than git does."""
    snapshot = _load_metrics_script()

    via_git = snapshot._count_api_route_modules()

    real_run = subprocess.run

    def _git_refuses(cmd, *args, **kwargs):
        if cmd and cmd[0] == "git":
            raise subprocess.CalledProcessError(128, cmd, stderr="dubious ownership")
        return real_run(cmd, *args, **kwargs)

    with mock.patch.object(subprocess, "run", _git_refuses):
        via_glob = snapshot._count_api_route_modules()

    assert via_git == via_glob


def _run_write_against_copy(tmp_path: Path, committed: dict[str, object]) -> dict[str, object]:
    """Run ``--write`` against a private copy so the committed snapshot is never mutated.

    Rewriting ``docs/PRODUCT_METRICS.json`` in place raced every concurrent
    reader of that file under ``pytest -n --dist worksteal``.
    """
    json_out = tmp_path / "PRODUCT_METRICS.json"
    markdown_out = tmp_path / "PRODUCT_METRICS.md"
    json_out.write_text(json.dumps(committed, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), "--write", "--json-out", str(json_out), "--markdown-out", str(markdown_out)],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return cast(dict[str, object], json.loads(json_out.read_text(encoding="utf-8")))


def test_write_preserves_the_stamp_when_no_metric_changed(tmp_path: Path) -> None:
    """Re-running --write must not churn the committed artifact.

    The snapshot stamps ``generated_on``, but the drift gate compares only
    ``version`` and ``metrics``. Re-stamping on every run produced a diff with
    no signal, which every branch then had to revert or carry, and which
    collided whenever two branches ran the generator on different days.

    Simulated by ageing the stamp rather than by waiting a day, so the
    assertion is real on the day it is written. The snapshot is regenerated
    from this tree first: PRs no longer refresh the committed counts, so the
    committed file may legitimately lag the tree.
    """
    current = _run_write_against_copy(tmp_path, json.loads(METRICS_JSON.read_text(encoding="utf-8")))
    aged = dict(current)
    aged["generated_on"] = "2020-01-01"

    rewritten = _run_write_against_copy(tmp_path, aged)

    assert rewritten["generated_on"] == "2020-01-01", (
        "--write re-stamped generated_on even though no metric changed; that is churn every branch has to carry"
    )
    assert rewritten["metrics"] == aged["metrics"], "metrics must be untouched when nothing moved"


def test_write_restamps_when_a_metric_actually_moved(tmp_path: Path) -> None:
    """The stamp must still advance when a metric genuinely changes."""
    stale = json.loads(METRICS_JSON.read_text(encoding="utf-8"))
    stale["generated_on"] = "2020-01-01"
    stale["metrics"][0]["value"] = -1

    rewritten = _run_write_against_copy(tmp_path, stale)
    metrics = cast(list[dict[str, object]], rewritten["metrics"])

    assert rewritten["generated_on"] != "2020-01-01", "a real metric change must refresh the stamp"
    assert metrics[0]["value"] != -1, "the stale metric must be corrected"


def _write_variant(tmp_path: Path, mutate: Callable[[dict[str, Any]], object]) -> Path:
    """A snapshot that matches the repository exactly, then *mutate*-d."""
    variant = json.loads(METRICS_JSON.read_text(encoding="utf-8"))
    variant["metrics"] = _load_metrics_script().build_snapshot()["metrics"]
    mutate(variant)
    json_out = tmp_path / "PRODUCT_METRICS.json"
    json_out.write_text(json.dumps(variant, indent=2) + "\n")
    return json_out


def _bump_first_value(variant: dict[str, Any]) -> None:
    variant["metrics"][0]["value"] = cast(int, variant["metrics"][0]["value"]) + 1


def test_release_check_reports_a_stale_snapshot(tmp_path: Path) -> None:
    """The release gate stays strict: a drifted count blocks the tag."""
    module = _load_metrics_script()
    json_out = _write_variant(tmp_path, _bump_first_value)

    assert module.main(["--check", "--release", "--json-out", str(json_out)]) == 1


def test_release_env_var_turns_on_the_strict_check(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_metrics_script()
    json_out = _write_variant(tmp_path, _bump_first_value)
    monkeypatch.setenv("AGENT_BOM_RELEASE_CHECK", "1")

    assert module.main(["--check", "--json-out", str(json_out)]) == 1


def test_pr_check_tolerates_drifted_counts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """PRs must not have to regenerate the snapshot.

    Every PR that added a test file moved the test-file count, so every PR
    regenerated docs/PRODUCT_METRICS.* and every pair of PRs conflicted on them.
    Counts are refreshed at release time; a PR only proves the generator runs.
    """
    module = _load_metrics_script()
    json_out = _write_variant(tmp_path, _bump_first_value)
    monkeypatch.delenv("AGENT_BOM_RELEASE_CHECK", raising=False)

    assert module.main(["--check", "--json-out", str(json_out)]) == 0
    out = capsys.readouterr().out
    assert "refreshed at release" in out
    assert "committed=" in out, "the drift is still reported, just not fatal"


def test_pr_check_still_fails_when_the_metric_set_changes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Adding or renaming a metric is a generator change and must ship its artifact."""
    module = _load_metrics_script()
    json_out = _write_variant(tmp_path, lambda variant: variant["metrics"].pop())
    monkeypatch.delenv("AGENT_BOM_RELEASE_CHECK", raising=False)

    assert module.main(["--check", "--json-out", str(json_out)]) == 1


def test_pr_check_still_fails_on_a_version_mismatch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """bump-version.py rewrites the version, so it never drifts legitimately."""
    module = _load_metrics_script()
    json_out = _write_variant(tmp_path, lambda variant: variant.update(version="0.0.1"))
    monkeypatch.delenv("AGENT_BOM_RELEASE_CHECK", raising=False)

    assert module.main(["--check", "--json-out", str(json_out)]) == 1


def test_pr_check_fails_on_an_unreadable_snapshot(tmp_path: Path) -> None:
    module = _load_metrics_script()
    json_out = tmp_path / "PRODUCT_METRICS.json"
    json_out.write_text("{not json")

    assert module.main(["--check", "--json-out", str(json_out)]) == 1


def test_check_mode_accepts_the_committed_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_metrics_script()
    monkeypatch.delenv("AGENT_BOM_RELEASE_CHECK", raising=False)

    assert module.main(["--check"]) == 0


def test_release_paths_run_the_strict_check() -> None:
    """The strict comparison moved off PRs; it must still gate every release."""
    strict = "scripts/product_metrics_snapshot.py --check --release"
    assert strict in (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert strict in (ROOT / "scripts" / "preflight_release.sh").read_text(encoding="utf-8")
    assert "release" in (_load_metrics_script().__doc__ or "").lower()
