"""The daily ``latest`` refresh must publish fresh OS packages and gate what it scanned.

* BuildKit's GitHub Actions cache keyed the ``apk upgrade`` / ``apt-get
  upgrade`` layers on an unchanged RUN line and a digest-pinned base, so the
  pushed images reused stale OS packages (the 2026-11-02 refresh log shows the
  upgrade layer ``CACHED``) and the daily refresh never absorbed new fixes.
* Docker Engine 29 gives a locally built tag a ``RepoDigests`` entry, so the
  gate scanned the candidate from the daemon and asked Docker Hub for its
  signatures. The gates scan the saved archive instead, as CI does: a local
  RepoDigest does not prove registry publication.
* The UI image's Node.js runtime has no advisory source; its gate accepts that
  gap only through a reviewed coverage exception.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "refresh-latest-container.yml"
JOBS = {
    "refresh-latest": ("agent-bom:latest-refresh-test", "build-push"),
    "refresh-ui-latest": ("agent-bom-ui:latest-refresh-test", "build-push-ui"),
    "refresh-collector-latest": ("agent-bom-collector:latest-refresh-test", "build-push"),
}


def _jobs() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())["jobs"]


def _step(steps: list[dict], predicate) -> dict:
    matches = [step for step in steps if predicate(step)]
    assert len(matches) == 1, [step.get("name") for step in matches]
    return matches[0]


@pytest.mark.parametrize("job", sorted(JOBS))
def test_published_refresh_rebuilds_os_layers_without_the_buildkit_cache(job):
    steps = _jobs()[job]["steps"]
    _tag, push_id = JOBS[job]
    push = _step(steps, lambda step: step.get("id") == push_id)
    assert push["uses"].startswith("docker/build-push-action@")
    assert push["with"].get("no-cache") is True
    assert "cache-from" not in push["with"]
    assert "cache-to" not in push["with"]


@pytest.mark.parametrize("job", sorted(JOBS))
def test_scanned_candidate_is_also_built_from_scratch(job):
    tag, _push_id = JOBS[job]
    steps = _jobs()[job]["steps"]
    build = _step(steps, lambda step: "docker build" in str(step.get("run", "")) and f"-t {tag}" in str(step.get("run", "")))
    assert "--no-cache" in build["run"]


@pytest.mark.parametrize("job", sorted(JOBS))
def test_uncached_multi_arch_publish_has_room_in_the_job_budget(job):
    assert _jobs()[job]["timeout-minutes"] >= 45


@pytest.mark.parametrize("job", sorted(JOBS))
def test_gate_scans_the_saved_candidate_archive_not_a_registry_lookup(job):
    tag, _push_id = JOBS[job]
    steps = _jobs()[job]["steps"]
    gate = _step(steps, lambda step: "vulnerability refresh gate" in step.get("name", ""))
    run = gate["run"]
    assert f"docker save {tag} -o" in run
    assert 'image --tar "${RUNNER_TEMP}/' in run
    assert f"image {tag}" not in run
    for flag in ("--ignore .image-scan-ignore", "--exclude-unfixable", "--fail-on-severity medium"):
        assert flag in run
    assert "|| true" not in run
    assert "continue-on-error" not in gate


def test_ui_gate_accepts_only_reviewed_coverage_exceptions_after_a_partial_exit():
    steps = _jobs()["refresh-ui-latest"]["steps"]
    gate = _step(steps, lambda step: "vulnerability refresh gate" in step.get("name", ""))
    run = gate["run"]
    assert "--format json --output image-refresh.json" in run
    assert "|| status=$?" in run
    assert 'if [ "$status" -eq 1 ]; then' in run
    assert 'exit "$status"' in run
    assert "scripts/check_image_coverage_exceptions.py" in run
    assert "--exceptions docs/security/image-exceptions.yaml" in run
    assert "--image agentbom/agent-bom-ui" in run
    assert "--fail-on-severity medium" in run.split("check_image_coverage_exceptions.py", 1)[1]
    overlay = _step(steps, lambda step: step.get("name") == "Apply current UI runtime security overlay")
    assert "scripts/check_image_coverage_exceptions.py" in overlay["run"], "the release tag checkout predates the checker"


@pytest.mark.parametrize("job", ["refresh-latest", "refresh-collector-latest"])
def test_api_and_collector_gates_take_no_coverage_exception(job):
    gate = _step(_jobs()[job]["steps"], lambda step: "vulnerability refresh gate" in step.get("name", ""))
    assert "check_image_coverage_exceptions" not in gate["run"]
