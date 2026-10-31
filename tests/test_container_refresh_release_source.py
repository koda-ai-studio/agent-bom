"""Floating image refreshes must not publish a failed or unpublished tag."""

from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _workflow():
    return yaml.safe_load((ROOT / ".github/workflows/refresh-latest-container.yml").read_text())


def test_refresh_resolves_a_published_release_once_before_publish_jobs():
    jobs = _workflow()["jobs"]
    assert "release" in jobs, "refresh must resolve the published release before any image job"
    job = jobs["release"]
    assert job["permissions"] == {"contents": "read"}
    steps = job["steps"]
    resolver = next(step for step in steps if step.get("id") == "resolve")
    assert "python scripts/resolve_published_mcp_release.py" in resolver["run"]
    assert resolver["env"]["GH_TOKEN"] == "${{ github.token }}"
    for key in ["release_sha", "release_tag", "version"]:
        assert job["outputs"][key] == "${{ steps.resolve.outputs." + key + " }}"


@pytest.mark.parametrize("name", ["refresh-latest", "refresh-ui-latest", "refresh-collector-latest"])
def test_refresh_builds_verified_commit_and_never_selects_highest_tag(name):
    job = _workflow()["jobs"][name]
    assert job.get("needs") == "release"
    step = next(step for step in job["steps"] if step.get("id") == "release")
    assert step["env"]["RELEASE_SHA"] == "${{ needs.release.outputs.release_sha }}"
    assert step["env"]["RELEASE_TAG"] == "${{ needs.release.outputs.release_tag }}"
    assert step["env"]["RELEASE_VERSION"] == "${{ needs.release.outputs.version }}"
    assert 'git checkout --detach "$RELEASE_SHA"' in step["run"]
    assert "git tag -l" not in step["run"]
    assert "--force" not in step["run"]
    assert 'echo "tag=$RELEASE_TAG"' in step["run"]
    assert 'echo "main_sha=$MAIN_SHA"' in step["run"]


@pytest.mark.parametrize("name", ["refresh-latest", "refresh-ui-latest", "refresh-collector-latest"])
def test_refresh_checkout_ignores_a_newer_unpublished_tag(tmp_path, name):
    import os
    import subprocess

    def git(*args):
        return subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True, text=True).stdout.strip()

    git("init", "-b", "main")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.test")
    git("config", "commit.gpgsign", "false")
    git("commit", "--allow-empty", "-m", "Published fixture")
    published_sha = git("rev-parse", "HEAD")
    git("tag", "v1.0.0")
    git("commit", "--allow-empty", "-m", "Unpublished fixture")
    unpublished_sha = git("rev-parse", "HEAD")
    git("tag", "v9.0.0")
    outputs = tmp_path / "outputs"
    env = {
        **os.environ,
        "RELEASE_SHA": published_sha,
        "RELEASE_TAG": "v1.0.0",
        "RELEASE_VERSION": "1.0.0",
        "GITHUB_OUTPUT": str(outputs),
    }
    step = next(step for step in _workflow()["jobs"][name]["steps"] if step.get("id") == "release")
    subprocess.run(["bash", "-c", step["run"]], cwd=tmp_path, env=env, check=True, capture_output=True, text=True)
    assert git("rev-parse", "HEAD") == published_sha
    assert dict(line.split("=", 1) for line in outputs.read_text().splitlines()) == {
        "tag": "v1.0.0",
        "version": "1.0.0",
        "main_sha": unpublished_sha,
    }
