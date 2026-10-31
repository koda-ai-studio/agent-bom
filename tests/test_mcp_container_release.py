"""MCP publishing must preserve the API image and the released source identity."""

import importlib.util
import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def _workflow(name):
    return yaml.safe_load((ROOT / ".github/workflows" / name).read_text())


def _tags(job):
    return {
        tag.strip()
        for step in job["steps"]
        if str(step.get("uses", "")).startswith("docker/build-push-action@")
        for tag in step["with"]["tags"].splitlines()
    }


def test_mcp_images_cannot_overwrite_the_api_release_tags():
    api_tags = _tags(_workflow("release.yml")["jobs"]["docker-publish"])
    jobs = _workflow("publish-mcp.yml")["jobs"]
    for name in ("publish-stdio", "publish-sse"):
        assert not (_tags(jobs[name]) & api_tags), "MCP publisher overwrites an API image tag"
    assert any("/agent-bom-mcp:" in tag for tag in _tags(jobs["publish-stdio"]))


def test_mcp_resolver_uses_the_default_branch():
    jobs = _workflow("publish-mcp.yml")["jobs"]
    resolver_checkout = next(step for step in jobs["release"]["steps"] if str(step.get("uses", "")).startswith("actions/checkout@"))
    assert resolver_checkout["with"].get("ref") == "${{ github.event.repository.default_branch }}"


@pytest.mark.parametrize("name", ["publish-stdio", "publish-sse"])
def test_mcp_publishers_keep_release_source_inside_buildkit(name):
    steps = _workflow("publish-mcp.yml")["jobs"][name]["steps"]
    assert not any(str(step.get("uses", "")).startswith(("actions/checkout@", "./")) for step in steps)
    assert not any("run" in step for step in steps), "release source must not execute on the publishing runner"
    build = next(step for step in steps if str(step.get("uses", "")).startswith("docker/build-push-action@"))
    assert not ({"secrets", "secret-envs", "secret-files", "ssh", "allow"} & build["with"].keys())


def test_both_mcp_images_build_the_resolved_release_commit():
    workflow = _workflow("publish-mcp.yml")
    assert workflow["concurrency"]["cancel-in-progress"] is False
    jobs = workflow["jobs"]
    for name in ("publish-stdio", "publish-sse"):
        job = jobs[name]
        assert job["needs"] == "release"
        assert "needs.release.outputs.publish_current == 'true'" in job["if"]
        build = next(step for step in job["steps"] if str(step.get("uses", "")).startswith("docker/build-push-action@"))
        assert build["with"]["context"] == "https://github.com/${{ github.repository }}.git#${{ needs.release.outputs.release_sha }}"
        assert "VERSION=${{ needs.release.outputs.version }}" in build["with"]["build-args"]
        assert "org.opencontainers.image.revision=${{ needs.release.outputs.release_sha }}" in build["with"]["labels"]


@pytest.fixture
def resolver():
    spec = importlib.util.spec_from_file_location("mcp_release", ROOT / "scripts/resolve_published_mcp_release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def release_case():
    repo = "example/scanner"
    sha = "a" * 40
    event = {
        "repository": {"full_name": repo, "default_branch": "main"},
        "workflow_run": {
            "repository": {"full_name": repo},
            "event": "push",
            "conclusion": "success",
            "head_branch": "v9.8.7",
            "head_sha": sha,
        },
    }
    release = {"tag_name": "v9.8.7", "draft": False, "prerelease": False, "published_at": "2026-10-31T12:00:00Z"}
    calls = []

    def run(args):
        calls.append(args)
        if args[:2] == ["gh", "api"]:
            return json.dumps(release)
        if args[:2] == ["git", "rev-parse"]:
            return sha
        if args[:2] == ["git", "show"]:
            return '[project]\nversion = "9.8.7"\n'
        return ""

    return repo, event, release, calls, run


@pytest.mark.parametrize("event_name", ["workflow_run", "workflow_dispatch", "schedule"])
def test_resolves_published_tag_and_checks_ancestry_and_package_version(resolver, release_case, event_name):
    repo, event, _, calls, run = release_case
    result = resolver.resolve_release(repo, event_name, event, run)
    assert result == {
        "publish_current": "true",
        "release_sha": "a" * 40,
        "release_tag": "v9.8.7",
        "version": "9.8.7",
        "published_at": "2026-10-31T12:00:00Z",
    }
    assert ["git", "merge-base", "--is-ancestor", "a" * 40, "refs/remotes/origin/main"] in calls
    assert ["git", "show", f"{'a' * 40}:pyproject.toml"] in calls
    assert not any("--force" in call for call in calls)


def test_delayed_event_cannot_move_latest_backwards(resolver, release_case):
    repo, event, _, calls, run = release_case
    event["workflow_run"]["head_branch"] = "v9.8.6"
    assert resolver.resolve_release(repo, "workflow_run", event, run) == {"publish_current": "false"}
    assert not any(call[0] == "git" for call in calls)


@pytest.mark.parametrize(
    "field,value",
    [
        ("event", "pull_request"),
        ("conclusion", "failure"),
        ("head_branch", "main"),
        ("head_sha", "bad"),
        ("repository", {"full_name": "other/scanner"}),
    ],
)
def test_invalid_trigger_cannot_publish(resolver, release_case, field, value):
    repo, event, _, calls, run = release_case
    event["workflow_run"][field] = value
    with pytest.raises(ValueError):
        resolver.resolve_release(repo, "workflow_run", event, run)
    assert calls == []


@pytest.mark.parametrize(
    "field,value", [("draft", True), ("prerelease", True), ("tag_name", "v9.8.7\nversion=other"), ("published_at", "")]
)
def test_unpublished_or_invalid_release_cannot_publish(resolver, release_case, field, value):
    repo, event, release, calls, run = release_case
    release[field] = value
    with pytest.raises(ValueError):
        resolver.resolve_release(repo, "workflow_run", event, run)
    assert not any(call[0] == "git" for call in calls)


@pytest.mark.parametrize("failure", ["tag_moved", "version_mismatch", "not_on_main", "timeout"])
def test_source_verification_fails_closed(resolver, release_case, failure):
    repo, event, _, _, run = release_case

    def broken(args):
        if failure == "tag_moved" and args[:2] == ["git", "rev-parse"]:
            return "b" * 40
        if failure == "version_mismatch" and args[:2] == ["git", "show"]:
            return '[project]\nversion = "9.8.8"\n'
        if failure == "not_on_main" and args[:2] == ["git", "merge-base"]:
            raise subprocess.CalledProcessError(1, args)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(args, 30)
        return run(args)

    with pytest.raises((ValueError, subprocess.SubprocessError)):
        resolver.resolve_release(repo, "workflow_run", deepcopy(event), broken)


def test_failed_resolution_writes_no_publish_outputs_or_raw_error(resolver, tmp_path, monkeypatch, capsys):
    event = tmp_path / "event.json"
    event.write_text("{}")
    output = tmp_path / "output"
    for key, value in {
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_OUTPUT": str(output),
        "GITHUB_REPOSITORY": "example/scanner",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
    }.items():
        monkeypatch.setenv(key, value)

    def fail(*args):
        raise ValueError("private diagnostic content")

    monkeypatch.setattr(resolver, "resolve_release", fail)
    assert resolver.main() == 1
    assert not output.exists()
    assert "private diagnostic content" not in capsys.readouterr().err
