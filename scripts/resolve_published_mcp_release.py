#!/usr/bin/env python3
"""Resolve image builds to the latest published release, never moving main."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path


def _command(args: list[str]) -> str:
    result = subprocess.run(
        args,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true"},
    )
    return result.stdout.strip()


# Release jobs that run after every artifact is published and that nothing
# downstream needs. Their failure marks the whole Release run failed, which must
# not leave the MCP image and registry entry behind the release they belong to.
POST_PUBLISH_JOBS = ("Docs build (deploy on main)", "Sync post-release pins")
PASSING_JOB_CONCLUSIONS = {"success", "skipped", "neutral"}


def blocking_failures(repository: str, run_id: int, run: Callable[[list[str]], str] = _command) -> list[str]:
    """Names of failed Release jobs that are not post-publish; fails closed when the list is incomplete."""
    payload = json.loads(run(["gh", "api", f"repos/{repository}/actions/runs/{run_id}/jobs?filter=latest&per_page=100"]))
    jobs = payload["jobs"]
    if payload["total_count"] != len(jobs):
        raise ValueError("Release job list is incomplete")

    def post_publish(name: str) -> bool:
        return any(name == job or name.startswith(f"{job} / ") for job in POST_PUBLISH_JOBS)

    return sorted(job["name"] for job in jobs if job["conclusion"] not in PASSING_JOB_CONCLUSIONS and not post_publish(job["name"]))


def resolve_release(repository: str, event_name: str, event: dict, run: Callable[[list[str]], str] = _command) -> dict[str, str]:
    """Reject mismatched source evidence; skip delayed events for older releases."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid repository")
    if not isinstance(event, dict):
        raise ValueError("Invalid event payload")
    if event["repository"]["full_name"] != repository or event_name not in {"workflow_run", "workflow_dispatch", "schedule"}:
        raise ValueError("Unsupported release event")
    workflow = event.get("workflow_run", {})
    if event_name == "workflow_run":
        completed = workflow["conclusion"] in {"success", "failure"}
        if workflow["repository"]["full_name"] != repository or workflow["event"] != "push" or not completed:
            raise ValueError("Release workflow was not a completed same-repository push")
        if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", workflow["head_branch"]):
            raise ValueError("Release workflow did not identify a version tag")
        if not re.fullmatch(r"[0-9a-f]{40}", workflow["head_sha"]):
            raise ValueError("Release workflow did not identify a commit")
        if workflow["conclusion"] == "failure" and blocking_failures(repository, int(workflow["id"]), run):
            return {"publish_current": "false", "reason": "release-failed"}
    release = json.loads(run(["gh", "api", f"repos/{repository}/releases/latest"]))
    tag = release["tag_name"]
    if release["draft"] is not False or release["prerelease"] is not False or not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("A published stable release is required")
    if event_name == "workflow_run" and workflow["head_branch"] != tag:
        return {"publish_current": "false"}
    published_at = release["published_at"]
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", published_at):
        raise ValueError("Release publication time is missing")
    branch = event["repository"]["default_branch"]
    run(["git", "check-ref-format", f"refs/heads/{branch}"])
    # Do not force an existing tag to another commit.
    run(["git", "fetch", "--no-tags", "origin", f"refs/tags/{tag}:refs/tags/{tag}"])
    sha = run(["git", "rev-parse", f"refs/tags/{tag}^{{commit}}"])
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or (event_name == "workflow_run" and sha != workflow["head_sha"]):
        raise ValueError("Release tag and workflow commit differ")
    run(["git", "fetch", "--no-tags", "origin", f"refs/heads/{branch}:refs/remotes/origin/{branch}"])
    run(["git", "merge-base", "--is-ancestor", sha, f"refs/remotes/origin/{branch}"])
    project = tomllib.loads(run(["git", "show", f"{sha}:pyproject.toml"]))
    version = tag.removeprefix("v")
    if project["project"]["version"] != version:
        raise ValueError("Tagged package version differs from release")
    return {"publish_current": "true", "release_sha": sha, "release_tag": tag, "version": version, "published_at": published_at}


def main() -> int:
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        outputs = resolve_release(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_EVENT_NAME"], event)
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
            stream.write("".join(f"{key}={value}\n" for key, value in outputs.items() if key != "reason"))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("::error::Could not verify the published release source; no image will be published.", file=sys.stderr)
        return 1
    if outputs["publish_current"] == "true":
        print("Published release source verified.")
    elif outputs.get("reason") == "release-failed":
        print("::notice title=MCP publish skipped::The Release run failed before its artifacts were published.")
    else:
        print("Skipping a superseded release event.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
