"""The Docker Hub push token never reaches pull-request CI; only release environments can read it."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
PUSH_TOKEN = "secrets.DOCKERHUB_TOKEN"


def _jobs(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text())["jobs"]


def _environment(job: dict) -> str:
    env = job.get("environment")
    return env.get("name", "") if isinstance(env, dict) else str(env or "")


def _runs_on_pull_requests(job: dict) -> bool:
    return "github.event_name != 'pull_request'" not in str(job.get("if", ""))


def test_pull_request_ci_never_reads_the_push_token() -> None:
    exposed = [name for name, job in _jobs("ci.yml").items() if _runs_on_pull_requests(job) and PUSH_TOKEN in yaml.safe_dump(job)]
    assert exposed == []
    assert "secrets.DOCKERHUB_READ_TOKEN" in (WORKFLOWS / "ci.yml").read_text()


def test_every_job_holding_the_push_token_runs_in_the_release_environment() -> None:
    holders = []
    for path in sorted(WORKFLOWS.glob("*.yml")):
        if path.name == "ci.yml":
            continue
        for name, job in (yaml.safe_load(path.read_text()).get("jobs") or {}).items():
            if PUSH_TOKEN in yaml.safe_dump(job):
                holders.append((path.name, name, _environment(job)))
    assert holders, "expected the release workflows to publish images"
    assert [h for h in holders if h[2] != "docker-release"] == []
