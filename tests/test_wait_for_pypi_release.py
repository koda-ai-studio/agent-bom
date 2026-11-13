"""The post-release pin job waits until PyPI serves the release before relocking launchers."""

from __future__ import annotations

import importlib.util
import sys
import urllib.error
from pathlib import Path
from types import ModuleType

import yaml

ROOT = Path(__file__).resolve().parents[1]
RELEASE_WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


def _load() -> ModuleType:
    path = ROOT / "scripts" / "wait_for_pypi_release.py"
    spec = importlib.util.spec_from_file_location("wait_for_pypi_release", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["wait_for_pypi_release"] = module
    spec.loader.exec_module(module)
    return module


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _fetcher(ready_after: dict[str, int]):
    calls: dict[str, int] = {"json": 0, "simple": 0}

    def fetch(url: str, accept: str | None = None):
        kind = "simple" if "/simple/" in url else "json"
        calls[kind] += 1
        if calls[kind] <= ready_after[kind]:
            if kind == "json":
                raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)  # type: ignore[arg-type]
            return {"versions": ["0.114.0"]}
        if kind == "json":
            return {"info": {"version": "0.115.0"}}
        assert accept == "application/vnd.pypi.simple.v1+json"
        return {"versions": ["0.114.0", "0.115.0"]}

    return fetch, calls


def test_returns_once_both_the_json_api_and_the_simple_index_serve_the_version() -> None:
    mod = _load()
    clock = _Clock()
    fetch, calls = _fetcher({"json": 2, "simple": 4})
    assert mod.wait_for_release("agent-bom", "0.115.0", timeout=600, fetch=fetch, sleep=clock.sleep, clock=clock.time) is True
    assert calls["simple"] == 5
    assert clock.sleeps and all(a <= b for a, b in zip(clock.sleeps, clock.sleeps[1:])), "backoff never shrinks"
    assert max(clock.sleeps) <= mod.MAX_INTERVAL


def test_gives_up_at_the_deadline_instead_of_hanging() -> None:
    mod = _load()
    clock = _Clock()
    fetch, _ = _fetcher({"json": 10**6, "simple": 10**6})
    assert mod.wait_for_release("agent-bom", "0.115.0", timeout=600, fetch=fetch, sleep=clock.sleep, clock=clock.time) is False
    assert 600 <= clock.now <= 600 + mod.MAX_INTERVAL


def test_network_errors_are_retried_not_fatal() -> None:
    mod = _load()
    clock = _Clock()
    state = {"n": 0}

    def flaky(url: str, accept: str | None = None):
        state["n"] += 1
        if state["n"] < 3:
            raise urllib.error.URLError("connection reset")
        return {"versions": ["0.115.0"]} if "/simple/" in url else {"info": {"version": "0.115.0"}}

    assert mod.wait_for_release("agent-bom", "0.115.0", timeout=600, fetch=flaky, sleep=clock.sleep, clock=clock.time) is True


def test_main_fails_visibly_with_an_annotation(monkeypatch, capsys) -> None:
    mod = _load()
    monkeypatch.setattr(mod, "wait_for_release", lambda *a, **k: False)
    assert mod.main(["0.115.0", "--timeout", "5"]) == 1
    out = capsys.readouterr()
    assert "::error" in out.out and "0.115.0" in out.out


def test_main_rejects_a_non_semver_version(capsys) -> None:
    mod = _load()
    assert mod.main(["v0.115.0"]) == 2


def test_pin_job_waits_for_pypi_before_bumping() -> None:
    steps = yaml.safe_load(RELEASE_WORKFLOW.read_text(encoding="utf-8"))["jobs"]["docker-mcp-pin"]["steps"]
    runs = [step.get("run", "") for step in steps]
    wait = next(i for i, run in enumerate(runs) if "scripts/wait_for_pypi_release.py" in run)
    bump = next(i for i, run in enumerate(runs) if "bump-version.py --published" in run)
    assert wait < bump
    assert '"${TAG#v}"' in runs[wait] and "--timeout 600" in runs[wait]
    assert not steps[wait].get("continue-on-error", False)
