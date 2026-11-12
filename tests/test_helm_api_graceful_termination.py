"""A terminating API pod keeps serving until endpoints drain, then finishes in-flight work inside its grace period."""

from __future__ import annotations

import pytest

from tests._helm_render import container_env, find, objects, render, requires_helm

pytestmark = requires_helm


def _pod(docs: list[dict], name: str) -> dict:
    return find(docs, "Deployment", name)["spec"]["template"]["spec"]


def test_api_pod_sleeps_before_sigterm_and_its_budget_fits_the_grace_period() -> None:
    docs = objects(render({}))
    pod = _pod(docs, "agent-bom-api")
    container = pod["containers"][0]
    assert container["lifecycle"]["preStop"] == {"exec": {"command": ["sleep", "10"]}}
    env = container_env(find(docs, "Deployment", "agent-bom-api"))
    budget = 10 + int(env["AGENT_BOM_GRACEFUL_SHUTDOWN_SECONDS"]) + int(env["AGENT_BOM_SHUTDOWN_DRAIN_SECONDS"])
    assert pod["terminationGracePeriodSeconds"] >= budget + 5


def test_worker_gets_the_same_shutdown_budget_without_the_endpoint_sleep() -> None:
    docs = objects(render({"worker": {"enabled": True}}))
    pod = _pod(docs, "agent-bom-worker")
    container = pod["containers"][0]
    assert "lifecycle" not in container
    env = container_env(find(docs, "Deployment", "agent-bom-worker"))
    budget = int(env["AGENT_BOM_GRACEFUL_SHUTDOWN_SECONDS"]) + int(env["AGENT_BOM_SHUTDOWN_DRAIN_SECONDS"])
    assert pod["terminationGracePeriodSeconds"] >= budget + 5


def test_operators_tune_the_shutdown_budget() -> None:
    shutdown = {"preStopSleepSeconds": 5, "gracefulShutdownSeconds": 20, "drainSeconds": 30}
    docs = objects(render({"api": {"shutdown": shutdown, "terminationGracePeriodSeconds": 60}}))
    container = _pod(docs, "agent-bom-api")["containers"][0]
    assert container["lifecycle"]["preStop"]["exec"]["command"] == ["sleep", "5"]
    env = container_env(find(docs, "Deployment", "agent-bom-api"))
    assert (env["AGENT_BOM_GRACEFUL_SHUTDOWN_SECONDS"], env["AGENT_BOM_SHUTDOWN_DRAIN_SECONDS"]) == ("20", "30")


def test_zero_pre_stop_sleep_renders_no_hook() -> None:
    docs = objects(render({"api": {"shutdown": {"preStopSleepSeconds": 0}}}))
    assert "lifecycle" not in _pod(docs, "agent-bom-api")["containers"][0]


@pytest.mark.parametrize(
    ("control_plane", "path"),
    [
        ({"api": {"terminationGracePeriodSeconds": 30}}, "controlPlane.api.terminationGracePeriodSeconds"),
        ({"worker": {"enabled": True, "terminationGracePeriodSeconds": 20}}, "controlPlane.worker.terminationGracePeriodSeconds"),
    ],
)
def test_a_budget_longer_than_the_grace_period_fails_rendering(control_plane: dict, path: str) -> None:
    result = render(control_plane)
    assert result.returncode != 0
    assert path in result.stderr


@pytest.mark.parametrize("name", ["AGENT_BOM_SHUTDOWN_DRAIN_SECONDS", "AGENT_BOM_GRACEFUL_SHUTDOWN_SECONDS"])
def test_shutdown_timing_comes_only_from_chart_values(name: str) -> None:
    result = render({"api": {"env": [{"name": name, "value": "5"}]}})
    assert result.returncode != 0
    assert "controlPlane.api.shutdown" in result.stderr
