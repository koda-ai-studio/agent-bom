"""JSON logging is an operator switch in the Helm chart and in compose, off by default."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests._helm_render import ATTESTED_API_SET_ARGS

ROOT = Path(__file__).resolve().parents[1]
HELM_DIR = ROOT / "deploy" / "helm" / "agent-bom"
COMPOSE_WITH_API = [
    ROOT / "deploy" / "docker-compose.fullstack.yml",
    ROOT / "deploy" / "docker-compose.platform.yml",
    ROOT / "deploy" / "docker-compose.pilot.yml",
]


def _control_plane_containers(*sets: str) -> dict[str, dict]:
    # Workers need the shared Postgres queue, so render from the BYO Postgres profile.
    profile = HELM_DIR / "examples" / "byo-postgres-values.yaml"
    args = [
        "helm",
        "template",
        "abom",
        str(HELM_DIR),
        "-f",
        str(profile),
        "--set",
        "controlPlane.worker.enabled=true",
        *ATTESTED_API_SET_ARGS,
    ]
    for item in sets:
        args += ["--set", item]
    rendered = subprocess.run(args, check=True, capture_output=True, text=True).stdout
    containers: dict[str, dict] = {}
    for doc in yaml.safe_load_all(rendered):
        if not doc or doc.get("kind") != "Deployment":
            continue
        component = doc["metadata"].get("labels", {}).get("app.kubernetes.io/component", "")
        if component in {"api", "worker"}:
            containers[component] = doc["spec"]["template"]["spec"]["containers"][0]
    return containers


def _env(container: dict) -> dict[str, str]:
    return {entry["name"]: entry.get("value") for entry in container.get("env", [])}


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
def test_chart_json_logging_is_off_by_default_and_reaches_api_and_worker_when_on() -> None:
    default = _control_plane_containers()
    assert set(default) == {"api", "worker"}
    for container in default.values():
        assert "AGENT_BOM_LOG_JSON" not in _env(container)

    enabled = _control_plane_containers("controlPlane.logging.json=true")
    for container in enabled.values():
        assert _env(container)["AGENT_BOM_LOG_JSON"] == "1"


def test_chart_values_document_the_switch_off() -> None:
    values = yaml.safe_load((HELM_DIR / "values.yaml").read_text(encoding="utf-8"))
    assert values["controlPlane"]["logging"]["json"] is False


COMPOSE_FILES = sorted(
    {*ROOT.glob("compose*.y*ml"), *(ROOT / "deploy").glob("docker-compose*.y*ml"), *(ROOT / "examples").glob("docker-compose*.y*ml")}
)


@pytest.mark.parametrize("path", COMPOSE_FILES, ids=lambda p: p.name)
def test_compose_services_do_not_pin_container_names(path: Path) -> None:
    # A fixed container_name stops a second copy of the stack (another project
    # name) from starting; services reach each other by service name instead.
    services = yaml.safe_load(path.read_text(encoding="utf-8")).get("services") or {}
    pinned = {name: svc["container_name"] for name, svc in services.items() if "container_name" in svc}
    assert not pinned


@pytest.mark.parametrize("path", COMPOSE_WITH_API, ids=lambda p: p.name)
def test_compose_api_reads_the_json_switch_and_defaults_off(path: Path) -> None:
    services = yaml.safe_load(path.read_text(encoding="utf-8"))["services"]
    api = next(svc for name, svc in services.items() if "api" in name and "migrate" not in name)
    env = api.get("environment") or {}
    if isinstance(env, list):
        env = dict(item.split("=", 1) for item in env)
    assert env.get("AGENT_BOM_LOG_JSON") == "${AGENT_BOM_LOG_JSON:-0}"
