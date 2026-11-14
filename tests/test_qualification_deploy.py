"""The deploy lane's image source: images built from the checkout on PRs, published images on releases."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

QUALIFICATION = Path(__file__).resolve().parents[1] / "scripts" / "qualification"
sys.path.insert(0, str(QUALIFICATION))

import common  # noqa: E402
import summarize  # noqa: E402

import deploy  # noqa: E402

WORKFLOW = QUALIFICATION.parents[1] / ".github" / "workflows" / "qualification.yml"
LOCAL_API = f"{deploy.API_REPOSITORY}:{deploy.LOCAL_TAG}"
LOCAL_UI = f"{deploy.UI_REPOSITORY}:{deploy.LOCAL_TAG}"
_REAL_RUN = subprocess.run


@pytest.mark.parametrize(
    ("requested", "ref", "expected"),
    [
        ("auto", "refs/tags/v0.115.0", "published"),
        ("auto", "refs/pull/6290/merge", "local"),
        ("auto", "refs/heads/ci/some-branch", "local"),
        ("auto", "refs/heads/main", "local"),
        ("auto", "", "local"),
        ("published", "refs/pull/1/merge", "published"),
        ("local", "refs/tags/v0.115.0", "local"),
    ],
)
def test_image_mode_is_published_only_for_a_release_ref_unless_asked(requested: str, ref: str, expected: str) -> None:
    assert deploy.resolve_image_mode(requested, ref) == expected


def test_unknown_image_mode_is_refused() -> None:
    with pytest.raises(ValueError):
        deploy.resolve_image_mode("latest", "refs/heads/main")


def test_local_builds_use_the_release_dockerfiles_and_only_the_checkout() -> None:
    api, ui = deploy.local_build_commands()
    assert api[:2] == ["docker", "build"]
    assert api[api.index("-t") + 1] == LOCAL_API
    assert api[-1] == str(deploy.REPO_ROOT)
    assert "-f" not in api  # the release publishes the root Dockerfile for agentbom/agent-bom
    assert ui[ui.index("-f") + 1] == str(deploy.REPO_ROOT / "ui" / "Dockerfile")
    assert ui[ui.index("-t") + 1] == LOCAL_UI
    assert "NEXT_PUBLIC_API_URL=" in ui
    assert ui[-1] == str(deploy.REPO_ROOT / "ui")
    for command in (api, ui):
        assert "--push" not in command and not any("secret" in part for part in command)


def test_kind_load_targets_both_local_images_on_the_lane_cluster() -> None:
    commands = deploy.kind_load_commands()
    assert commands == [
        ["kind", "load", "docker-image", LOCAL_API, "--name", deploy.KIND_CLUSTER],
        ["kind", "load", "docker-image", LOCAL_UI, "--name", deploy.KIND_CLUSTER],
    ]


def test_published_mode_adds_no_helm_overrides() -> None:
    assert deploy.helm_image_overrides("published") == []


def _settings(arguments: list[str]) -> dict[str, str]:
    assert arguments[::2] == ["--set"] * (len(arguments) // 2)
    return dict(item.split("=", 1) for item in arguments[1::2])


def test_local_mode_overrides_every_agent_bom_image_key_and_never_pulls() -> None:
    settings = _settings(deploy.helm_image_overrides("local"))
    for key in ("image", "runtimeImage", "tests.image", "teardownHooks.image", "gateway.image"):
        assert settings[f"{key}.repository"] == deploy.API_REPOSITORY, key
        assert settings[f"{key}.tag"] == deploy.LOCAL_TAG, key
        assert settings[f"{key}.pullPolicy"] == "Never", key
    assert settings["uiImage.repository"] == deploy.UI_REPOSITORY
    assert settings["uiImage.tag"] == deploy.LOCAL_TAG
    assert settings["uiImage.pullPolicy"] == "Never"
    assert settings["sidecarInjection.image.repository"] == deploy.API_REPOSITORY
    assert settings["sidecarInjection.image.pullPolicy"] == "Never"


def test_rendered_images_are_read_from_the_manifest() -> None:
    manifest = (
        "# Source: agent-bom/templates/a.yaml\n"
        '          image: "agentbom/agent-bom:0.115.0"\n'
        "          image: agentbom/agent-bom-ui:0.115.0\n"
        "    image: postgres:16-alpine\n"
        '          image: "agentbom/agent-bom:0.115.0"\n'
    )
    assert deploy.rendered_images(manifest) == ["agentbom/agent-bom-ui:0.115.0", "agentbom/agent-bom:0.115.0", "postgres:16-alpine"]


def test_local_mode_flags_any_agent_bom_image_that_would_still_be_pulled() -> None:
    images = [LOCAL_API, LOCAL_UI, "agentbom/agent-bom:0.115.0", "agentbom/agent-bom-collector:0.115.0", "postgres:16-alpine"]
    assert deploy.unbuilt_images(images, "local") == ["agentbom/agent-bom:0.115.0"]
    assert deploy.unbuilt_images(images, "published") == []


def _render(*values: str) -> list[str]:
    command = ["helm", "template", "q", str(deploy.CHART), "--set", "controlPlane.observability.prometheusRule.enabled=false", *values]
    rendered = subprocess.run(command, capture_output=True, text=True, check=True)  # noqa: S603
    return deploy.rendered_images(rendered.stdout)


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
@pytest.mark.parametrize("values", [(), ("-f", str(deploy.PILOT_VALUES))], ids=["default", "pilot"])
def test_local_overrides_cover_every_image_the_lane_installs(values: tuple[str, ...]) -> None:
    published = _render(*values)
    assert deploy.unbuilt_images(published, "local"), "the stock render must pin published images"
    local = _render(*values, *deploy.helm_image_overrides("local"))
    assert deploy.unbuilt_images(local, "local") == []
    assert all(image in (LOCAL_API, LOCAL_UI) or image.startswith(deploy.COLLECTOR_REPOSITORY + ":") for image in local)


def test_compose_local_mode_selects_local_tags_and_never_pulls() -> None:
    env = deploy.compose_env("local", {"PATH": "/bin"})
    assert env["AGENT_BOM_IMAGE_TAG"] == deploy.LOCAL_TAG and env["PATH"] == "/bin"
    assert deploy.compose_up_arguments("local")[-2:] == ["--pull", "never"]


def test_compose_published_mode_keeps_the_pinned_tag() -> None:
    env = deploy.compose_env("published", {"PATH": "/bin", "AGENT_BOM_IMAGE_TAG": "stale"})
    assert "AGENT_BOM_IMAGE_TAG" not in env
    assert "--pull" not in deploy.compose_up_arguments("published")


def test_compose_tag_knob_names_both_images() -> None:
    pilot = yaml.safe_load((deploy.REPO_ROOT / "deploy" / "docker-compose.pilot.yml").read_text(encoding="utf-8"))
    images = {name: service["image"] for name, service in pilot["services"].items()}
    assert images["api"].startswith(f"{deploy.API_REPOSITORY}:${{AGENT_BOM_IMAGE_TAG:-")
    assert images["ui"].startswith(f"{deploy.UI_REPOSITORY}:${{AGENT_BOM_IMAGE_TAG:-")


def test_the_image_mode_shows_in_the_summary(tmp_path: Path) -> None:
    result = deploy.LaneResult("deploy", "helm")
    result.check("helm_pilot_install", True)
    result.measurements["image_mode"] = "local"
    result.write(tmp_path)
    assert "image_mode=local" in summarize.render(summarize.load(tmp_path))


def test_workflow_passes_the_image_mode_to_the_deploy_lane() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    dispatch = workflow[True]["workflow_dispatch"]["inputs"]["images"]
    assert dispatch["type"] == "choice" and dispatch["default"] == "auto"
    assert set(dispatch["options"]) == {"auto", "local", "published"}
    step = next(step for step in workflow["jobs"]["deploy"]["steps"] if step.get("name") == "Run the deploy lane")
    assert step["env"]["DEPLOY_IMAGES"] == "${{ inputs.images || 'auto' }}"
    assert '--images "$DEPLOY_IMAGES"' in step["run"]


def _helm_run(monkeypatch, mode: str) -> tuple[list[list[str]], deploy.LaneResult]:
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs) -> common.RunResult:
        commands.append(command)
        stdout = ""
        if command[:2] == ["helm", "template"]:
            stdout = _REAL_RUN(command, capture_output=True, text=True, check=True).stdout  # noqa: S603
        failed = command[:2] == ["helm", "upgrade"] and "agent-bom" in command[3:4]
        return common.RunResult(returncode=1 if failed else 0, seconds=0.1, peak_rss_mb=None, stdout=stdout, stderr="")

    def fake_version(command: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "v0\n", "")

    monkeypatch.setattr(deploy, "run_measured", fake_run)
    monkeypatch.setattr(deploy.subprocess, "run", fake_version)
    monkeypatch.setattr(deploy, "kubectl", lambda *_a, **_k: subprocess.CompletedProcess([], 0, "deployment/x\n", ""))
    monkeypatch.setattr(deploy, "helm_uninstall", lambda *_a: None)
    monkeypatch.setattr(deploy, "prepare_pilot_namespace", lambda: "key")
    monkeypatch.setattr(deploy, "dump_cluster_state", lambda _name: "")
    result = deploy.LaneResult("deploy", "helm")
    deploy.run_helm(result, mode)
    return commands, result


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
def test_local_helm_run_builds_loads_then_installs_with_overrides(monkeypatch) -> None:
    commands, result = _helm_run(monkeypatch, "local")
    order = [" ".join(command[:3]) for command in commands if command[0] != "helm" or command[1] == "upgrade"]
    assert order == [
        "docker build -t",
        "docker build -f",
        "kind create cluster",
        "kind load docker-image",
        "kind load docker-image",
        "helm upgrade --install",
        "helm upgrade --install",
    ]
    installs = [command for command in commands if command[:2] == ["helm", "upgrade"]]
    for install in installs:
        assert f"image.tag={deploy.LOCAL_TAG}" in install and "teardownHooks.image.pullPolicy=Never" in install
    assert set(result.measurements["helm_pilot_images"]) == {LOCAL_API, LOCAL_UI}
    assert not result.passed  # the faked pilot install failure still fails the lane


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
def test_published_helm_run_builds_nothing_and_installs_the_pins(monkeypatch) -> None:
    commands, result = _helm_run(monkeypatch, "published")
    assert not any(command[0] == "docker" or command[:2] == ["kind", "load"] for command in commands)
    installs = [command for command in commands if command[:2] == ["helm", "upgrade"]]
    assert installs and not any("--set" in install for install in installs)
    assert any(
        image.startswith(f"{deploy.API_REPOSITORY}:") and deploy.LOCAL_TAG not in image
        for image in result.measurements["helm_pilot_images"]
    )
