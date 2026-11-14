#!/usr/bin/env python3
"""Deploy lane: the repo's compose file and Helm chart on a real runtime.

Compose runs the checked-out ``compose.yaml``. Helm installs the chart on ``kind``
with the repo's values. Each path asserts health and a real API write and read.
Failures, including a chart that needs a CRD the cluster lacks, are recorded as
defects and fail the lane; the lane never edits the chart.

``--images`` picks where the API and UI images come from:

- ``published`` uses the images compose and the chart pin, because that is what a
  user of a released checkout gets. Run it on a release tag, after publishing.
- ``local`` builds both images from this checkout with the release Dockerfiles,
  loads them into ``kind`` and points every agent-bom image key at them with
  ``pullPolicy: Never``. Between a version bump and its release the pinned tags
  do not exist yet, so PRs and branches test what they would ship instead.
- ``auto`` (the default) is ``published`` on a ``refs/tags/`` ref and ``local``
  otherwise.

The local build reads only the checkout and pushes nothing. The collector image
keeps its pin in both modes: only the scanner CronJob uses it, and the lane never
triggers that CronJob.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import REPO_ROOT, RESULTS_DIR, LaneResult, free_port, http_json, run_measured, tail, wait_for_http  # noqa: E402

CHART = REPO_ROOT / "deploy" / "helm" / "agent-bom"
PILOT_VALUES = CHART / "examples" / "eks-control-plane-sqlite-pilot-values.yaml"
NAMESPACE = "agent-bom"
KIND_CLUSTER = "qualification"
API_REPOSITORY = "agentbom/agent-bom"
UI_REPOSITORY = "agentbom/agent-bom-ui"
COLLECTOR_REPOSITORY = "agentbom/agent-bom-collector"
LOCAL_TAG = "qualification-local"
IMAGE_MODES = ("auto", "local", "published")
# Chart keys that run the API image; sidecarInjection takes its tag from image.tag.
_API_IMAGE_KEYS = ("image", "runtimeImage", "tests.image", "teardownHooks.image", "gateway.image")
_IMAGE_LINE = re.compile(r"^\s*-?\s*image:\s*[\"']?([^\"'\s]+)", re.MULTILINE)
PUSH_REPORT = {
    "scan_id": "qualification-deploy",
    "source_id": "qualification",
    "agents": [{"name": "qualification-agent", "type": "custom", "mcp_servers": []}],
    "blast_radius": [],
}


def resolve_image_mode(requested: str, ref: str) -> str:
    """``auto`` tests published images on a release tag and the checkout's images everywhere else."""
    if requested not in IMAGE_MODES:
        raise ValueError(f"unknown image mode {requested!r}; expected one of {IMAGE_MODES}")
    if requested != "auto":
        return requested
    return "published" if ref.startswith("refs/tags/") else "local"


def local_build_commands() -> list[list[str]]:
    """The release's API and UI image builds, tagged locally and never pushed."""
    return [
        ["docker", "build", "-t", f"{API_REPOSITORY}:{LOCAL_TAG}", str(REPO_ROOT)],
        [
            "docker",
            "build",
            "-f",
            str(REPO_ROOT / "ui" / "Dockerfile"),
            "--build-arg",
            "NEXT_PUBLIC_API_URL=",
            "-t",
            f"{UI_REPOSITORY}:{LOCAL_TAG}",
            str(REPO_ROOT / "ui"),
        ],
    ]


def kind_load_commands() -> list[list[str]]:
    return [
        ["kind", "load", "docker-image", f"{repository}:{LOCAL_TAG}", "--name", KIND_CLUSTER]
        for repository in (API_REPOSITORY, UI_REPOSITORY)
    ]


def helm_image_overrides(mode: str) -> list[str]:
    """``--set`` flags that point every agent-bom image the chart can render at the local build."""
    if mode != "local":
        return []
    settings = [(key, API_REPOSITORY) for key in _API_IMAGE_KEYS] + [("uiImage", UI_REPOSITORY)]
    flags: list[str] = []
    for key, repository in settings:
        for field, value in (("repository", repository), ("tag", LOCAL_TAG), ("pullPolicy", "Never")):
            flags += ["--set", f"{key}.{field}={value}"]
    for field, value in (("repository", API_REPOSITORY), ("pullPolicy", "Never")):
        flags += ["--set", f"sidecarInjection.image.{field}={value}"]
    return flags


def rendered_images(manifest: str) -> list[str]:
    return sorted(set(_IMAGE_LINE.findall(manifest)))


def unbuilt_images(images: list[str], mode: str) -> list[str]:
    """In local mode, API or UI images that would still come from a registry."""
    if mode != "local":
        return []
    local = {f"{API_REPOSITORY}:{LOCAL_TAG}", f"{UI_REPOSITORY}:{LOCAL_TAG}"}
    return [image for image in images if image.rsplit(":", 1)[0] in (API_REPOSITORY, UI_REPOSITORY) and image not in local]


def compose_env(mode: str, base: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if base is None else base)
    env.pop("AGENT_BOM_IMAGE_TAG", None)
    if mode == "local":
        env["AGENT_BOM_IMAGE_TAG"] = LOCAL_TAG
    return env


def compose_up_arguments(mode: str) -> list[str]:
    arguments = ["up", "-d", "--wait", "--wait-timeout", "300"]
    return [*arguments, "--pull", "never"] if mode == "local" else arguments


def build_local_images(result: LaneResult) -> bool:
    for command in local_build_commands():
        built = run_measured(command, cwd=REPO_ROOT, timeout=1500)
        name = command[command.index("-t") + 1].split(":")[0].rsplit("/", 1)[-1].replace("-", "_")
        result.measurements[f"{name}_image_build_seconds"] = built.seconds
        if not result.check(f"{name}_image_builds", built.returncode == 0, f"exit {built.returncode}\n{tail(built.stdout + built.stderr)}"):
            return False
    return True


def record_images(result: LaneResult, prefix: str, images: list[str], mode: str) -> bool:
    """Record which images a deployment runs; in local mode, fail if any would still be pulled."""
    result.measurements[f"{prefix}_images"] = images
    unbuilt = unbuilt_images(images, mode)
    return result.check(f"{prefix}_images_match_mode", bool(images) and not unbuilt, unbuilt or images)


def helm_rendered_images(*values: str) -> list[str]:
    rendered = run_measured(["helm", "template", "qualification", str(CHART), *values], timeout=120)
    return rendered_images(rendered.stdout) if rendered.returncode == 0 else []


def assert_api(result: LaneResult, prefix: str, base: str, *, expect_write: bool, headers: dict[str, str] | None = None) -> None:
    headers = headers or {}
    result.check(f"{prefix}_health", wait_for_http(f"{base}/health", timeout=120), f"{base}/health")
    status, version, _size = http_json(f"{base}/version", headers=headers)
    result.check(f"{prefix}_version_read", status == 200 and bool(version), f"HTTP {status} {str(version)[:200]}")
    result.measurements[f"{prefix}_version"] = version.get("version") if isinstance(version, dict) else None
    if expect_write:
        body = json.dumps(PUSH_REPORT).encode()
        status, receipt, _size = http_json(
            f"{base}/v1/results/push", method="POST", body=body, headers={**headers, "Content-Type": "application/json"}
        )
        job_id = receipt.get("job_id") if isinstance(receipt, dict) else None
        result.check(f"{prefix}_push_stored", status in (201, 202) and bool(job_id), f"HTTP {status} {str(receipt)[:300]}")
        time.sleep(3)
        status, jobs, _size = http_json(f"{base}/v1/jobs", headers=headers)
        result.check(f"{prefix}_push_reads_back", status == 200 and str(job_id) in json.dumps(jobs), f"HTTP {status} {str(jobs)[:300]}")
    else:
        status, jobs, _size = http_json(f"{base}/v1/jobs", headers=headers)
        result.check(f"{prefix}_jobs_read", status == 200 and isinstance(jobs, (dict, list)), f"HTTP {status} {str(jobs)[:300]}")
    status, findings, _size = http_json(f"{base}/v1/findings?limit=1", headers=headers)
    result.check(f"{prefix}_findings_read", status == 200 and isinstance(findings, dict), f"HTTP {status} {str(findings)[:300]}")


def run_compose(result: LaneResult, mode: str) -> None:
    compose = ["docker", "compose", "-f", str(REPO_ROOT / "compose.yaml")]
    env = compose_env(mode)
    if mode == "local" and not build_local_images(result):
        return
    images = run_measured([*compose, "config", "--images"], env=env, cwd=REPO_ROOT, timeout=60)
    if not record_images(result, "compose", sorted(images.stdout.split()), mode):
        return
    up = run_measured([*compose, *compose_up_arguments(mode)], env=env, cwd=REPO_ROOT, timeout=700)
    result.measurements["compose_up_seconds"] = up.seconds
    try:
        if not result.check("compose_up_healthy", up.returncode == 0, f"exit {up.returncode}\n{tail(up.stdout + up.stderr)}"):
            return
        assert_api(result, "compose_api", "http://127.0.0.1:8422", expect_write=True)
        status, page, _size = http_json("http://127.0.0.1:3000/", timeout=30)
        result.check("compose_ui_serves", status == 200 and "<html" in str(page).lower(), f"HTTP {status}")
        status, jobs, _size = http_json("http://127.0.0.1:3000/v1/jobs", timeout=30)
        result.check("compose_ui_proxies_api", status == 200 and isinstance(jobs, (dict, list)), f"HTTP {status} {str(jobs)[:200]}")
    finally:
        logs = run_measured([*compose, "logs", "--no-color", "--tail", "200"], env=env, cwd=REPO_ROOT, timeout=120)
        (RESULTS_DIR / "logs").mkdir(parents=True, exist_ok=True)
        (RESULTS_DIR / "logs" / "compose.log").write_text(logs.stdout + logs.stderr, encoding="utf-8")
        run_measured([*compose, "down", "-v"], env=env, cwd=REPO_ROOT, timeout=180)


def kubectl(*args: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["kubectl", *args], capture_output=True, text=True, timeout=timeout)  # noqa: S603, S607


def _apply(document: dict[str, Any]) -> None:
    subprocess.run(["kubectl", "apply", "-f", "-"], input=json.dumps(document), text=True, check=True, capture_output=True)  # noqa: S603, S607


def _fernet_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def prepare_pilot_namespace() -> str:
    """Create what the profile documents it needs; returns the sign-in key."""
    key = secrets.token_urlsafe(24)
    _apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}})
    _apply(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "agent-bom-control-plane", "namespace": NAMESPACE},
            "type": "Opaque",
            "stringData": {"AGENT_BOM_CONNECTIONS_KEY": _fernet_key(), "AGENT_BOM_API_KEYS": f"{key}:admin"},
        }
    )
    _apply(
        {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {"name": "agent-bom-sqlite-pilot", "namespace": NAMESPACE},
            "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "1Gi"}}},
        }
    )
    return key


def helm_install(release: str, namespace: str, *extra: str, timeout: str = "5m") -> Any:
    return run_measured(
        [
            "helm",
            "upgrade",
            "--install",
            release,
            str(CHART),
            "--namespace",
            namespace,
            "--create-namespace",
            "--wait",
            "--timeout",
            timeout,
            *extra,
        ],
        timeout=700,
    )


def dump_cluster_state(name: str) -> str:
    pods = kubectl("get", "pods", "-A", "-o", "wide").stdout
    events = kubectl("get", "events", "-A", "--sort-by=.lastTimestamp").stdout
    (RESULTS_DIR / "logs").mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "logs" / f"{name}-cluster.txt").write_text(pods + "\n" + events, encoding="utf-8")
    return tail(pods, 15)


def port_forward_api() -> tuple[subprocess.Popen[bytes], str]:
    services = json.loads(kubectl("get", "svc", "-n", NAMESPACE, "-o", "json").stdout)
    names = [item["metadata"]["name"] for item in services["items"] if "api" in item["metadata"]["name"]]
    if not names:
        raise RuntimeError(f"no API service in {[item['metadata']['name'] for item in services['items']]}")
    port = free_port()
    process = subprocess.Popen(
        ["kubectl", "port-forward", "-n", NAMESPACE, f"svc/{names[0]}", f"{port}:8422"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )  # noqa: S603, S607
    return process, f"http://127.0.0.1:{port}"


def helm_uninstall(result: LaneResult, release: str, namespace: str) -> None:
    """Uninstall as a user would; a failing hook is a defect, then removal continues without hooks."""
    uninstall = run_measured(["helm", "uninstall", release, "--namespace", namespace, "--wait", "--timeout", "3m"], timeout=240)
    error = uninstall.stdout + uninstall.stderr
    result.check(f"helm_uninstall_{release}", uninstall.returncode == 0, tail(error))
    if uninstall.returncode == 0:
        return
    hook_log = kubectl("logs", "-n", namespace, "-l", "app.kubernetes.io/component=teardown-hook", "--tail", "25").stdout
    result.measurements[f"helm_uninstall_{release}_hook_log"] = tail(hook_log, 25)
    if not any(defect["id"] == "helm-uninstall-hook-fails" for defect in result.defects):
        result.defect(
            "helm-uninstall-hook-fails",
            f"`helm uninstall` exits 1 because the pre-delete cleanup Job fails: {tail(hook_log, 3) or tail(error, 2)}",
            "kind create cluster && helm install x deploy/helm/agent-bom -n x --create-namespace --wait && helm uninstall x -n x --wait",
        )
    run_measured(["helm", "uninstall", release, "--namespace", namespace, "--no-hooks", "--wait", "--timeout", "3m"], timeout=240)


def run_helm(result: LaneResult, mode: str) -> None:
    tools = {
        name: subprocess.run(command, capture_output=True, text=True).stdout.strip()[:120]
        for name, command in (("kind", ["kind", "version"]), ("helm", ["helm", "version", "--short"]))
    }  # noqa: S603
    result.measurements["tools"] = tools
    result.skip(
        "collector_image",
        f"{COLLECTOR_REPOSITORY} keeps the chart's pin: only the scanner CronJob runs it and the lane never triggers that CronJob",
    )
    overrides = helm_image_overrides(mode)
    pilot_values = ["-f", str(PILOT_VALUES), *overrides]
    if not (
        record_images(result, "helm_default", helm_rendered_images(*overrides), mode)
        and record_images(result, "helm_pilot", helm_rendered_images(*pilot_values), mode)
    ):
        return
    if mode == "local" and not build_local_images(result):
        return
    created = run_measured(["kind", "create", "cluster", "--name", KIND_CLUSTER, "--wait", "180s"], timeout=400)
    if not result.check("kind_cluster_created", created.returncode == 0, tail(created.stdout + created.stderr)):
        return
    if mode == "local":
        for command in kind_load_commands():
            loaded = run_measured(command, timeout=600)
            if not result.check(f"kind_loaded_{command[3]}", loaded.returncode == 0, tail(loaded.stdout + loaded.stderr)):
                return

    default = helm_install("scanner", "scanner-only", *overrides, timeout="4m")
    result.measurements["helm_default_install_seconds"] = default.seconds
    result.check(
        "helm_default_values_install", default.returncode == 0, f"exit {default.returncode}\n{tail(default.stdout + default.stderr)}"
    )
    resources = kubectl("get", "cronjob,job,daemonset,deployment", "-n", "scanner-only", "-o", "name").stdout.split()
    result.check("helm_default_values_create_workloads", bool(resources), resources)

    # The default and pilot releases both own the cluster-scoped agent-bom-reader ClusterRole.
    helm_uninstall(result, "scanner", "scanner-only")
    headers = {"Authorization": f"Bearer {prepare_pilot_namespace()}"}
    stock = helm_install("agent-bom", NAMESPACE, *pilot_values)
    result.measurements["helm_pilot_install_seconds"] = stock.seconds
    stock_error = stock.stdout + stock.stderr
    if stock.returncode != 0 and "PrometheusRule" in stock_error:
        result.defect(
            "chart-requires-prometheusrule-crd",
            "The chart's default controlPlane.observability.prometheusRule.enabled=true "
            "makes install fail on a cluster without the Prometheus Operator CRDs",
            f"kind create cluster && helm install agent-bom deploy/helm/agent-bom -n {NAMESPACE} --create-namespace "
            "-f deploy/helm/agent-bom/examples/eks-control-plane-sqlite-pilot-values.yaml",
        )
        print(tail(stock_error, 8))
        # Keep measuring the rest of the deployment; the defect above already fails the lane.
        stock = helm_install("agent-bom", NAMESPACE, *pilot_values, "--set", "controlPlane.observability.prometheusRule.enabled=false")
        result.measurements["helm_pilot_install_without_rule_seconds"] = stock.seconds
    state = dump_cluster_state("helm")
    if not result.check(
        "helm_pilot_install", stock.returncode == 0, f"exit {stock.returncode}\n{tail(stock.stdout + stock.stderr)}\n{state}"
    ):
        return
    forward, base = port_forward_api()
    try:
        time.sleep(3)
        assert_api(result, "helm_api", base, expect_write=True, headers=headers)
    finally:
        forward.terminate()
    helm_uninstall(result, "agent-bom", NAMESPACE)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--variant", required=True, choices=("compose", "helm"))
    parser.add_argument(
        "--images",
        default="auto",
        choices=IMAGE_MODES,
        help="local builds the API and UI images from this checkout; published uses the pinned tags; "
        "auto is published on a refs/tags/ ref and local otherwise",
    )
    args = parser.parse_args()
    result = LaneResult("deploy", args.variant)
    mode = resolve_image_mode(args.images, os.environ.get("GITHUB_REF", ""))
    result.measurements["image_mode"] = mode
    print(f"image mode: {mode} (requested {args.images})", flush=True)
    try:
        (run_compose if args.variant == "compose" else run_helm)(result, mode)
    except Exception as exc:  # noqa: BLE001 - a lane records its own failure before exiting
        result.check("lane_completed", False, f"{type(exc).__name__}: {exc}")
    finally:
        if args.variant == "helm":
            dump_cluster_state("helm-final")
            subprocess.run(["kind", "delete", "cluster", "--name", KIND_CLUSTER], capture_output=True)  # noqa: S603, S607
    return result.write()


if __name__ == "__main__":
    raise SystemExit(main())
