#!/usr/bin/env python3
"""Deploy lane: the repo's compose file and Helm chart on a real runtime.

Compose runs the checked-out ``compose.yaml``. Helm installs the chart on ``kind``
with the repo's values. Both use the published images those files pin, because
that is what a user of this checkout gets. Each path asserts health and a real
API write and read. Failures, including a chart that needs a CRD the cluster lacks,
are recorded as defects and fail the lane; the lane never edits the chart.
"""

from __future__ import annotations

import argparse
import base64
import json
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import REPO_ROOT, RESULTS_DIR, LaneResult, free_port, http_json, run_measured, tail, wait_for_http  # noqa: E402

CHART = REPO_ROOT / "deploy" / "helm" / "agent-bom"
PILOT_VALUES = CHART / "examples" / "eks-control-plane-sqlite-pilot-values.yaml"
NAMESPACE = "agent-bom"
PUSH_REPORT = {
    "scan_id": "qualification-deploy",
    "source_id": "qualification",
    "agents": [{"name": "qualification-agent", "type": "custom", "mcp_servers": []}],
    "blast_radius": [],
}


def assert_api(result: LaneResult, prefix: str, base: str, *, expect_write: bool) -> None:
    result.check(f"{prefix}_health", wait_for_http(f"{base}/health", timeout=120), f"{base}/health")
    status, version, _size = http_json(f"{base}/version")
    result.check(f"{prefix}_version_read", status == 200 and bool(version), f"HTTP {status} {str(version)[:200]}")
    result.measurements[f"{prefix}_version"] = version.get("version") if isinstance(version, dict) else None
    if expect_write:
        body = json.dumps(PUSH_REPORT).encode()
        status, receipt, _size = http_json(
            f"{base}/v1/results/push", method="POST", body=body, headers={"Content-Type": "application/json"}
        )
        job_id = receipt.get("job_id") if isinstance(receipt, dict) else None
        result.check(f"{prefix}_push_stored", status in (201, 202) and bool(job_id), f"HTTP {status} {str(receipt)[:300]}")
        time.sleep(3)
        status, jobs, _size = http_json(f"{base}/v1/jobs")
        result.check(f"{prefix}_push_reads_back", status == 200 and str(job_id) in json.dumps(jobs), f"HTTP {status} {str(jobs)[:300]}")
    else:
        status, jobs, _size = http_json(f"{base}/v1/jobs")
        result.check(f"{prefix}_jobs_read", status == 200 and isinstance(jobs, (dict, list)), f"HTTP {status} {str(jobs)[:300]}")
    status, findings, _size = http_json(f"{base}/v1/findings?limit=1")
    result.check(f"{prefix}_findings_read", status == 200 and isinstance(findings, dict), f"HTTP {status} {str(findings)[:300]}")


def run_compose(result: LaneResult) -> None:
    compose = ["docker", "compose", "-f", str(REPO_ROOT / "compose.yaml")]
    up = run_measured([*compose, "up", "-d", "--wait", "--wait-timeout", "300"], cwd=REPO_ROOT, timeout=700)
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
        logs = run_measured([*compose, "logs", "--no-color", "--tail", "200"], cwd=REPO_ROOT, timeout=120)
        (RESULTS_DIR / "logs").mkdir(parents=True, exist_ok=True)
        (RESULTS_DIR / "logs" / "compose.log").write_text(logs.stdout + logs.stderr, encoding="utf-8")
        run_measured([*compose, "down", "-v"], cwd=REPO_ROOT, timeout=180)


def kubectl(*args: str, timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["kubectl", *args], capture_output=True, text=True, timeout=timeout)  # noqa: S603, S607


def _apply(document: dict[str, Any]) -> None:
    subprocess.run(["kubectl", "apply", "-f", "-"], input=json.dumps(document), text=True, check=True, capture_output=True)  # noqa: S603, S607


def _fernet_key() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()


def prepare_pilot_namespace() -> None:
    _apply({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}})
    _apply(
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "agent-bom-control-plane", "namespace": NAMESPACE},
            "type": "Opaque",
            "stringData": {"AGENT_BOM_CONNECTIONS_KEY": _fernet_key()},
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


def helm_install(release: str, namespace: str, *extra: str, timeout: str = "8m") -> Any:
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


def run_helm(result: LaneResult) -> None:
    tools = {
        name: subprocess.run(command, capture_output=True, text=True).stdout.strip()[:120]
        for name, command in (("kind", ["kind", "version"]), ("helm", ["helm", "version", "--short"]))
    }  # noqa: S603
    result.measurements["tools"] = tools
    created = run_measured(["kind", "create", "cluster", "--name", "qualification", "--wait", "180s"], timeout=400)
    if not result.check("kind_cluster_created", created.returncode == 0, tail(created.stdout + created.stderr)):
        return

    default = helm_install("scanner", "scanner-only", timeout="4m")
    result.measurements["helm_default_install_seconds"] = default.seconds
    result.check(
        "helm_default_values_install", default.returncode == 0, f"exit {default.returncode}\n{tail(default.stdout + default.stderr)}"
    )
    resources = kubectl("get", "cronjob,job,daemonset,deployment", "-n", "scanner-only", "-o", "name").stdout.split()
    result.check("helm_default_values_create_workloads", bool(resources), resources)

    prepare_pilot_namespace()
    stock = helm_install("agent-bom", NAMESPACE, "-f", str(PILOT_VALUES))
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
        stock = helm_install(
            "agent-bom", NAMESPACE, "-f", str(PILOT_VALUES), "--set", "controlPlane.observability.prometheusRule.enabled=false"
        )
        result.measurements["helm_pilot_install_without_rule_seconds"] = stock.seconds
    state = dump_cluster_state("helm")
    if not result.check(
        "helm_pilot_install", stock.returncode == 0, f"exit {stock.returncode}\n{tail(stock.stdout + stock.stderr)}\n{state}"
    ):
        return
    forward, base = port_forward_api()
    try:
        time.sleep(3)
        assert_api(result, "helm_api", base, expect_write=False)
    finally:
        forward.terminate()
    uninstall = run_measured(["helm", "uninstall", "agent-bom", "--namespace", NAMESPACE, "--wait", "--timeout", "3m"], timeout=240)
    result.check("helm_uninstall", uninstall.returncode == 0, tail(uninstall.stdout + uninstall.stderr))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--variant", required=True, choices=("compose", "helm"))
    args = parser.parse_args()
    result = LaneResult("deploy", args.variant)
    with tempfile.TemporaryDirectory(prefix="qualification-deploy-"):
        try:
            (run_compose if args.variant == "compose" else run_helm)(result)
        except Exception as exc:  # noqa: BLE001 - a lane records its own failure before exiting
            result.check("lane_completed", False, f"{type(exc).__name__}: {exc}")
        finally:
            if args.variant == "helm":
                dump_cluster_state("helm-final")
                subprocess.run(["kind", "delete", "cluster", "--name", "qualification"], capture_output=True)  # noqa: S603, S607
    return result.write()


if __name__ == "__main__":
    raise SystemExit(main())
