"""Every rendered probe sets an explicit timeout and failure threshold.

Without ``timeoutSeconds`` Kubernetes defaults to 1s, so a dependency stall
fails liveness and restarts healthy pods; an explicit budget keeps probe
behaviour a reviewed decision rather than an implicit default.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

CHART = Path(__file__).resolve().parents[1] / "deploy/helm/agent-bom"
pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")

_VALUES = {
    "monitor": {"enabled": True},
    "gateway": {
        "enabled": True,
        "replicas": 1,
        "persistence": {"enabled": True, "existingClaim": "gateway-audit"},
        "controlPlaneDiscovery": {"url": "https://control.example.test"},
    },
    "sidecarInjection": {"enabled": True},
    "controlPlane": {
        "enabled": True,
        "postgresSecrets": {
            "enabled": True,
            "appSecretRef": {"name": "test-db"},
            "maintenanceSecretRef": {"name": "test-maintenance"},
            "adminSecretRef": {"name": "test-admin"},
        },
    },
}


def _containers() -> list[tuple[str, dict]]:
    result = subprocess.run(
        ["helm", "template", "probe-timeouts", str(CHART), "--values", "-"],
        input=yaml.safe_dump(_VALUES),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    found = []
    for doc in yaml.safe_load_all(result.stdout):
        if not doc or doc.get("kind") not in {"Deployment", "DaemonSet", "StatefulSet"}:
            continue
        for container in doc["spec"]["template"]["spec"].get("containers", []):
            found.append((f"{doc['kind']}/{doc['metadata']['name']}/{container['name']}", container))
    return found


def test_rendered_workloads_cover_api_ui_gateway_injector_and_monitor():
    names = {name for name, _ in _containers()}
    for expected in ("agent-bom-api", "agent-bom-ui", "gateway", "sidecar-injector", "DaemonSet/"):
        assert any(expected in name for name in names), (expected, sorted(names))


def test_every_rendered_probe_has_explicit_timeout_and_failure_threshold():
    probes = 0
    for name, container in _containers():
        for probe_name in ("livenessProbe", "readinessProbe", "startupProbe"):
            probe = container.get(probe_name)
            if probe is None:
                continue
            probes += 1
            assert int(probe.get("timeoutSeconds", 0)) >= 2, (name, probe_name, probe)
            assert int(probe.get("failureThreshold", 0)) >= 1, (name, probe_name, probe)
    assert probes >= 10


def test_api_readiness_timeout_exceeds_the_server_readiness_budget():
    from agent_bom.api.readiness import READINESS_TIMEOUT_SECONDS

    api = next(container for name, container in _containers() if "agent-bom-api" in name)
    assert api["readinessProbe"]["timeoutSeconds"] > READINESS_TIMEOUT_SECONDS
    assert api["livenessProbe"]["httpGet"]["path"] == "/health"
