"""Render the agent-bom chart for tests."""

from __future__ import annotations

import copy
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

CHART = Path(__file__).resolve().parents[1] / "deploy/helm/agent-bom"
requires_helm = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")

# A clustered API must attest requests; these declare that a Secret in envFrom supplies it.
ATTESTED_API: dict[str, Any] = {"listenerAttestation": {"fromSecret": True}, "envFrom": [{"secretRef": {"name": "test-auth"}}]}
ATTESTED_API_SET_ARGS = (
    "--set",
    "controlPlane.api.listenerAttestation.fromSecret=true",
    "--set",
    "controlPlane.api.envFrom[0].secretRef.name=test-auth",
)

# A clustered control plane on Postgres whose API attests requests through a trusted proxy.
CONTROL_PLANE: dict[str, Any] = {
    "enabled": True,
    "postgresSecrets": {
        "enabled": True,
        "appSecretRef": {"name": "test-db"},
        "maintenanceSecretRef": {"name": "test-maintenance"},
        "adminSecretRef": {"name": "test-admin"},
    },
    "api": ATTESTED_API,
}


def merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def render(control_plane: dict[str, Any], **top_level: Any) -> subprocess.CompletedProcess[str]:
    values = {"controlPlane": merge(CONTROL_PLANE, control_plane), **top_level}
    return subprocess.run(
        ["helm", "template", "agent-bom", str(CHART), "--values", "-"],
        input=yaml.safe_dump(values),
        text=True,
        capture_output=True,
        check=False,
    )


def objects(result: subprocess.CompletedProcess[str]) -> list[dict[str, Any]]:
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def find(docs: list[dict[str, Any]], kind: str, name: str) -> dict[str, Any]:
    return next(doc for doc in docs if doc["kind"] == kind and doc["metadata"]["name"] == name)


def container_env(workload: dict[str, Any]) -> dict[str, str]:
    container = workload["spec"]["template"]["spec"]["containers"][0]
    return {entry["name"]: entry.get("value", "<from>") for entry in container.get("env", [])}
