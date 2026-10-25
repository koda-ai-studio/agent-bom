"""The chart wires NVD_API_KEY only from an existing Kubernetes Secret, unset by default."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

CHART = Path(__file__).resolve().parents[1] / "deploy/helm/agent-bom"
pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")

_CONTROL_PLANE = {
    "enabled": True,
    "postgresSecrets": {
        "enabled": True,
        "appSecretRef": {"name": "test-db"},
        "maintenanceSecretRef": {"name": "test-maintenance"},
        "adminSecretRef": {"name": "test-admin"},
    },
}


def _render(extra: dict) -> list[dict]:
    result = subprocess.run(
        ["helm", "template", "nvd-key", str(CHART), "--values", "-"],
        input=yaml.safe_dump({"controlPlane": _CONTROL_PLANE, **extra}),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def _containers(objects: list[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for doc in objects:
        spec = doc.get("spec") or {}
        pod = (spec.get("jobTemplate") or {}).get("spec", spec).get("template", {}).get("spec", {})
        for container in pod.get("containers") or []:
            out[f"{doc['kind']}/{doc['metadata']['name']}/{container['name']}"] = container
    return out


def _nvd_entries(container: dict) -> list[dict]:
    return [entry for entry in container.get("env") or [] if entry["name"] == "NVD_API_KEY"]


def test_nvd_api_key_is_unset_by_default() -> None:
    containers = _containers(_render({}))
    assert containers, "chart rendered no containers"
    assert all(not _nvd_entries(c) for c in containers.values())


def test_nvd_api_key_reads_existing_secret_in_scanner_and_api() -> None:
    containers = _containers(_render({"nvdApiKey": {"existingSecret": {"name": "nvd-api", "key": "api-key"}}}))
    wired = {name: _nvd_entries(c) for name, c in containers.items() if _nvd_entries(c)}
    assert set(wired) == {"CronJob/agent-bom-scan/scanner", "Deployment/agent-bom-api/api"}
    for entries in wired.values():
        assert entries == [{"name": "NVD_API_KEY", "valueFrom": {"secretKeyRef": {"name": "nvd-api", "key": "api-key"}}}]


def test_values_never_carry_a_plaintext_nvd_key() -> None:
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    assert values["nvdApiKey"] == {"existingSecret": {"name": "", "key": "NVD_API_KEY"}}
