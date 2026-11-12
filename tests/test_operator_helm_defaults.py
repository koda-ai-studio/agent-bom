"""A default chart installs without optional monitoring CRDs."""

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests._helm_render import ATTESTED_API_SET_ARGS

CHART = Path(__file__).resolve().parents[1] / "deploy/helm/agent-bom"


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm is not installed")
@pytest.mark.parametrize("enabled", [False, True])
def test_prometheus_rules_are_explicitly_opt_in(enabled):
    command = [
        "helm",
        "template",
        "operator-defaults",
        str(CHART),
        "--set",
        "controlPlane.enabled=true",
        "--set",
        "controlPlane.postgresSecrets.enabled=true",
        "--set",
        "controlPlane.postgresSecrets.appSecretRef.name=test-db",
        "--set",
        "controlPlane.postgresSecrets.maintenanceSecretRef.name=test-maintenance",
        "--set",
        "controlPlane.postgresSecrets.adminSecretRef.name=test-admin",
        *ATTESTED_API_SET_ARGS,
    ]
    if enabled:
        command.extend(["--set", "controlPlane.observability.prometheusRule.enabled=true"])
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    rules = [doc for doc in yaml.safe_load_all(result.stdout) if doc and doc.get("kind") == "PrometheusRule"]
    assert bool(rules) is enabled
