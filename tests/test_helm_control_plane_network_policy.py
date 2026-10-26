"""The control-plane API and UI accept traffic only from their namespace and the ingress controller, not the whole cluster."""

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


def _policies(values: dict) -> dict[str, dict]:
    result = subprocess.run(
        ["helm", "template", "np", str(CHART), "--values", "-"],
        input=yaml.safe_dump(values),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    docs = [doc for doc in yaml.safe_load_all(result.stdout) if doc and doc.get("kind") == "NetworkPolicy"]
    return {doc["spec"]["podSelector"]["matchLabels"].get("app.kubernetes.io/component", ""): doc for doc in docs}


@pytest.mark.parametrize("component", ["api", "ui"])
def test_control_plane_pods_are_not_reachable_from_every_namespace(component: str) -> None:
    policy = _policies({"controlPlane": _CONTROL_PLANE})[component]
    assert policy["spec"]["policyTypes"] == ["Ingress"]
    peers = [peer for rule in policy["spec"]["ingress"] for peer in rule["from"]]
    assert {"podSelector": {}} in peers
    assert {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "ingress-nginx"}}} in peers
    assert all(peer.get("namespaceSelector") != {} for peer in peers)


def test_operators_can_widen_or_disable_the_policy() -> None:
    values = {"controlPlane": {**_CONTROL_PLANE, "networkPolicy": {"ingressNamespaces": ["traefik"], "additionalIngress": []}}}
    peers = [peer for rule in _policies(values)["api"]["spec"]["ingress"] for peer in rule["from"]]
    assert {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "traefik"}}} in peers
    disabled = {"controlPlane": {**_CONTROL_PLANE, "networkPolicy": {"enabled": False}}}
    assert "api" not in _policies(disabled)
