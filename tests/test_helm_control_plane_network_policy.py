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
    "api": {"listenerAttestation": {"fromSecret": True}, "envFrom": [{"secretRef": {"name": "test-auth"}}]},
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


def _render_external(component: str, service_type: str, network_policy: dict) -> subprocess.CompletedProcess[str]:
    control_plane = {**_CONTROL_PLANE, "networkPolicy": network_policy}
    control_plane[component] = {**control_plane.get(component, {}), "service": {"type": service_type}}
    return subprocess.run(
        ["helm", "template", "np", str(CHART), "--values", "-"],
        input=yaml.safe_dump({"controlPlane": control_plane}),
        text=True,
        capture_output=True,
        check=False,
    )


@pytest.mark.parametrize("component", ["api", "ui"])
@pytest.mark.parametrize("service_type", ["NodePort", "LoadBalancer"])
def test_external_service_without_admitted_sources_fails_rendering(component: str, service_type: str) -> None:
    result = _render_external(component, service_type, {})
    assert result.returncode != 0
    assert "controlPlane.networkPolicy.ingressCIDRs" in result.stderr
    assert service_type in result.stderr


@pytest.mark.parametrize(("component", "port"), [("api", 8422), ("ui", 3000)])
def test_ingress_cidrs_admit_external_sources_to_the_service_port_only(component: str, port: int) -> None:
    result = _render_external(component, "NodePort", {"ingressCIDRs": ["10.0.0.0/16", "192.168.0.0/24"]})
    assert result.returncode == 0, result.stderr
    docs = [doc for doc in yaml.safe_load_all(result.stdout) if doc and doc.get("kind") == "NetworkPolicy"]
    policy = next(doc for doc in docs if doc["spec"]["podSelector"]["matchLabels"]["app.kubernetes.io/component"] == component)
    rules = [rule for rule in policy["spec"]["ingress"] if any("ipBlock" in peer for peer in rule["from"])]
    assert rules == [
        {
            "from": [{"ipBlock": {"cidr": "10.0.0.0/16"}}, {"ipBlock": {"cidr": "192.168.0.0/24"}}],
            "ports": [{"port": port, "protocol": "TCP"}],
        }
    ]


def test_cluster_ip_services_admit_no_external_sources() -> None:
    policy = _policies({"controlPlane": _CONTROL_PLANE})["api"]
    assert not [peer for rule in policy["spec"]["ingress"] for peer in rule["from"] if "ipBlock" in peer]


def test_additional_ingress_counts_as_admitted_sources_and_a_disabled_policy_is_not_checked() -> None:
    rule = {"from": [{"ipBlock": {"cidr": "172.16.0.0/12"}}], "ports": [{"port": 8422, "protocol": "TCP"}]}
    assert _render_external("api", "NodePort", {"additionalIngress": [rule]}).returncode == 0
    assert _render_external("api", "LoadBalancer", {"enabled": False}).returncode == 0
