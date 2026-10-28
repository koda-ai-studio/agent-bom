"""Only the explicit shared audit backend permits overlapping gateway pods."""

import shutil
import subprocess

import pytest
import yaml

pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="requires Helm")


def render(**overrides):
    gateway = {
        "enabled": True,
        "replicas": 2,
        "auditBackend": "postgres",
        "controlPlaneDiscovery": {"url": "https://control.example"},
        "envFrom": [{"secretRef": {"name": "gateway-dedicated-credentials"}}],
        **overrides,
    }
    return subprocess.run(
        ["helm", "template", "audit-test", "deploy/helm/agent-bom", "-f", "-"],
        input=yaml.safe_dump({"gateway": gateway}),
        text=True,
        capture_output=True,
        check=False,
    )


def test_shared_backend_renders_two_replicas_without_shared_file_spool():
    result = render()
    assert result.returncode == 0, result.stderr
    deployment = next(
        item
        for item in yaml.safe_load_all(result.stdout)
        if item and item["kind"] == "Deployment" and item["metadata"]["name"].endswith("-gateway")
    )
    assert deployment["spec"]["replicas"] == 2
    assert deployment["spec"].get("strategy", {}).get("type") != "Recreate"
    env = deployment["spec"]["template"]["spec"]["containers"][0]["env"]
    assert {"name": "AGENT_BOM_GATEWAY_AUDIT_BACKEND", "value": "postgres"} in env


@pytest.mark.parametrize(
    "overrides",
    [
        {"auditBackend": "typo"},
        {"envFrom": []},
        {"controlPlaneDiscovery": {"url": ""}},
        {"persistence": {"enabled": True, "existingClaim": "shared-file"}},
        {"env": [{"name": "AGENT_BOM_GATEWAY_AUDIT_BACKEND", "value": "local"}]},
    ],
)
def test_shared_backend_rejects_ambiguous_or_missing_dependencies(overrides):
    assert render(**overrides).returncode != 0
