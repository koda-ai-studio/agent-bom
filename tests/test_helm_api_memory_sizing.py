"""The rendered API memory defaults and published sizing table must agree."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CHART = ROOT / "deploy/helm/agent-bom"
SIZING_DOC = ROOT / "site-docs/deployment/performance-and-sizing.md"

API_MEMORY_REQUEST = "512Mi"
API_MEMORY_LIMIT = "2Gi"


def _rendered_api_container() -> dict:
    result = subprocess.run(
        ["helm", "template", "api-sizing", str(CHART), "--values", "-"],
        input=yaml.safe_dump(
            {
                "controlPlane": {
                    "enabled": True,
                    "postgresSecrets": {
                        "enabled": True,
                        "appSecretRef": {"name": "test-db"},
                        "maintenanceSecretRef": {"name": "test-maintenance"},
                        "adminSecretRef": {"name": "test-admin"},
                    },
                }
            }
        ),
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    for doc in yaml.safe_load_all(result.stdout):
        if doc and doc.get("kind") == "Deployment" and doc["metadata"]["name"].endswith("-api"):
            containers = doc["spec"]["template"]["spec"]["containers"]
            assert len(containers) == 1, containers
            return containers[0]
    raise AssertionError("API deployment not rendered")


@pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
def test_rendered_api_container_carries_the_sized_memory_envelope():
    resources = _rendered_api_container()["resources"]
    assert resources["requests"]["memory"] == API_MEMORY_REQUEST
    assert resources["limits"]["memory"] == API_MEMORY_LIMIT


def test_values_file_defaults_match_the_sizing_table():
    values = yaml.safe_load((CHART / "values.yaml").read_text())
    api_resources = values["controlPlane"]["api"]["resources"]
    assert api_resources["requests"]["memory"] == API_MEMORY_REQUEST
    assert api_resources["limits"]["memory"] == API_MEMORY_LIMIT

    api_section = SIZING_DOC.read_text().split("### API", 1)[1].split("### UI", 1)[0]
    assert re.search(rf"requests:.*`{API_MEMORY_REQUEST}` memory", api_section), api_section
    assert re.search(rf"limits:.*`{API_MEMORY_LIMIT}` memory", api_section), api_section
