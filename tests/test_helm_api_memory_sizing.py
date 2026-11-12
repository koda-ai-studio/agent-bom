"""The rendered API memory defaults and published sizing table must agree."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests._helm_render import ATTESTED_API

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
                    "api": ATTESTED_API,
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


_UNITS = {"Ki": 1024, "Mi": 1024**2, "Gi": 1024**3}
_PERF_SOURCE = "scripts/qualification/performance.py"
_BASELINE = ROOT / "scripts/qualification/baseline.json"
_SIZING_SURFACES = (
    CHART / "values.yaml",
    SIZING_DOC,
    ROOT / "site-docs/deployment/control-plane-helm.md",
)


def _bytes(quantity: str) -> int:
    match = re.fullmatch(r"(\d+)(Ki|Mi|Gi)", quantity)
    assert match, quantity
    return int(match.group(1)) * _UNITS[match.group(2)]


def test_push_sizing_never_claims_a_fixed_body_multiple():
    """Measured peaks at 5,000 agents are over 100x the push body; an 8x rule undersizes pods."""
    for path in _SIZING_SURFACES:
        text = path.read_text().lower()
        for stale in ("8x the body", "eight times", "8 x that budget", "covers the 192 mib"):
            assert stale not in text, f"{path.relative_to(ROOT)} still says {stale!r}"


def test_sizing_doc_publishes_the_measured_table_and_its_source():
    assert (ROOT / _PERF_SOURCE).is_file()
    text = SIZING_DOC.read_text()
    assert _PERF_SOURCE in text
    assert _PERF_SOURCE in (CHART / "values.yaml").read_text()
    baseline = yaml.safe_load(_BASELINE.read_text())["metrics"]
    for backend, column in (("sqlite", "730 MB"), ("postgres", "789 MB")):
        measured = baseline[f"performance/{backend}/medium-1000-agents/api_peak_rss_mb"]
        assert column == f"{round(measured)} MB", (backend, measured)
    row = next(line for line in text.splitlines() if line.startswith("| 1,000 "))
    assert "730 MB" in row and "789 MB" in row
    row = next(line for line in text.splitlines() if line.startswith("| 5,000 "))
    assert "2.4 GB" in row and "4.1 GB" in row and "116,907" in row


def test_default_memory_limit_fits_the_measured_1000_agent_push():
    values = yaml.safe_load((CHART / "values.yaml").read_text())["controlPlane"]
    baseline = yaml.safe_load(_BASELINE.read_text())["metrics"]
    peak = max(baseline[f"performance/{b}/medium-1000-agents/api_peak_rss_mb"] for b in ("sqlite", "postgres")) * 1024**2
    for component in ("api", "worker"):
        limit = _bytes(values[component]["resources"]["limits"]["memory"])
        assert limit >= peak, f"{component} memory limit {limit} below the measured 1,000-agent peak {peak}"
