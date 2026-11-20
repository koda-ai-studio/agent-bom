"""The release self-SBOM names the product it describes.

`cyclonedx-py environment` without a root component wrote no
`metadata.component`, so the documented `jq '.metadata.component.name'`
check printed null and consumers could not tell what the SBOM was for.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _sbom_run() -> str:
    workflow = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
    steps = workflow["jobs"]["sbom"]["steps"]
    runs = [step.get("run", "") for step in steps if "agent-bom-sbom.cdx.json" in step.get("run", "")]
    assert len(runs) == 1, "exactly one step writes the release SBOM"
    return runs[0]


def test_release_sbom_declares_agent_bom_as_its_root_component() -> None:
    run = _sbom_run()
    assert re.search(r"cyclonedx-py environment\b[^\n]*--pyproject pyproject\.toml", run)
    assert ".metadata.component.purl = $purl" in run
    assert "pkg:pypi/agent-bom@" in run


def test_release_sbom_fails_closed_without_name_version_and_purl() -> None:
    run = _sbom_run()
    assert "set -euo pipefail" in run
    check = re.search(r"jq -e '([^']+)' agent-bom-sbom\.cdx\.json", run)
    assert check, "the step must assert the root component it wrote"
    for field in ('.name == "agent-bom"', ".version", ".purl"):
        assert field in check.group(1)


def test_documented_sbom_inspection_reads_fields_the_release_writes() -> None:
    doc = (ROOT / "docs/RELEASE_VERIFICATION.md").read_text(encoding="utf-8")
    section = doc.split("## Inspect the self-SBOM", 1)[1].split("\n## ", 1)[0]
    assert "jq -r '.metadata.component.name, .metadata.component.version, .metadata.component.purl' agent-bom-sbom.cdx.json" in section
