"""Image-scan SARIF must give every result a physical location GitHub can ingest."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from jsonschema import Draft7Validator

from agent_bom.models import Agent, AIBOMReport, BlastRadius, Package, Severity, Vulnerability
from agent_bom.output.sarif import to_sarif

ROOT = Path(__file__).resolve().parents[1]
IMAGE_URI = "docker://sha256:2f3e5d0c9a4b7e6f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f"
PURL = "pkg:apk/alpine/zlib@1.3.1-r0"


def _image_report(config_path: str = IMAGE_URI, name: str = f"image:{IMAGE_URI.removeprefix('docker://')}") -> AIBOMReport:
    vuln = Vulnerability(id="CVE-2026-85091", summary="zlib overflow", severity=Severity.HIGH, fixed_version="1.3.2-r0")
    pkg = Package(name="zlib", version="1.3.1-r0", ecosystem="apk", purl=PURL, vulnerabilities=[vuln])
    # Installed-package evidence lives inside the image, never in the checkout.
    pkg.version_evidence = [{"type": "package_db", "source_file": "/lib/apk/db/installed"}]
    agent = Agent(name=name, agent_type="custom", config_path=config_path, mcp_servers=[])
    blast = BlastRadius(
        vulnerability=vuln, package=pkg, affected_agents=[agent], affected_servers=[], exposed_credentials=[], exposed_tools=[]
    )
    return AIBOMReport(agents=[agent], blast_radii=[blast])


def _normalizer():
    spec = importlib.util.spec_from_file_location(
        "normalize_container_sarif_for_github", ROOT / "scripts/normalize_container_sarif_for_github.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _primary_uris(document: dict) -> list[str | None]:
    return [
        (location.get("physicalLocation") or {}).get("artifactLocation", {}).get("uri")
        for run in document["runs"]
        for result in run["results"]
        for location in (result.get("locations") or [{}])
    ]


def test_every_image_scan_result_has_a_physical_location() -> None:
    document = to_sarif(_image_report())
    results = document["runs"][0]["results"]

    assert [result["ruleId"] for result in results] == ["CVE-2026-85091"]
    assert all(_primary_uris(document)), _primary_uris(document)
    location = results[0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"] == {"uri": IMAGE_URI}
    assert "region" not in location["physicalLocation"]  # no invented line inside an image
    assert location["logicalLocations"] == [{"fullyQualifiedName": PURL}]
    schema = json.loads((ROOT / "tests/fixtures/sarif-schema-2.1.0.json").read_text())
    Draft7Validator(schema).validate(document)


def test_tarball_scan_location_names_the_tarball_without_its_local_directory() -> None:
    report = _image_report(config_path="oci-tar:///home/runner/work/private dir/app image.tar", name="image-tar:app image.tar")
    location = to_sarif(report)["runs"][0]["results"][0]["locations"][0]

    assert location["physicalLocation"]["artifactLocation"] == {"uri": "oci-tar://app%20image.tar"}
    assert "runner" not in json.dumps(location)


def test_normalized_image_sarif_points_github_at_the_dockerfile() -> None:
    normalized = _normalizer().normalize_document(to_sarif(_image_report()))
    result = normalized["runs"][0]["results"][0]

    assert _primary_uris(normalized) == ["Dockerfile"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    assert result["properties"]["agent-bom:container_uri"] == IMAGE_URI
    assert result["locations"][0]["logicalLocations"] == [{"fullyQualifiedName": PURL}]


def test_normalizer_backfills_logical_only_and_locationless_results() -> None:
    document = {
        "runs": [
            {
                "results": [
                    {"ruleId": "CVE-1", "locations": [{"logicalLocations": [{"fullyQualifiedName": PURL}]}]},
                    {"ruleId": "finding/X", "locations": []},
                    {"ruleId": "finding/Y"},
                ]
            }
        ]
    }

    normalized = _normalizer().normalize_document(document)

    assert _primary_uris(normalized) == ["Dockerfile", "Dockerfile", "Dockerfile"]
    first = normalized["runs"][0]["results"][0]["locations"][0]
    assert first["logicalLocations"] == [{"fullyQualifiedName": PURL}]
