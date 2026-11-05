#!/usr/bin/env python3
"""Make container SARIF artifact locations acceptable to GitHub code scanning.

GitHub rejects a SARIF upload when a result URI uses ``docker://`` while the
checked-out source root uses ``file://``. Preserve the scanned image reference
in result properties, but point GitHub at the checked-in Dockerfile for source
rendering and deduplication.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

# Findings with no repository file; agent_bom.output.sarif_common.VIRTUAL_ARTIFACT_PREFIX.
_VIRTUAL_PREFIX = "agent-bom-findings/"


def _normalize_artifact_location(physical: dict[str, Any], result: dict[str, Any]) -> None:
    artifact = physical.get("artifactLocation")
    if not isinstance(artifact, dict):
        return
    uri = artifact.get("uri")
    if not isinstance(uri, str) or not uri.startswith(("docker://", _VIRTUAL_PREFIX)):
        return
    properties = result.setdefault("properties", {})
    if isinstance(properties, dict):
        image = uri if uri.startswith("docker://") else properties.get("scanned_artifact")
        if image:
            properties.setdefault("agent-bom:container_uri", image)
    artifact["uri"] = "Dockerfile"
    artifact["uriBaseId"] = "%SRCROOT%"


def _dockerfile_location() -> dict[str, Any]:
    return {"artifactLocation": {"uri": "Dockerfile", "uriBaseId": "%SRCROOT%"}}


def normalize_document(document: dict[str, Any]) -> dict[str, Any]:
    for run in document.get("runs", []):
        if not isinstance(run, dict):
            continue
        run.pop("automationDetails", None)
        for result in run.get("results", []):
            if not isinstance(result, dict):
                continue
            # GitHub rejects the whole upload ("expected a physical location")
            # when any result lacks one, so a logical-only or locationless
            # result is anchored to the checked-in image source.
            locations = result.get("locations")
            if not isinstance(locations, list) or not locations:
                result["locations"] = locations = [{}]
            for location in locations:
                if not isinstance(location, dict):
                    continue
                physical = location.get("physicalLocation")
                if not isinstance(physical, dict):
                    location["physicalLocation"] = _dockerfile_location()
                    continue
                _normalize_artifact_location(physical, result)
            # SARIF 2.1 permits logical-only related locations, but GitHub's
            # ingestion rejects them while building its related-location index.
            # Add checked-in source context without discarding the graph hop.
            for related in result.get("relatedLocations", []):
                if not isinstance(related, dict):
                    continue
                physical = related.get("physicalLocation")
                if not isinstance(physical, dict):
                    related["physicalLocation"] = _dockerfile_location()
                    continue
                _normalize_artifact_location(physical, result)
    return document


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)
    document = json.loads(args.path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise SystemExit("SARIF root must be an object")
    normalized = normalize_document(document)
    args.path.write_text(json.dumps(normalized, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
