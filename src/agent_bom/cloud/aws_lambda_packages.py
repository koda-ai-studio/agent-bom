"""Cloud aws lambda packages helpers."""

from __future__ import annotations

import json
import zipfile
from email.parser import Parser as EmailParser
from pathlib import Path
from typing import Any

from agent_bom.cloud.archive_limits import MAX_ARCHIVE_BYTES, ArchiveLimitError, read_member, validate_archive
from agent_bom.cloud.serverless_zip import packages_from_zip_bytes
from agent_bom.models import Package
from agent_bom.security import sanitize_text

from .normalization import (
    build_package_purl,
)

# ---------------------------------------------------------------------------
# Lambda package extraction
# ---------------------------------------------------------------------------


def _extract_lambda_packages(
    session: Any,
    lambda_arn: str,
    region: str,
    warnings: list[str],
) -> list[Package]:
    """Extract packages from a Lambda function's layers and deployment package."""
    lambda_client = session.client("lambda", region_name=region)
    packages: list[Package] = []
    get_function = getattr(lambda_client, "get_function", None)
    if not callable(get_function):
        return packages

    try:
        func_config = get_function(FunctionName=lambda_arn)
        config = func_config.get("Configuration", {})
        runtime = config.get("Runtime", "")

        # Determine ecosystem from runtime
        ecosystem = "pypi" if "python" in runtime else "npm" if "node" in runtime else "unknown"

        # Extract from layers
        for layer in config.get("Layers", []):
            layer_arn = layer.get("Arn", "")
            try:
                layer_packages = _packages_from_layer(lambda_client, layer_arn, ecosystem)
                packages.extend(layer_packages)
            except Exception as exc:
                warnings.append(
                    f"Could not extract packages from Lambda layer {layer_arn}: {sanitize_text(exc)}; package coverage incomplete."
                )

        # Extract from the function's own deployment package. Most functions
        # bundle their dependencies inline (vendored into the zip) rather than
        # in a layer, so scanning layers alone misses the common case.
        code_location = func_config.get("Code", {}).get("Location", "")
        if code_location and ecosystem in ("pypi", "npm"):
            try:
                from agent_bom.http_client import fetch_bytes

                code_bytes = fetch_bytes(code_location, timeout=60, max_bytes=MAX_ARCHIVE_BYTES)
                packages.extend(packages_from_zip_bytes(code_bytes, ecosystem=ecosystem))
            except Exception as exc:
                warnings.append(
                    f"Could not extract packages from Lambda deployment package {lambda_arn}: "
                    f"{sanitize_text(exc)}; package coverage incomplete."
                )

    except Exception as exc:
        warnings.append(f"Could not get Lambda function {lambda_arn}: {sanitize_text(exc)}; package coverage incomplete.")

    return _dedupe_packages(packages)


def _packages_from_layer(
    lambda_client: Any,
    layer_arn: str,
    ecosystem: str,
) -> list[Package]:
    """Download and parse a Lambda layer to extract package metadata."""
    packages: list[Package] = []

    # Get the layer version (ARN includes version)
    response = lambda_client.get_layer_version_by_arn(Arn=layer_arn)
    download_url = response.get("Content", {}).get("Location", "")
    if not download_url:
        return packages

    # Download the layer zip
    from agent_bom.http_client import fetch_bytes

    layer_bytes = fetch_bytes(download_url, timeout=60, max_bytes=MAX_ARCHIVE_BYTES)
    return packages_from_zip_bytes(layer_bytes, ecosystem=ecosystem)


def _dedupe_packages(packages: list[Package]) -> list[Package]:
    """Drop duplicate packages when the same dep appears in a layer and the
    function's own zip (or across multiple layers)."""
    seen: set[tuple[str, str, str]] = set()
    unique: list[Package] = []
    for pkg in packages:
        key = (pkg.ecosystem, pkg.name.lower(), pkg.version)
        if key in seen:
            continue
        seen.add(key)
        unique.append(pkg)
    return unique


def _parse_python_packages_from_zip(zf: zipfile.ZipFile) -> list[Package]:
    """Extract Python package info from .dist-info/METADATA files in a zip."""
    packages: list[Package] = []
    seen: set[str] = set()

    validate_archive(zf)
    for member in zf.infolist():
        name = member.filename
        if name.endswith(".dist-info/METADATA"):
            try:
                metadata_text = read_member(zf, member).decode("utf-8", errors="replace")
                parser = EmailParser()
                msg = parser.parsestr(metadata_text)
                pkg_name = msg.get("Name", "")
                pkg_version = msg.get("Version", "")
                if pkg_name and pkg_version and pkg_name.lower() not in seen:
                    seen.add(pkg_name.lower())
                    packages.append(
                        Package(
                            name=pkg_name,
                            version=pkg_version,
                            ecosystem="pypi",
                            purl=build_package_purl(ecosystem="pypi", name=pkg_name, version=pkg_version),
                        )
                    )
            except Exception as exc:
                raise ArchiveLimitError("Deployment archive metadata could not be inspected") from exc

    return packages


def _parse_node_packages_from_zip(zf: zipfile.ZipFile) -> list[Package]:
    """Extract Node.js package info from node_modules/*/package.json in a zip."""
    packages: list[Package] = []
    seen: set[str] = set()

    validate_archive(zf)
    for member in zf.infolist():
        name = member.filename
        parts = Path(name).parts
        if len(parts) >= 3 and parts[-1] == "package.json" and "node_modules" in parts:
            try:
                data = json.loads(read_member(zf, member))
                pkg_name = data.get("name", "")
                pkg_version = data.get("version", "")
                if pkg_name and pkg_version and pkg_name not in seen:
                    seen.add(pkg_name)
                    packages.append(
                        Package(
                            name=pkg_name,
                            version=pkg_version,
                            ecosystem="npm",
                            purl=build_package_purl(ecosystem="npm", name=pkg_name, version=pkg_version),
                        )
                    )
            except Exception as exc:
                raise ArchiveLimitError("Deployment archive metadata could not be inspected") from exc

    return packages
