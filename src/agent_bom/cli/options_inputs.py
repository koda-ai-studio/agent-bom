"""Repeatable scan input options.

Each input flag either accepts every repeated value (``multiple=True``, and the
scan pipeline consumes them all) or names one target and rejects a repeat;
none silently keeps only the last value.
"""

from __future__ import annotations

import click

from agent_bom.cli.options_helpers import _single_value

PROJECT_OPTION = click.option(
    "--project",
    "-p",
    "project",
    multiple=True,
    type=click.Path(exists=True),
    help="Project directory to scan. Repeatable: every project is scanned into one report.",
)

REPO_OPTION = click.option(
    "--repo",
    "repo_url",
    type=str,
    multiple=True,
    callback=_single_value("--repo"),
    metavar="URL",
    help=(
        "Public git repository URL to clone and scan (e.g. "
        "https://github.com/org/repo). Shallow, static, read-only: the repo is "
        "cloned to a temp dir, scanned without executing its code, then deleted. "
        "Mutually exclusive with --project/-p."
    ),
)

CONFIG_DIR_OPTION = click.option(
    "--config-dir",
    "config_dir",
    multiple=True,
    type=click.Path(exists=True),
    help="Custom agent config directory to scan. Repeatable.",
)

INVENTORY_OPTION = click.option(
    "--inventory",
    "inventory",
    multiple=True,
    type=str,
    help="Inventory file (JSON or CSV). Use '-' for stdin. Repeatable: agents from every file are merged.",
)

SBOM_OPTION = click.option(
    "--sbom",
    "sbom_file",
    multiple=True,
    type=click.Path(exists=True),
    help="Existing SBOM file to ingest (CycloneDX or SPDX JSON from Syft/Grype/Trivy). Repeatable.",
)

SBOM_NAME_OPTION = click.option(
    "--sbom-name",
    "sbom_name",
    multiple=True,
    metavar="NAME",
    help=(
        "Label for the SBOM resource (e.g. 'prod-api-01', 'nginx:1.25'). Auto-detected from SBOM metadata if "
        "omitted. With repeated --sbom, give one --sbom-name per --sbom (paired in order)."
    ),
)

CORRELATE_OPTION = click.option(
    "--correlate",
    "correlate_log",
    type=click.Path(exists=True),
    multiple=True,
    callback=_single_value("--correlate"),
    metavar="AUDIT_LOG",
    help="Cross-reference scan results with proxy audit log (JSONL) to identify which vulnerable tools were actually called.",
)

EXTERNAL_SCAN_OPTION = click.option(
    "--external-scan",
    "external_scan_path",
    type=click.Path(exists=True),
    multiple=True,
    help=(
        "Path to an existing tool-agnostic report: SARIF 2.x, CycloneDX or SPDX JSON, Trivy/Grype/Syft JSON, "
        "Prowler JSON-OCSF, or AWS Security Hub ASFF. Adds its evidence without executing the producing tool. "
        "SARIF dependency results (CVE/GHSA rule ids) attach to the real package@version, other SARIF results "
        "stay SAST findings with file:line; a CycloneDX/SPDX SBOM without vulnerabilities is ingested like --sbom. Repeatable."
    ),
)
