"""Possibly-affected advisories across every report surface.

``Package.possibly_affected`` holds advisories the scan could not decide (a
distro package of a CPE product with no distro record). Each output renders
them from the rows built here so JSON, SARIF, CycloneDX, HTML and the terminal
agree. They are review items: never vulnerabilities, never counted in severity
totals, never a ``--fail-on-severity`` trigger.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import quote

from rich.markup import escape

SARIF_RULE_ID = "agent-bom/possibly-affected"
_NVD_URL = "https://nvd.nist.gov/vuln/detail/"


def _image_uri(config_path: str) -> str | None:
    if config_path.startswith("docker://"):
        return config_path
    if config_path.startswith("oci-tar://"):
        name = Path(config_path.removeprefix("oci-tar://")).name
        return f"oci-tar://{quote(name)}" if name else None
    return None


def _package_identity(pkg: Any) -> dict[str, Any]:
    return {
        "name": pkg.name,
        "version": pkg.version,
        "ecosystem": pkg.ecosystem,
        "purl": pkg.purl,
        "stable_id": pkg.stable_id,
        "source_package": pkg.source_package,
        "distro_name": pkg.distro_name,
        "distro_version": pkg.distro_version,
    }


def possibly_affected_rows(report: Any) -> list[dict[str, Any]]:
    """One row per (package, advisory), naming every agent that carries the package."""
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for agent in getattr(report, "agents", None) or []:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                for entry in getattr(pkg, "possibly_affected", None) or []:
                    row = rows.setdefault(
                        (pkg.stable_id, str(entry["id"])),
                        {**entry, "package": _package_identity(pkg), "agents": [], "images": []},
                    )
                    if agent.name not in row["agents"]:
                        row["agents"].append(agent.name)
                    image = _image_uri(str(getattr(agent, "config_path", "") or ""))
                    if image and image not in row["images"]:
                        row["images"].append(image)
    return sorted(rows.values(), key=lambda row: (str(row["id"]), row["package"]["name"], row["package"]["version"]))


def json_section(report: Any) -> dict[str, Any]:
    rows = possibly_affected_rows(report)
    return {"possibly_affected": rows} if rows else {}


def _label(row: dict[str, Any]) -> str:
    return f"{row['package']['name']} {row['package']['version']}"


# --- SARIF ----------------------------------------------------------------------------------


def _sarif_rule() -> dict[str, Any]:
    text = "A distro package ships a product an advisory names, and no distro record decides it; verify the distribution's advisory."
    return {
        "id": SARIF_RULE_ID,
        "name": "PossiblyAffectedDistroPackage",
        "shortDescription": {"text": "Possibly affected: verify the distribution's advisory"},
        "fullDescription": {"text": text},
        "defaultConfiguration": {"level": "note"},
        "help": {"text": text + " Possibly-affected results are not counted as vulnerabilities and do not trip severity gates."},
        "properties": {"tags": ["security", "possibly-affected"]},
    }


def _sarif_result(row: dict[str, Any]) -> dict[str, Any]:
    purl = row["package"]["purl"] or f"pkg:{row['package']['ecosystem']}/{row['package']['name']}@{row['package']['version']}"
    logical = {"logicalLocations": [{"fullyQualifiedName": purl}]}
    location = {"physicalLocation": {"artifactLocation": {"uri": row["images"][0]}}, **logical} if row["images"] else logical
    fingerprint = hashlib.sha256(f"{SARIF_RULE_ID}:{row['id']}:{row['package']['stable_id']}".encode()).hexdigest()
    fix = f" Upstream fix: {row['upstream_fixed_version']}." if row.get("upstream_fixed_version") else ""
    return {
        "ruleId": SARIF_RULE_ID,
        "level": "note",
        "kind": "review",
        "message": {"text": f"{row['id']} possibly affects {_label(row)}: {row['detail']} (reason: {row['reason']}).{fix}"},
        "fingerprints": {"agent-bom/v1": fingerprint},
        "locations": [location],
        "properties": {
            "cve_id": row["id"],
            "verdict": row["verdict"],
            "reason": row["reason"],
            "detail": row["detail"],
            "package": row["package"]["name"],
            "package_version": row["package"]["version"],
            "purl": purl,
            "cpe_product": row.get("cpe_product"),
            "upstream_version": row.get("upstream_version"),
            "upstream_fixed_version": row.get("upstream_fixed_version"),
            "advisory_severity": row.get("severity"),
            "affected_agents": list(row["agents"]),
        },
    }


def add_sarif_results(rules: list[dict[str, Any]], results: list[dict[str, Any]], report: Any) -> None:
    rows = possibly_affected_rows(report)
    if not rows:
        return
    rules.append(_sarif_rule())
    results.extend(_sarif_result(row) for row in rows)


# --- CycloneDX ------------------------------------------------------------------------------


def cyclonedx_vulnerabilities(report: Any, package_ref: Callable[[str], str]) -> list[dict[str, Any]]:
    """``analysis.state: in_triage`` entries, one per advisory, affecting each undecided package."""
    by_id: dict[str, dict[str, Any]] = {}
    for row in possibly_affected_rows(report):
        entry = by_id.get(row["id"])
        if entry is None:
            entry = by_id[row["id"]] = {
                "id": row["id"],
                "source": {"name": "NVD", "url": f"{_NVD_URL}{row['id']}"},
                "description": row.get("summary") or "",
                "affects": [],
                "analysis": {"state": "in_triage", "detail": ""},
                "properties": [
                    {"name": "agent-bom:verdict", "value": row["verdict"]},
                    {"name": "agent-bom:reason", "value": row["reason"]},
                    {"name": "agent-bom:advisory-severity", "value": str(row.get("severity") or "unknown")},
                ],
            }
        entry["affects"].append({"ref": package_ref(f"pkg-{row['package']['stable_id']}")})
        details = [part for part in entry["analysis"]["detail"].split("\n") if part]
        if row["detail"] not in details:
            entry["analysis"]["detail"] = "\n".join([*details, row["detail"]])
    return [by_id[key] for key in sorted(by_id)]


# --- terminal -------------------------------------------------------------------------------


def print_possibly_affected(report: Any, console: Any, limit: int = 20) -> None:
    rows = possibly_affected_rows(report)
    if not rows:
        return
    console.print()
    console.print(f"[bold yellow]Possibly affected — verify distro advisory ({len(rows)})[/bold yellow]")
    console.print("  [dim]Review items, not counted as vulnerabilities and never a --fail-on-severity trigger.[/dim]")
    for row in rows[:limit]:
        fix = f" · upstream fix {row['upstream_fixed_version']}" if row.get("upstream_fixed_version") else ""
        console.print(f"  [yellow]?[/yellow] [bold]{escape(row['id'])}[/bold] {escape(_label(row))} — {escape(row['detail'])}{escape(fix)}")
    if len(rows) > limit:
        console.print(f"  [dim]... {len(rows) - limit} more in the JSON/SARIF/CycloneDX outputs[/dim]")
