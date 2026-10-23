"""Opt-in vulnerability lookups for installed packages through the shared package scanner."""

from __future__ import annotations

import asyncio
from typing import Any

MAX_CHECKED = 50
_ECOSYSTEMS = {"npm", "pypi", "cargo", "go"}


async def _check_all(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from agent_bom.models import Package
    from agent_bom.scanners import ScanOptions, scan_packages

    targets = [row for row in packages if row["ecosystem"] in _ECOSYSTEMS][:MAX_CHECKED]
    scanned = [Package(name=row["name"], version=row["version"] or "latest", ecosystem=row["ecosystem"]) for row in targets]
    failed = False
    try:
        await scan_packages(scanned, options=ScanOptions(offline=False))
    except Exception:  # broad-except: a failed lookup is reported per package, never as clean
        failed = True
    return [
        {
            "ecosystem": row["ecosystem"],
            "name": row["name"],
            "checked_version": package.version,
            "scan_failed": failed,
            "vulnerabilities": [
                {"id": vuln.id, "severity": str(getattr(vuln.severity, "value", vuln.severity)).lower(), "is_kev": bool(vuln.is_kev)}
                for vuln in package.vulnerabilities
            ],
        }
        for row, package in zip(targets, scanned)
    ]


def check_installed_packages(packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Network lookup; only runs when the caller asked for it."""
    return asyncio.run(_check_all(packages))
