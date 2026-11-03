"""Advisories on a registry-selected version are review candidates, not findings.

A manifest range with no lockfile or installed copy has no installed version.
The resolver records the version a fresh install would select from the
registry (``resolved_from_registry`` + ``floating_reference``); an advisory
matched against it says "the newest matching release is affected", not "your
dependency is". ``scan`` moves such matches to ``Package.possibly_affected``
(reason ``registry_selected_version``, tier ``unverified_range``) so they are
shown on every surface but never counted as vulnerabilities and never trip
``--fail-on-severity``. Malicious-package advisories (``MAL-``) stay findings.

``AGENT_BOM_INCLUDE_RANGE_RESOLVED=1`` keeps them as findings. ``check`` of a
named package keeps them because the selected version is the one asked about.
"""

from __future__ import annotations

from typing import Any

from agent_bom.advisory_ids import MATCH_CONFIDENCE_UNVERIFIED_RANGE
from agent_bom.core.settings import env_flag
from agent_bom.models import Package, Vulnerability

REGISTRY_SELECTED_VERSION = "registry_selected_version"
INCLUDE_ENV = "AGENT_BOM_INCLUDE_RANGE_RESOLVED"


def include_registry_selected() -> bool:
    return env_flag(INCLUDE_ENV)


def is_registry_selected(pkg: Package) -> bool:
    """The version came from a registry lookup for a non-exact declaration."""
    return bool(pkg.resolved_from_registry and pkg.floating_reference)


def _candidate(pkg: Package, vuln: Vulnerability) -> dict[str, Any]:
    declared = pkg.declared_version or "an unpinned reference"
    return {
        "id": vuln.id,
        "verdict": "possibly_affected",
        "reason": REGISTRY_SELECTED_VERSION,
        "detail": (
            f"{pkg.name} is declared as {declared} with no lockfile or installed version; {pkg.version} is the "
            "version a fresh install would select from the registry, not a confirmed installed version. "
            "Lock or pin the dependency to confirm."
        ),
        "severity": str(getattr(vuln.severity, "value", vuln.severity) or "unknown").lower(),
        "cvss_score": vuln.cvss_score,
        "summary": vuln.summary,
        "aliases": list(vuln.aliases),
        "source": ",".join(vuln.advisory_sources) or "osv",
        "upstream_fixed_version": vuln.fixed_version,
        "match_confidence_tier": MATCH_CONFIDENCE_UNVERIFIED_RANGE,
    }


def demote_registry_selected(packages: list[Package]) -> int:
    """Move advisories on registry-selected versions into candidates; return how many moved."""
    if include_registry_selected():
        return 0
    moved = 0
    for pkg in packages:
        if not is_registry_selected(pkg):
            continue
        candidates = [v for v in pkg.vulnerabilities if not v.id.upper().startswith("MAL-")]
        if not candidates:
            continue
        recorded = {entry["id"] for entry in pkg.possibly_affected}
        for vuln in candidates:
            if vuln.id not in recorded:
                pkg.possibly_affected.append(_candidate(pkg, vuln))
                recorded.add(vuln.id)
        pkg.vulnerabilities = [v for v in pkg.vulnerabilities if v.id.upper().startswith("MAL-")]
        moved += len(candidates)
    return moved
