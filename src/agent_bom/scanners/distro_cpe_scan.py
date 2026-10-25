"""Scan-time verdicts for distro packages that ship an upstream CPE product.

An NVD CPE range (``php:php`` up to 8.2.35) names upstream releases. Debian's
``php8.2-cli 8.2.29-1~deb12u1`` carries upstream 8.2.29 but may hold a
backported fix, so the range can neither confirm nor clear it. When the
upstream release falls inside the range and no distro record in the local DB
covers that CVE for the package's release, the CVE is recorded on
``Package.possibly_affected`` with reason ``distro_backport_unverified``. It is
evidence to review, never a vulnerability: it is not counted and never trips a
severity gate. When a distro record exists, the distro feed decides through the
normal lookup path and nothing is recorded here.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable
from typing import Any

from agent_bom.db.lookup import cpe_lookup_package
from agent_bom.models import Package
from agent_bom.scanners.advisory_merge import advisory_keys
from agent_bom.scanners.cpe_distro_packages import CPE_DISTRO_PACKAGES, distro_ships_cpe_product
from agent_bom.scanners.distro_cpe_verdict import local_distro_verdict
from agent_bom.scanners.operator_advisory import DISTRO_BACKPORT_UNVERIFIED

POSSIBLY_AFFECTED = "possibly_affected"
_UPSTREAM = re.compile(r"^(?:\d+:)?(?P<upstream>.+?)(?:-[^-]*)?$")


def _package_row(pkg: Package) -> dict[str, Any]:
    return {
        "name": pkg.name,
        "version": pkg.version,
        "ecosystem": pkg.ecosystem,
        "purl": pkg.purl,
        "source_package": pkg.source_package,
        "distro_name": pkg.distro_name,
        "distro_version": pkg.distro_version,
    }


def upstream_version(version: str) -> str:
    """The upstream release a distro version carries: no epoch, revision or ``+dfsg``/``~`` suffix."""
    match = _UPSTREAM.match(version.strip())
    upstream = match.group("upstream") if match else version
    return re.split(r"[+~]", upstream, maxsplit=1)[0]


def shipped_cpe_product(pkg: Package) -> str | None:
    """The CPE product (``vendor:product``) a distro package ships, if mapped."""
    row = _package_row(pkg)
    return next((product for product in CPE_DISTRO_PACKAGES if distro_ships_cpe_product(product, row)), None)


def _detail(pkg: Package, product: str) -> str:
    return f"distro package {pkg.name} {pkg.version} ships {product.split(':', 1)[1]}; verify against the distribution's advisory"


def attach_possibly_affected(conn: sqlite3.Connection, pkg: Package, product: str) -> None:
    """Record NVD CPE CVEs the distro feed has not decided for ``pkg`` as possibly affected."""
    vendor, name = product.split(":", 1)
    upstream = upstream_version(pkg.version)
    if not upstream:
        return
    verdict = local_distro_verdict(conn)
    row = _package_row(pkg)
    known = {key for vuln in pkg.vulnerabilities for key in advisory_keys(vuln)}
    recorded = {entry["id"] for entry in pkg.possibly_affected}
    for candidate in cpe_lookup_package(conn, name, upstream, vendor=vendor):
        identifiers = {candidate.id, *candidate.aliases}
        if identifiers & known or candidate.id in recorded or verdict(identifiers, row) is not None:
            continue
        recorded.add(candidate.id)
        pkg.possibly_affected.append(
            {
                "id": candidate.id,
                "verdict": POSSIBLY_AFFECTED,
                "reason": DISTRO_BACKPORT_UNVERIFIED,
                "detail": _detail(pkg, product),
                "cpe_product": product,
                "upstream_version": upstream,
                "upstream_fixed_version": candidate.fixed_version,
                "severity": str(candidate.severity or "unknown").lower(),
                "cvss_score": candidate.cvss_score,
                "summary": candidate.summary,
                "source": "nvd",
            }
        )


def propagate_possibly_affected(packages: list[Package], scanned: list[Package], key: Callable[[Package], str]) -> None:
    """Copy possibly-affected verdicts from the scanned representative to duplicate instances."""
    verdicts = {key(package): package.possibly_affected for package in scanned if package.possibly_affected}
    for package in packages:
        source = verdicts.get(key(package))
        if source is not None and package.possibly_affected is not source:
            package.possibly_affected = [dict(entry) for entry in source]
