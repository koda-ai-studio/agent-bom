"""Runtime components no advisory source assessed are coverage gaps, never clean packages."""

from __future__ import annotations

import logging
import sqlite3
from typing import Optional, Sequence

from agent_bom.coverage import RUNTIME_COVERAGE_UNKNOWN, CoverageWarning, runtime_coverage_release
from agent_bom.cpe_match import cpe_identity
from agent_bom.models import Package
from agent_bom.scanners.cpython_advisory import is_cpython_runtime
from agent_bom.scanners.nodejs_advisory import is_nodejs_runtime
from agent_bom.scanners.package_matching import _osv_ecosystems_for_package

_logger = logging.getLogger(__name__)


def _has_dedicated_runtime_source(pkg: Package, *, offline: bool) -> bool:
    """Runtimes with their own advisory lookup, which records its own coverage gap on failure."""
    if is_cpython_runtime(pkg) or is_nodejs_runtime(pkg):
        return True
    return not offline and (pkg.cpe or "").startswith("cpe:2.3:a:nvidia:")


def _local_cpe_ranges_exist(conn: Optional[sqlite3.Connection], pkg: Package) -> bool:
    identity = cpe_identity(pkg)
    if conn is None or identity is None:
        return False
    try:
        row = conn.execute("SELECT 1 FROM cpe_matches WHERE vendor = ? AND product = ? LIMIT 1", identity).fetchone()
    except sqlite3.Error as exc:
        _logger.debug("runtime coverage check could not read CPE ranges: %s", exc)
        return False
    return row is not None


def _runtime_gap_warning(pkg: Package) -> dict:
    return CoverageWarning(
        ecosystem=(pkg.ecosystem or "").lower(),
        release=runtime_coverage_release(pkg),
        reason=RUNTIME_COVERAGE_UNKNOWN,
        detail=(
            f"Vulnerability coverage for {pkg.name} {pkg.version} is unknown: it has no OSV ecosystem and "
            "no advisory source this scan consulted tracks it (the local advisory DB holds no CPE ranges "
            "for it). It was not assessed, so zero findings is not a clean bill of health."
        ),
        package_count=1,
        advisory_rows=0,
    ).to_dict()


def detect_runtime_coverage_gaps(
    packages: Sequence[Package],
    *,
    offline: bool,
    conn: Optional[sqlite3.Connection] = None,
) -> list[dict]:
    """Coverage warnings for runtime components no advisory source assessed.

    A runtime with no OSV ecosystem (``generic``) is only assessed when a
    dedicated source covers it or the local DB carries CPE ranges for its
    identity. Anything else was skipped, and must not read as clean.
    """
    warnings: list[dict] = []
    seen: set[str] = set()
    for pkg in packages:
        if (pkg.ecosystem or "").lower() != "generic" or pkg.vulnerabilities:
            continue
        if _osv_ecosystems_for_package(pkg) or _has_dedicated_runtime_source(pkg, offline=offline):
            continue
        if _local_cpe_ranges_exist(conn, pkg):
            continue
        release = runtime_coverage_release(pkg)
        if release not in seen:
            seen.add(release)
            warnings.append(_runtime_gap_warning(pkg))
    return warnings
