"""The distribution's own verdict for a distro package against an advisory.

Distributions backport fixes without changing the upstream version, so a
distro package that ships a CPE product is decided by the distro feed record
in the local DB (Debian tracker, Alpine secdb, RHEL/OSV distro rows), never by
upstream ranges. ``None`` means no distro record covers that package and CVE
for that release, which the matcher must report as indeterminate.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agent_bom.core.versions.osv import version_match_state
from agent_bom.models import Package
from agent_bom.scanners.osv import package_lookup_names
from agent_bom.scanners.package_matching import _db_ecosystems_for_package


@dataclass(frozen=True)
class DistroVerdict:
    """``affected`` is ``None`` when the distro record's bounds cannot order the version."""

    affected: bool | None
    fixed: str | None
    ecosystem: str
    record: str


DistroVerdictFn = Callable[[set[str], dict[str, Any]], "DistroVerdict | None"]


def _package(row: dict[str, Any]) -> Package | None:
    try:
        return Package(
            name=str(row.get("name") or ""),
            version=str(row.get("version") or ""),
            ecosystem=str(row.get("ecosystem") or ""),
            purl=row.get("purl"),
            source_package=row.get("source_package"),
            distro_name=row.get("distro_name"),
            distro_version=row.get("distro_version"),
        )
    except (TypeError, ValueError):
        return None


def _names_record(record_id: str, aliases: str, identifiers: set[str]) -> bool:
    """A distro record covers the advisory by id, a ``DEBIAN-CVE-*`` style prefix, or an alias."""
    if record_id in identifiers or record_id.split("-", 1)[-1] in identifiers:
        return True
    return any(alias.strip() in identifiers for alias in (aliases or "").split(","))


def _rows(conn: sqlite3.Connection, ecosystems: list[str], names: list[str]) -> list[sqlite3.Row]:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(affected)").fetchall()}
    limit = "a.limit_version" if "limit_version" in columns else "''"
    eco_marks, name_marks = ",".join("?" * len(ecosystems)), ",".join("?" * len(names))
    return conn.execute(
        f"SELECT a.vuln_id, a.ecosystem, a.introduced, a.fixed, a.last_affected, {limit} AS limit_version, v.aliases "  # nosec B608
        f"FROM affected a JOIN vulns v ON v.id = a.vuln_id WHERE a.ecosystem IN ({eco_marks}) AND a.package_name IN ({name_marks})",
        [*ecosystems, *names],
    ).fetchall()


def _verdict(version: str, rows: list[sqlite3.Row]) -> DistroVerdict:
    undetermined = False
    for row in rows:
        state = version_match_state(version, row[2] or None, row[3] or None, row[4] or None, row[1], row[5])
        if state == "affected":
            return DistroVerdict(True, row[3] or None, row[1], row[0])
        undetermined = undetermined or state == "unknown"
    return DistroVerdict(None if undetermined else False, None, rows[0][1], rows[0][0])


def local_distro_verdict(conn: sqlite3.Connection) -> DistroVerdictFn:
    """Resolve distro verdicts from an open local vulnerability DB connection."""

    def resolve(identifiers: set[str], package: dict[str, Any]) -> DistroVerdict | None:
        pkg = _package(package)
        if pkg is None or not pkg.version:
            return None
        ecosystems, names = _db_ecosystems_for_package(pkg), package_lookup_names(pkg)
        if not ecosystems or not names:
            return None
        wanted = {identifier.upper() for identifier in identifiers}
        rows = [row for row in _rows(conn, ecosystems, names) if _names_record(str(row[0]).upper(), str(row[6] or "").upper(), wanted)]
        return _verdict(pkg.version, rows) if rows else None

    return resolve
