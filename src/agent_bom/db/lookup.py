"""Fast local vulnerability lookup against the SQLite DB.

The primary query pattern is:
    vulns = lookup_package(conn, ecosystem="PyPI", name="requests", version="2.0.0")

Version range matching uses the shared ecosystem-aware comparator from
``agent_bom.version_utils`` so Debian, Alpine, and RPM advisories use the
same semantics as CLI, image, and OSV scans.
"""

from __future__ import annotations

import logging
import sqlite3
from collections import defaultdict
from contextlib import nullcontext
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

from agent_bom.advisory_ids import MATCH_CONFIDENCE_UNVERIFIED_RANGE
from agent_bom.api.tracing import get_tracer
from agent_bom.core.packages import legacy_package_lookup_names, normalize_package_name, package_lookup_names
from agent_bom.core.versions.osv import comparator_ecosystem as _comparator_ecosystem
from agent_bom.core.versions.osv import version_match_state as _version_match_state

_logger = logging.getLogger(__name__)
_LOOKUP_TRACER = get_tracer("agent_bom.db.lookup")


@dataclass
class LocalVuln:
    """A vulnerability record from the local DB."""

    id: str  # CVE-* / GHSA-* / OSV-*
    summary: str
    severity: str
    cvss_score: Optional[float]
    fixed_version: Optional[str]
    cvss_vector: Optional[str] = None
    epss_probability: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_kev: bool = False
    kev_date_added: Optional[str] = None
    kev_due_date: Optional[str] = None  # CISA BOD 22-01 remediation deadline
    published_at: Optional[str] = None
    modified_at: Optional[str] = None
    source: str = "osv"
    ecosystem: str = ""
    package_name: str = ""
    introduced: Optional[str] = None
    upstream_ids: list[str] = field(default_factory=list)  # Relationships, never identity aliases
    epss_cve_id: Optional[str] = None  # CVE supplying the selected maximum EPSS
    kev_cve_id: Optional[str] = None  # CVE supplying the selected KEV dates
    aliases: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    # Explicit candidate tiers override downstream source-based classification.
    match_confidence_tier: Optional[str] = None


@lru_cache(maxsize=16384)
def _cvss4_base_score(vector: str) -> Optional[float]:
    from agent_bom.scanners.risk import parse_cvss_vector

    return parse_cvss_vector(vector)


def _current_severity(severity: str, score: Optional[float], vector: Optional[str]) -> tuple[str, Optional[float]]:
    """Re-derive a stored CVSS 4.0 score from its vector at read time.

    Databases synced before the CVSS 4.0 scorer was fixed keep inflated
    scores, and syncs never rewrite unchanged advisories. The vector is the
    source of truth, so the score is recomputed from it (cached per vector).
    Severity follows only when it was itself derived from the stale score; a
    vendor label that disagrees with that score is left alone.
    """
    if not vector or not vector.upper().startswith("CVSS:4"):
        return severity, score
    fresh = _cvss4_base_score(vector)
    if fresh is None or fresh == score:
        return severity, score
    from agent_bom.db.sync import _cvss_to_severity

    stored_label = (severity or "").lower()
    if score is None or stored_label in ("", "unknown") or stored_label == _cvss_to_severity(score):
        severity = _cvss_to_severity(fresh)
    return severity, fresh


def _cve_candidates(vuln_id: str, raw_aliases: str, raw_upstream: str = "") -> list[str]:
    """CVE ids whose EPSS/KEV belong to a row: its own, else one CVE alias (a fused multi-CVE set joins none), plus upstream."""
    if vuln_id.upper().startswith("CVE-"):
        return [vuln_id]
    alias_cves = {alias.strip() for alias in (raw_aliases or "").split(",") if alias.strip().startswith("CVE-")}
    upstream = [item.strip() for item in (raw_upstream or "").split(",") if item.strip().startswith("CVE-")]
    return list(dict.fromkeys([*(alias_cves if len(alias_cves) == 1 else ()), *upstream]))


def _load_cve_enrichment(
    conn: sqlite3.Connection,
    rows: list[sqlite3.Row],
) -> tuple[dict[str, tuple[Optional[float], Optional[float]]], dict[str, tuple[Optional[str], Optional[str]]]]:
    """Load EPSS and KEV data for any CVE aliases referenced by *rows*."""
    cve_ids: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for cve_id in _cve_candidates(row["id"], row["aliases"] or "", row["upstream_ids"] or ""):
            if cve_id not in seen:
                seen.add(cve_id)
                cve_ids.append(cve_id)

    if not cve_ids:
        return {}, {}

    epss_map: dict[str, tuple[Optional[float], Optional[float]]] = {}
    kev_map: dict[str, tuple[Optional[str], Optional[str]]] = {}
    # An advisory can refer to many upstream CVEs; keep below SQLite limits.
    for offset in range(0, len(cve_ids), 400):
        chunk = cve_ids[offset : offset + 400]
        placeholders = ", ".join("?" for _ in chunk)
        # Only generated question-mark placeholders enter these SQL strings.
        epss_query = f"SELECT cve_id, probability, percentile FROM epss_scores WHERE cve_id IN ({placeholders})"  # nosec B608
        kev_query = f"SELECT cve_id, date_added, due_date FROM kev_entries WHERE cve_id IN ({placeholders})"  # nosec B608
        epss_rows = conn.execute(epss_query, chunk).fetchall()
        kev_rows = conn.execute(kev_query, chunk).fetchall()
        epss_map.update({row["cve_id"]: (row["probability"], row["percentile"]) for row in epss_rows})
        kev_map.update({row["cve_id"]: (row["date_added"], row["due_date"]) for row in kev_rows})
    return epss_map, kev_map


def _resolve_row_enrichment(
    row: sqlite3.Row,
    epss_map: dict[str, tuple[Optional[float], Optional[float]]],
    kev_map: dict[str, tuple[Optional[str], Optional[str]]],
) -> tuple[Optional[float], Optional[float], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """Use the same maximum EPSS and earliest KEV deadline as live scanning."""
    from agent_bom.scanners.enrichment_apply import epss_percentile, select_epss_cve, select_kev_cve

    ids = _cve_candidates(row["id"], row["aliases"] or "", row["upstream_ids"] or "")
    epss = {cve: {"score": epss_map[cve][0]} for cve in ids if cve in epss_map}
    kev = {cve: {"due_date": kev_map[cve][1]} for cve in ids if cve in kev_map}
    epss_id = select_epss_cve(ids, epss)
    kev_id = select_kev_cve(ids, kev)
    probability, percentile = epss_map[epss_id] if epss_id else (None, None)
    date_added, due_date = kev_map[kev_id] if kev_id else (None, None)
    return probability, epss_percentile(percentile), date_added, due_date, epss_id, kev_id


def _upstream_projection(conn: sqlite3.Connection) -> str:
    # Older read-only air-gap bundles cannot migrate until their next update.
    columns = {row[1] for row in conn.execute("PRAGMA table_info(vulns)")}
    return "COALESCE(v.upstream_ids, '')" if "upstream_ids" in columns else "''"


def _limit_projection(conn: sqlite3.Connection) -> str:
    """Read-only pre-v8 bundles have no limit receipt; keep that uncertainty."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(affected)")}
    return "a.limit_version" if "limit_version" in columns else "NULL"


def lookup_package(
    conn: sqlite3.Connection,
    ecosystem: str,
    name: str,
    version: Optional[str] = None,
) -> list[LocalVuln]:
    """Return all vulns affecting the given package/ecosystem from the local DB.

    Version matching uses ecosystem ordering. Unresolvable stored bounds are
    returned as explicitly unverified candidates, with no fix recommendation.
    """
    norm_name = normalize_package_name(name, ecosystem)
    eco_lower = ecosystem.lower()
    exact_names = package_lookup_names(norm_name, ecosystem)
    exact_slots = ", ".join("?" for _ in exact_names)
    legacy_names = (norm_name, *legacy_package_lookup_names(norm_name, ecosystem))
    legacy_slots = ", ".join("?" for _ in legacy_names)

    span_cm = _LOOKUP_TRACER.start_as_current_span("db.lookup_package") if _LOOKUP_TRACER else nullcontext()
    with span_cm as span:
        upstream_projection = _upstream_projection(conn)
        limit_projection = _limit_projection(conn)
        rows = conn.execute(
            f"""
            SELECT
                v.id, v.summary, v.severity, v.cvss_score, v.cvss_vector, v.fixed_version, v.cwe_ids,
                COALESCE(v.aliases, '') AS aliases, {upstream_projection} AS upstream_ids, v.source,
                v.published, v.modified,
                a.ecosystem, a.package_name, a.introduced, a.fixed, a.last_affected, {limit_projection} AS limit_version,
                e.probability AS epss_prob, e.percentile AS epss_pct,
                k.date_added AS kev_date, k.due_date AS kev_due_date
            FROM affected a
            JOIN vulns v ON v.id = a.vuln_id
            LEFT JOIN epss_scores e ON e.cve_id = v.id
            LEFT JOIN kev_entries k ON k.cve_id = v.id
            WHERE a.ecosystem = ? AND (a.package_name IN ({exact_slots})
                OR ({limit_projection} IS NULL AND a.package_name IN ({legacy_slots})))
            ORDER BY v.cvss_score DESC NULLS LAST
            """,  # nosec B608 - projection is one of two static SQL literals; values are bound
            (eco_lower, *exact_names, *legacy_names),
        ).fetchall()

        epss_map, kev_map = _load_cve_enrichment(conn, rows)
        results: list[LocalVuln] = []
        for row in _select_vulnerability_rows(rows, version):
            results.append(_local_vuln_from_row(row, rows, version, epss_map, kev_map))

        if span is not None:
            span.set_attribute("agent_bom.lookup.ecosystem", eco_lower)
            span.set_attribute("agent_bom.lookup.package_name", norm_name)
            span.set_attribute("agent_bom.lookup.row_count", len(rows))
            span.set_attribute("agent_bom.lookup.match_count", len(results))
        return results


def cpe_lookup_package(
    conn: sqlite3.Connection, name: str, version: str, *, vendor: Optional[str] = None, limit: int = 500, target_sw: Optional[str] = None
) -> list[LocalVuln]:
    """Long-tail CPE-candidate matches for a component, hydrated from ``vulns``.

    Maps the component to NVD CPE applicability ranges (see
    :func:`agent_bom.cpe_match.match_component_cpe`) and hydrates each matched CVE
    from the local ``vulns`` table so it carries real severity/CVSS/CWE. CVEs not
    yet synced into ``vulns`` are skipped (no severity to report). Every result is
    tagged ``nvd_cpe_candidate`` — a review-grade tier, never confirmed.
    """
    from agent_bom.cpe_match import MATCH_CONFIDENCE_NVD_CPE_CANDIDATE, match_component_cpe

    matches = match_component_cpe(conn, name, version, vendor=vendor, limit=limit, target_sw=target_sw)
    if not matches:
        return []
    cve_ids = [m["cve_id"] for m in matches]
    placeholders = ", ".join("?" for _ in cve_ids)
    rows = {
        row["id"]: row
        for row in conn.execute(
            "SELECT id, summary, severity, cvss_score, cvss_vector, fixed_version, "
            f"cwe_ids, aliases, published, modified FROM vulns WHERE id IN ({placeholders})",  # nosec B608 - placeholders are generated solely from "?" markers
            cve_ids,
        ).fetchall()
    }
    out: list[LocalVuln] = []
    for cve_id in cve_ids:
        row = rows.get(cve_id)
        if row is None:
            continue
        severity, cvss_score = _current_severity(row["severity"], row["cvss_score"], row["cvss_vector"])
        out.append(
            LocalVuln(
                id=row["id"],
                summary=row["summary"],
                severity=severity,
                cvss_score=cvss_score,
                fixed_version=row["fixed_version"],
                cvss_vector=row["cvss_vector"],
                source="nvd",
                package_name=name,
                cwe_ids=[c for c in (row["cwe_ids"] or "").split(",") if c],
                aliases=[a for a in (row["aliases"] or "").split(",") if a],
                published_at=row["published"],
                modified_at=row["modified"],
                match_confidence_tier=MATCH_CONFIDENCE_NVD_CPE_CANDIDATE,
            )
        )
    return out


def _version_affected(
    version: str,
    introduced: Optional[str],
    fixed: Optional[str],
    last_affected: Optional[str],
    ecosystem: str = "",
) -> bool:
    """Ecosystem-aware version-in-range check."""
    from agent_bom.version_utils import version_in_range

    return version_in_range(version, introduced, fixed, last_affected, _comparator_ecosystem(ecosystem))


def _is_distro_release_ecosystem(ecosystem: str) -> bool:
    """True for release-scoped OS ecosystems (``debian:10``, ``alpine:v3.18``, …).

    For these the authoritative fixed version is the *per-release* ``affected.fixed``
    column, not the cross-release ``vulns.fixed_version`` rollup. Debian/distro
    advisories assign a different (backported) fix — or no fix at all — per release,
    so reusing the global rollup both displays a wrong-release version and, worse,
    makes a no-fix-for-this-release entry look fixed, defeating the default
    unfixed-advisory suppression.
    """
    return _comparator_ecosystem(ecosystem) in ("deb", "apk", "rpm")


def _resolve_fixed_version(row: sqlite3.Row) -> Optional[str]:
    """Only the matched package/range can supply a remediation version.

    Advisory-level rollups can belong to another package, ecosystem or branch.
    Alias recovery below additionally verifies package and range applicability.
    """
    return (row["fixed"] or "").strip() or None


def _row_identifiers(row: sqlite3.Row) -> set[str]:
    """Vulnerability id plus its comma-separated aliases as a set."""
    ids = {row["id"]}
    ids.update(alias.strip() for alias in (row["aliases"] or "").split(",") if alias.strip())
    return ids


def _alias_cluster_fix(row: sqlite3.Row, rows: list[sqlite3.Row], version: Optional[str]) -> Optional[str]:
    """Recover a missing fix version from alias-linked sibling rows.

    OSV mirrors one advisory under several ids (PYSEC / GHSA / …) linked by
    aliases, and the sources disagree on fix metadata — e.g. CVE-2025-2999
    surfaces via a PYSEC row with no fix while its GHSA alias row in the same
    DB carries ``fixed=2.9.1``. Reporting the fix-less row as "no fix
    available" over-claims and lets ``--exclude-unfixable`` drop a fixable
    finding. For the same ecosystem/package, take the minimal valid fix among
    alias siblings that still exceeds the queried version. Distro-release
    ecosystems are excluded: there an empty per-release fix authoritatively
    means *no fix for this release*.
    """
    if _is_distro_release_ecosystem(row["ecosystem"]):
        return None
    from agent_bom.scanners.osv import is_valid_fix_version
    from agent_bom.version_utils import compare_version_order

    identifiers = _row_identifiers(row)
    comparator_eco = _comparator_ecosystem(row["ecosystem"])
    best: Optional[str] = None
    for other in rows:
        if other["id"] == row["id"]:
            continue
        if other["ecosystem"] != row["ecosystem"] or other["package_name"] != row["package_name"]:
            continue
        if identifiers.isdisjoint(_row_identifiers(other)):
            continue
        # An alias row is only a valid source of remediation metadata when its
        # own affected range includes the installed version.  Advisory mirrors
        # frequently share aliases while covering different releases; taking
        # a fix from an unrelated range makes an otherwise unfixable finding
        # look remediable (or, worse, hides a real finding after upgrade).
        if (
            version
            and _version_match_state(
                version,
                other["introduced"],
                other["fixed"],
                other["last_affected"],
                other["ecosystem"],
                other["limit_version"],
            )
            != "affected"
        ):
            continue
        fix = _resolve_fixed_version(other)
        if not fix or not is_valid_fix_version(fix):
            continue
        if version:
            fix_vs_version = compare_version_order(fix, version, comparator_eco)
            if fix_vs_version is None or fix_vs_version <= 0:
                continue  # a "fix" at/below the installed version resolves nothing
        if best is None:
            best = fix
        else:
            fix_vs_best = compare_version_order(fix, best, comparator_eco)
            if fix_vs_best is not None and fix_vs_best < 0:
                best = fix
    return best


def _resolve_fixed_version_with_aliases(row: sqlite3.Row, rows: list[sqlite3.Row], version: Optional[str]) -> Optional[str]:
    """Per-row fix resolution, falling back to the alias cluster when missing."""
    fixed = _resolve_fixed_version(row)
    if fixed is not None:
        return fixed
    return _alias_cluster_fix(row, rows, version)


def _select_vulnerability_rows(rows: list[sqlite3.Row], version: Optional[str]) -> list[sqlite3.Row]:
    """Choose at most one authoritative affected row per vulnerability.

    If any row for a vulnerability definitively matches the requested version,
    include the vulnerability. If no rows match but at least one row
    is ambiguous, retain an explicitly unverified candidate unless another
    window proves membership. An unaffected sibling cannot negate an unknown
    window because OSV ranges form a union. Rows whose only signal is ``uncomparable`` (git-SHA /
    non-version bounds — e.g. OSV-2022 OSS-Fuzz advisories) are never grounds
    for inclusion, so a concrete semver version does not draw a false positive.
    """
    if not version:
        grouped_rows: dict[str, list[sqlite3.Row]] = defaultdict(list)
        for row in rows:
            grouped_rows[row["id"]].append(row)
        return [group[0] for group in grouped_rows.values()]

    grouped: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        grouped[row["id"]].append(row)

    selected: list[sqlite3.Row] = []
    for vuln_rows in grouped.values():
        affected_row: sqlite3.Row | None = None
        unknown_row: sqlite3.Row | None = None

        for row in vuln_rows:
            state = _version_match_state(
                version, row["introduced"], row["fixed"], row["last_affected"], row["ecosystem"], row["limit_version"]
            )
            if state == "affected":
                affected_row = row
                break
            if state == "unknown" and unknown_row is None:
                unknown_row = row

        if affected_row is not None:
            selected.append(affected_row)
        elif unknown_row is not None:
            selected.append(unknown_row)

    return selected


def _package_rows_with_legacy_candidates(grouped: dict[tuple[str, str], list[sqlite3.Row]], ecosystem: str, name: str) -> list[sqlite3.Row]:
    name = normalize_package_name(name, ecosystem)
    exact_names = package_lookup_names(name, ecosystem)
    rows = [row for value in exact_names for row in grouped.get((ecosystem.lower(), value), [])]
    for legacy in set(legacy_package_lookup_names(name, ecosystem)) - set(exact_names):
        rows.extend(row for row in grouped.get((ecosystem.lower(), legacy), []) if row["limit_version"] is None)
    return rows


def _lookup_pairs(packages: list[tuple[str, str, str]]) -> list[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for ecosystem, name, _ in packages:
        name = normalize_package_name(name, ecosystem)
        pairs.update(
            (ecosystem.lower(), value) for value in (*package_lookup_names(name, ecosystem), *legacy_package_lookup_names(name, ecosystem))
        )
    return sorted(pairs)


def lookup_packages_batch(
    conn: sqlite3.Connection,
    packages: list[tuple[str, str, str]],
) -> dict[tuple[str, str, str], list[LocalVuln]]:
    """Batch lookup vulnerabilities for multiple packages in a single query.

    *packages* is a list of ``(ecosystem, normalized_name, version)`` tuples.

    Returns a dict mapping each input tuple to its list of matching
    :class:`LocalVuln` records.  Version range matching uses the same logic
    as :func:`lookup_package`.

    The query fetches all rows for the unique ``(ecosystem, package_name)``
    pairs, then filters by version in-memory.  SQLite's variable limit
    (default 999) is respected by chunking into groups of 400 pairs.
    """
    if not packages:
        return {}

    chunk_size = 400  # 400 pairs = 800 params, well under SQLite's 999

    # Deduplicate (ecosystem, name) pairs for the SQL query; keep version
    # info for in-memory filtering afterwards.
    pairs = _lookup_pairs(packages)

    span_cm = _LOOKUP_TRACER.start_as_current_span("db.lookup_packages_batch") if _LOOKUP_TRACER else nullcontext()
    with span_cm as span:
        # Fetch all rows in chunks
        upstream_projection = _upstream_projection(conn)
        limit_projection = _limit_projection(conn)
        all_rows: list[sqlite3.Row] = []
        for start in range(0, len(pairs), chunk_size):
            chunk = pairs[start : start + chunk_size]
            placeholders = ", ".join(["(?, ?)"] * len(chunk))
            params: list[str] = []
            for eco, nm in chunk:
                params.extend([eco, nm])

            # placeholders is only "(?, ?)" repeated — no user data in the SQL string.
            query = f"""
                SELECT
                    v.id, v.summary, v.severity, v.cvss_score, v.cvss_vector, v.fixed_version, v.cwe_ids,
                    COALESCE(v.aliases, '') AS aliases, {upstream_projection} AS upstream_ids, v.source,
                    v.published, v.modified,
                    a.ecosystem, a.package_name, a.introduced, a.fixed, a.last_affected, {limit_projection} AS limit_version,
                    e.probability AS epss_prob, e.percentile AS epss_pct,
                    k.date_added AS kev_date, k.due_date AS kev_due_date
                FROM affected a
                JOIN vulns v ON v.id = a.vuln_id
                LEFT JOIN epss_scores e ON e.cve_id = v.id
                LEFT JOIN kev_entries k ON k.cve_id = v.id
                WHERE (a.ecosystem, a.package_name) IN (VALUES {placeholders})
                ORDER BY v.cvss_score DESC NULLS LAST
            """  # nosec B608
            all_rows.extend(conn.execute(query, params).fetchall())

        epss_map, kev_map = _load_cve_enrichment(conn, all_rows)

        # Group rows by (lower_ecosystem, package_name)
        grouped: dict[tuple[str, str], list[sqlite3.Row]] = defaultdict(list)
        for row in all_rows:
            grouped[(row["ecosystem"].lower(), row["package_name"])].append(row)

        # Build results per input package (with version filtering)
        results: dict[tuple[str, str, str], list[LocalVuln]] = {}
        for eco, name, version in packages:
            key = (eco, name, version)
            rows = _package_rows_with_legacy_candidates(grouped, eco, name)

            vulns: list[LocalVuln] = []
            for row in _select_vulnerability_rows(rows, version):
                vulns.append(_local_vuln_from_row(row, rows, version, epss_map, kev_map))
            results[key] = vulns

        if span is not None:
            span.set_attribute("agent_bom.lookup.package_count", len(packages))
            span.set_attribute("agent_bom.lookup.unique_pairs", len(pairs))
            span.set_attribute("agent_bom.lookup.row_count", len(all_rows))
        return results


def package_in_db(conn: sqlite3.Connection, ecosystem: str, name: str) -> bool:
    """Return True if *any* affected record exists for this package in the DB.

    Used to decide whether the DB is authoritative for a package (and OSV fallback
    can be skipped) vs. the package simply not being indexed yet.
    """
    if _limit_projection(conn) == "NULL":
        return False
    names = package_lookup_names(name, ecosystem)
    slots = ", ".join("?" for _ in names)
    row = conn.execute(
        f"SELECT 1 FROM affected WHERE ecosystem = ? AND package_name IN ({slots}) AND limit_version IS NOT NULL LIMIT 1",  # nosec B608
        (ecosystem.lower(), *names),
    ).fetchone()
    return row is not None


def package_in_db_batch(
    conn: sqlite3.Connection,
    packages: list[tuple[str, str]],
) -> set[tuple[str, str]]:
    """Return the subset of ``(ecosystem, package_name)`` pairs present in affected."""
    if not packages:
        return set()

    if _limit_projection(conn) == "NULL":
        return set()
    normalized = {(ecosystem.lower(), normalize_package_name(name, ecosystem)) for ecosystem, name in packages}
    pairs = list({(eco, alias) for eco, name in normalized for alias in package_lookup_names(name, eco)})
    chunk_size = 400
    present: set[tuple[str, str]] = set()

    for start in range(0, len(pairs), chunk_size):
        chunk = pairs[start : start + chunk_size]
        placeholders = ", ".join(["(?, ?)"] * len(chunk))
        params: list[str] = []
        for eco, name in chunk:
            params.extend([eco, name])
        query = f"""
            SELECT DISTINCT ecosystem, package_name
            FROM affected
            WHERE (ecosystem, package_name) IN (VALUES {placeholders}) AND limit_version IS NOT NULL
        """  # nosec B608
        present.update(
            (row["ecosystem"], normalize_package_name(row["package_name"], row["ecosystem"]))
            for row in conn.execute(query, params).fetchall()
        )

    return present


class VulnDB:
    """Context-manager wrapper for the local vuln DB connection."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path
        self._conn: Optional[sqlite3.Connection] = None

    def __enter__(self) -> "VulnDB":
        from agent_bom.db.schema import DB_PATH, init_db

        self._conn = init_db(self._path or DB_PATH)
        return self

    def __exit__(self, *_) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def lookup(self, ecosystem: str, name: str, version: Optional[str] = None) -> list[LocalVuln]:
        """Look up vulns for a package."""
        if not self._conn:
            raise RuntimeError("VulnDB not opened — use as context manager")
        return lookup_package(self._conn, ecosystem, name, version)

    def stats(self) -> dict:
        """Return DB stats."""
        if not self._conn:
            raise RuntimeError("VulnDB not opened — use as context manager")
        from agent_bom.db.schema import db_stats

        return db_stats(self._conn)


def _local_vuln_from_row(row, rows, version, epss_map, kev_map) -> LocalVuln:
    """Hydrate identical evidence for single and batch package lookups."""
    raw_cwes = row["cwe_ids"] or ""
    cwe_list = [c for c in raw_cwes.split(",") if c] if raw_cwes else []
    raw_aliases = row["aliases"] or ""
    alias_list = [a for a in raw_aliases.split(",") if a] if raw_aliases else []
    epss_prob, epss_pct, kev_date, kev_due, epss_id, kev_id = _resolve_row_enrichment(row, epss_map, kev_map)
    severity, cvss_score = _current_severity(row["severity"], row["cvss_score"], row["cvss_vector"])
    legacy_receipt = row["limit_version"] is None
    unknown_range = legacy_receipt or bool(
        version
        and _version_match_state(version, row["introduced"], row["fixed"], row["last_affected"], row["ecosystem"], row["limit_version"])
        == "unknown"
    )
    if unknown_range:
        from agent_bom.scanners.state import record_scan_warning

        if legacy_receipt:
            # Rows carried over by the v7->v8 schema upgrade lost their OSV
            # range limits, so neither membership nor the fix can be confirmed
            # until the next OSV refresh rewrites them.
            record_scan_warning(
                "Local advisory rows predate range-limit receipts (not refreshed since the DB schema upgrade): "
                "findings from them are marked unverified_range and their fixed versions are withheld. "
                "Run `agent-bom db update` to restore range bounds and fixed versions."
            )
        else:
            record_scan_warning(
                "Some local advisory ranges cannot be verified. Findings marked unverified_range are candidates; "
                "run agent-bom db update to refresh source bounds and review unresolved versions."
            )
    return LocalVuln(
        match_confidence_tier=MATCH_CONFIDENCE_UNVERIFIED_RANGE if unknown_range else None,
        id=row["id"],
        summary=row["summary"],
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=row["cvss_vector"],
        fixed_version=None if unknown_range else _resolve_fixed_version_with_aliases(row, rows, version),
        epss_probability=epss_prob,
        epss_percentile=epss_pct,
        is_kev=kev_id is not None,
        kev_date_added=kev_date,
        kev_due_date=kev_due,
        published_at=row["published"],
        modified_at=row["modified"],
        source=row["source"],
        ecosystem=row["ecosystem"],
        package_name=row["package_name"],
        introduced=row["introduced"],
        upstream_ids=[item for item in (row["upstream_ids"] or "").split(",") if item],
        epss_cve_id=epss_id,
        kev_cve_id=kev_id,
        aliases=alias_list,
        cwe_ids=cwe_list,
    )
