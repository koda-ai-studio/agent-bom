"""Local and bundled advisory matching."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Optional

from agent_bom.cpe_match import cpe_identity
from agent_bom.cpe_match import cpe_vendor_hint as _cpe_vendor_hint
from agent_bom.malicious import flag_malicious_from_vulns
from agent_bom.models import Package, Severity, Vulnerability
from agent_bom.scanners.advisory_merge import self_consistent_aliases
from agent_bom.scanners.local_data_freshness import local_hits_line
from agent_bom.scanners.osv import is_valid_fix_version as _is_valid_fix_version
from agent_bom.scanners.osv import package_lookup_names as _package_lookup_names
from agent_bom.scanners.package_matching import _apply_distro_release_ambiguity as _apply_distro_release_ambiguity
from agent_bom.scanners.package_matching import _db_ecosystems_for_package as _db_ecosystems_for_package
from agent_bom.scanners.package_matching import _emit_scan_warning as _emit_scan_warning
from agent_bom.scanners.package_matching import _scanners_patchable as _scanners_patchable
from agent_bom.scanners.risk import advisory_id_severity_fallback, cvss_to_severity, parse_cvss_vector, severity_from_label
from agent_bom.scanners.scan_options import ScanOptions, _logger, _package_db_key
from agent_bom.vuln_compliance import tag_vulnerability as _tag_vuln


def merge_scanner_vulnerabilities(pkg: Package, new_vulns: list[Vulnerability]) -> list[Vulnerability]:
    """Merge alias clusters once, returning only clusters absent from the package."""
    from agent_bom.scanners.advisory_merge import advisory_keys, fix_fallback_allowed, merge_advisory_clusters

    previous_keys = {key for record in pkg.vulnerabilities for key in advisory_keys(record)}
    pkg.vulnerabilities = merge_advisory_clusters([*pkg.vulnerabilities, *new_vulns], fix_fallback=fix_fallback_allowed(pkg))
    return [record for record in pkg.vulnerabilities if not advisory_keys(record) & previous_keys]


def merge_local_vulns(pkg: "Any", local_vulns: "list[Any]") -> "list[Vulnerability]":
    """Use the same alias/severity reconciliation as online advisory scanning."""
    added = merge_scanner_vulnerabilities(pkg, [_local_vuln_to_vulnerability(record) for record in local_vulns])
    _apply_distro_release_ambiguity(pkg, pkg.vulnerabilities)
    return added


def _local_vuln_to_vulnerability(lv: "Any") -> Vulnerability:
    """Convert a LocalVuln (from SQLite DB) to a Vulnerability model object.

    Canonicalizes ID to CVE when available (prefer CVE-xxxx over GHSA/PYSEC).
    """
    # Same basis precedence as ``osv_severity_basis`` (online): a CVSS score
    # decides the band; the stored advisory label only applies without one.
    cvss_score = getattr(lv, "cvss_score", None)
    cvss_vector = getattr(lv, "cvss_vector", None)
    if cvss_score is None and isinstance(cvss_vector, str) and cvss_vector:
        cvss_score = parse_cvss_vector(cvss_vector)
    severity_source: Optional[str] = None
    if cvss_score is not None:
        severity = cvss_to_severity(cvss_score)
        severity_source = "cvss"
    else:
        severity = severity_from_label(getattr(lv, "severity", None))
        if severity != Severity.UNKNOWN:
            label_origin = str(getattr(lv, "source", "") or "osv").lower()
            severity_source = "osv_database" if label_origin == "osv" else f"{label_origin}_advisory"

    from agent_bom.advisory_ids import canonical_vulnerability_id, match_confidence_tier

    raw_id = lv.id
    aliases = self_consistent_aliases(raw_id, list(getattr(lv, "aliases", []) or []))
    canonical_id, all_aliases = canonical_vulnerability_id(raw_id, aliases)

    if severity == Severity.UNKNOWN:
        for advisory_id in [str(raw_id), *(str(alias) for alias in aliases)]:
            fallback, source = advisory_id_severity_fallback(advisory_id)
            if fallback != Severity.UNKNOWN:
                severity = fallback
                severity_source = source
                break

    advisory_source = getattr(lv, "source", None)
    fixed_version = lv.fixed_version if _is_valid_fix_version(lv.fixed_version or "") else None

    return Vulnerability(
        id=canonical_id,
        summary=lv.summary or "No description available",
        severity=severity,
        severity_source=severity_source,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector if isinstance(cvss_vector, str) and cvss_vector else None,
        fixed_version=fixed_version,
        epss_score=lv.epss_probability,
        epss_percentile=lv.epss_percentile,
        is_kev=lv.is_kev,
        kev_date_added=lv.kev_date_added,
        kev_due_date=getattr(lv, "kev_due_date", None),
        published_at=getattr(lv, "published_at", None),
        modified_at=getattr(lv, "modified_at", None),
        cwe_ids=getattr(lv, "cwe_ids", []),
        aliases=all_aliases,
        upstream_ids=getattr(lv, "upstream_ids", []),
        epss_cve_id=getattr(lv, "epss_cve_id", None),
        kev_cve_id=getattr(lv, "kev_cve_id", None),
        references=[],
        advisory_sources=[advisory_source] if isinstance(advisory_source, str) and advisory_source else [],
        match_confidence_tier=getattr(lv, "match_confidence_tier", None)
        or match_confidence_tier(
            advisory_source=advisory_source if isinstance(advisory_source, str) else None,
            db_ecosystem=getattr(lv, "ecosystem", None),
            package_ecosystem=None,
            fixed_version=fixed_version,
        ),
    )


_BATCH_DB_THRESHOLD = 50


def _scan_packages_local_db(packages: list[Package]) -> tuple[int, set[str]]:
    """Query the local SQLite DB for all packages.

    Returns ``(vuln_count, covered_keys)`` where covered_keys is the set of
    ``ecosystem:norm_name@version`` keys that had at least one entry in the DB
    (including zero-vuln hits — those are DB hits, not gaps).
    """
    try:
        from agent_bom.db.schema import DB_PATH, db_freshness_days

        freshness = db_freshness_days()
        if freshness is None:
            # A cache miss is not a coverage gap while the online OSV path is
            # available.  The remote lookup result below is authoritative; its
            # failure path records a coverage warning via
            # ``_flag_remote_lookup_gap``.
            _logger.info("Local vulnerability DB not found; falling back to remote lookups")
            return 0, set()  # No DB yet — fall through to OSV entirely
    except Exception as exc:
        _logger.debug("Local DB freshness check failed (falling through to OSV): %s", exc)
        _emit_scan_warning("local vulnerability DB freshness check failed")
        return 0, set()

    try:
        from agent_bom.db.schema import init_db, open_existing_db_readonly

        try:
            # Scans only need read access. Prefer the existing DB in read-only
            # mode so the hot path avoids init-time integrity work and extra
            # writable-open overhead on large catalogs.
            conn = open_existing_db_readonly(DB_PATH) if DB_PATH.exists() else init_db(DB_PATH)
        except Exception as exc:
            _logger.debug("Primary local DB open failed, retrying writable init: %s", exc)
            conn = init_db(DB_PATH)
    except Exception as exc:
        _logger.warning("Local DB unavailable: %s", exc)
        _emit_scan_warning("local vulnerability DB unavailable")
        return 0, set()

    try:
        covered: set[str] = set()
        total = _scan_packages_db_conn(conn, packages, covered)
    finally:
        conn.close()

    return total, covered


def _scan_packages_db_conn(conn: Any, packages: list[Package], covered: set[str]) -> int:
    """Scan packages against an initialized vulnerability DB connection."""

    from agent_bom.db import lookup_package
    from agent_bom.db.lookup import package_in_db

    if len(packages) > _BATCH_DB_THRESHOLD:
        return _scan_packages_local_db_batch(conn, packages, covered)

    total = 0
    for pkg in packages:
        eco_key = pkg.ecosystem.lower()
        db_ecos = _db_ecosystems_for_package(pkg) or [pkg.ecosystem.lower()]
        candidate_names = _package_lookup_names(pkg)
        norm_name = candidate_names[0]
        db_key = f"{eco_key}:{norm_name}@{pkg.version}"
        local_vulns = []
        db_hit = False
        for db_eco in db_ecos:
            for candidate_name in candidate_names:
                local_vulns.extend(lookup_package(conn, db_eco, candidate_name, pkg.version))
                db_hit = db_hit or package_in_db(conn, db_eco, candidate_name)

        # Only mark as "covered by DB" when the package name actually exists in
        # the affected table, not merely because the ecosystem is mapped.
        if db_hit:
            covered.add(db_key)

        # Long-tail CPE matching: only for components the OSV/distro feeds miss
        # (no DB hit) and only when explicitly enabled. Review-grade candidates.
        _attach_cpe_candidates(conn, pkg, candidate_names, local_vulns, db_hit=db_hit)

        if local_vulns:
            new_vulns = merge_local_vulns(pkg, local_vulns)
            total += len(new_vulns)
            for v in new_vulns:
                v.compliance_tags = _tag_vuln(v, pkg)
            flag_malicious_from_vulns(pkg)

    return total


def _attach_cpe_candidates(
    conn: Any,
    pkg: Package,
    candidate_names: list[str],
    local_vulns: list[Any],
    *,
    db_hit: bool,
) -> None:
    """Append CPE candidate matches for packages not covered by native feeds.

    Components that carry an explicit CPE identity (source-built language
    runtimes) are matched by exact vendor/product, so the name-guessing noise
    the opt-in flag guards against does not apply to them.
    """
    from agent_bom import config
    from agent_bom.db.lookup import cpe_lookup_package

    identity = cpe_identity(pkg)
    if identity is not None:
        local_vulns.extend(cpe_lookup_package(conn, identity[1], pkg.version, vendor=identity[0]))
        return
    if not config.ENABLE_CPE_MATCH or db_hit:
        return
    vendor = _cpe_vendor_hint(pkg)
    for candidate_name in candidate_names:
        cpe_vulns = cpe_lookup_package(conn, candidate_name, pkg.version, vendor=vendor)
        if cpe_vulns:
            local_vulns.extend(cpe_vulns)
            break


def _scan_packages_demo_advisories(packages: list[Package]) -> tuple[int, set[str]]:
    """Scan packages against the bundled demo advisory manifest."""

    from agent_bom.db.schema import init_db
    from agent_bom.demo_advisories import seed_demo_advisories

    with tempfile.TemporaryDirectory(prefix="agent-bom-demo-vulns-") as tmp_dir:
        conn = init_db(Path(tmp_dir) / "vulns.db")
        try:
            seed_demo_advisories(conn)
            covered: set[str] = set()
            total = _scan_packages_db_conn(conn, packages, covered)
            return total, covered
        finally:
            conn.close()


def _scan_packages_local_db_batch(
    conn: Any,
    packages: list[Package],
    covered: set[str],
) -> int:
    """Batch variant of the local DB scan — fewer SQL round-trips.

    Uses :func:`lookup_packages_batch` to fetch all vulnerabilities in bulk,
    then applies the same dedup / tagging logic as the per-package path.
    """
    from agent_bom.db.lookup import lookup_packages_batch, package_in_db_batch

    # Build batch keys: (db_ecosystem, normalized_name, version)
    pkg_index: list[tuple[Package, list[str], str, str, list[str]]] = []  # (pkg, db_ecos, primary_norm_name, db_key, candidate_names)
    batch_keys: list[tuple[str, str, str]] = []

    for pkg in packages:
        eco_key = pkg.ecosystem.lower()
        db_ecos = _db_ecosystems_for_package(pkg) or [pkg.ecosystem.lower()]
        candidate_names = _package_lookup_names(pkg)
        norm_name = candidate_names[0]
        db_key = f"{eco_key}:{norm_name}@{pkg.version}"
        pkg_index.append((pkg, db_ecos, norm_name, db_key, candidate_names))
        for db_eco in db_ecos:
            for candidate_name in candidate_names:
                batch_keys.append((db_eco, candidate_name, pkg.version))

    batch_results = lookup_packages_batch(conn, batch_keys)
    existing_pairs = package_in_db_batch(
        conn,
        [
            (db_eco, candidate_name)
            for _pkg, db_ecos, _norm_name, _db_key, candidate_names in pkg_index
            for db_eco in db_ecos
            for candidate_name in candidate_names
        ],
    )

    total = 0
    for pkg, db_ecos, norm_name, db_key, candidate_names in pkg_index:
        local_vulns = []
        for db_eco in db_ecos:
            for candidate_name in candidate_names:
                local_vulns.extend(batch_results.get((db_eco, candidate_name, pkg.version), []))

        db_hit = any((db_eco.lower(), candidate_name) in existing_pairs for db_eco in db_ecos for candidate_name in candidate_names)
        if db_hit:
            covered.add(db_key)

        _attach_cpe_candidates(conn, pkg, candidate_names, local_vulns, db_hit=db_hit)

        if local_vulns:
            new_vulns = merge_local_vulns(pkg, local_vulns)
            total += len(new_vulns)
            for v in new_vulns:
                v.compliance_tags = _tag_vuln(v, pkg)
            flag_malicious_from_vulns(pkg)

    return total


def _scan_local_advisories(scannable: list[Package], scan_options: ScanOptions, demo_keys: set[str]) -> tuple[int, set[str], list[Package]]:
    """Match against demo advisories and the local DB; return count, covered keys and DB targets."""
    # Demo mode uses bundled advisory rows first so published first-run evidence
    # is deterministic and does not depend on a user's ambient ~/.agent-bom DB.
    local_count = 0
    db_covered: set[str] = set()
    if scan_options.demo_advisories:
        demo_count, demo_covered = _scan_packages_demo_advisories(scannable)
        local_count += demo_count
        db_covered.update(demo_covered)
        # The curated demo inventory is a closed evidence set; some entries are intentionally clean or
        # malicious without a CVE, so a missing row must not fall through to the ambient DB or OSV.
        db_covered.update(demo_keys)

    # Query the local SQLite DB for packages the demo manifest does not cover; DB hits skip OSV.
    local_db_targets = [p for p in scannable if _package_db_key(p) not in db_covered]
    local_db_count, local_db_covered = _scanners_patchable("_scan_packages_local_db")(local_db_targets) if local_db_targets else (0, set())
    local_count += local_db_count
    db_covered.update(local_db_covered)
    if local_count:
        options = scan_options
        line = local_hits_line(local_count, offline=options.offline, prefer_local_db=options.prefer_local_db, demo=options.demo_advisories)
        _scanners_patchable("console").print(line)
    return local_count, db_covered, local_db_targets
