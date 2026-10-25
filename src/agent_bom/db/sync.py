"""Sync the local vulnerability database from upstream sources.

Sources:
    osv    — OSV.dev all-ecosystems bulk export (zip of per-ecosystem JSON files)
    alpine — Alpine Linux secdb package secfix feeds
    debian — Debian Security Tracker (per-release status + backported fixes,
             incl. end-of-life releases such as buster/Debian 10 via Extended LTS)
    epss   — FIRST EPSS v4 CSV bulk export
    kev    — CISA KEV JSON catalog
    ghsa   — GitHub Security Advisories across all supported ecosystems
    nvd    — NVD CVEs published/modified in a bounded recent window, with their
             CPE applicability ranges (120 days with ``NVD_API_KEY``, 14 days
             without; keyless runs also backfill CVSS/CWE for existing rows)

Usage:
    agent-bom db update            # sync the default sources (osv, alpine, debian, epss, kev, nvd)
    agent-bom db update --source osv
    agent-bom db update --source debian
    agent-bom db update --source epss
    agent-bom db update --source kev
    agent-bom db update --source ghsa
    agent-bom db update --source nvd"""

from __future__ import annotations

import sqlite3
import zipfile
from importlib import import_module
from pathlib import Path
from typing import Any, Callable, Optional

from agent_bom.db.sync_common import (
    _BATCH_SIZE,
    _GHSA_REST_URL,
    _NVD_API_URL,
    _OSV_ALL_ZIP_URL,
    GHSA_ECOSYSTEMS,
    OSV_APPLICATION_ECOSYSTEMS,
    _canonical_osv_ecosystem,
    _ingest_osv_file,
    _logger,
    _normalize_ghsa_db_ecosystem,
    _normalize_sync_cvss_score,
    _nvd_cve_candidates,
    _osv_bulk_url,
    _read_sync_metadata,
    _update_sync_meta,
    _validate_sync_url,
)
from agent_bom.db.sync_distributions import sync_alpine_secdb, sync_debian_tracker
from agent_bom.db.sync_exploit_feeds import sync_epss, sync_kev
from agent_bom.db.sync_nvd_window import NvdRateLimiter
from agent_bom.db.sync_nvd_window import sync_nvd_incremental as sync_nvd_incremental
from agent_bom.db.sync_parsing import _CVSS_SEVERITY as _CVSS_SEVERITY
from agent_bom.db.sync_parsing import _cpe_version_bound as _cpe_version_bound
from agent_bom.db.sync_parsing import _cvss_to_severity as _cvss_to_severity
from agent_bom.db.sync_parsing import _extract_nvd_cpe_matches as _extract_nvd_cpe_matches
from agent_bom.db.sync_parsing import _extract_nvd_cve_fields as _extract_nvd_cve_fields
from agent_bom.db.sync_parsing import _is_commit_bound as _is_commit_bound
from agent_bom.db.sync_parsing import _parse_alpine_secfix_tokens as _parse_alpine_secfix_tokens
from agent_bom.db.sync_parsing import _parse_debian_tracker_release_entry as _parse_debian_tracker_release_entry
from agent_bom.db.sync_parsing import _parse_ghsa_version_range as _parse_ghsa_version_range
from agent_bom.db.sync_parsing import _parse_osv_entry as _parse_osv_entry
from agent_bom.db.sync_parsing import _window_coverage as _window_coverage


def sync_osv(
    conn: sqlite3.Connection,
    url: Optional[str] = None,
    max_entries: int = 0,
    progress: Callable[[int, int | None], None] | None = None,
    ecosystem: str | None = None,
) -> int:
    """Download and ingest an OSV bulk export.

    Args:
        conn: open DB connection.
        url: override URL (for testing).
        max_entries: stop after ingesting this many entries (0 = unlimited; for tests).
        ecosystem: optional allowlisted ecosystem for a smaller official archive.

    Returns the number of advisories ingested.
    """
    import os
    import tempfile

    from agent_bom.http_client import download_to_file

    canonical_ecosystem = _canonical_osv_ecosystem(ecosystem) if ecosystem is not None else None
    src = url or (_osv_bulk_url(canonical_ecosystem) if canonical_ecosystem else _OSV_ALL_ZIP_URL)
    _validate_sync_url(src, "osv url")
    _logger.info("Downloading OSV bulk export from %s …", src)

    # Stream the (hundreds-of-MB) archive to disk in chunks rather than buffering
    # the whole payload — and a second BytesIO copy — in RAM, which OOMs on
    # memory-limited hosts. zipfile reads members lazily from the on-disk path.
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".zip", prefix="osv-all-")
    os.close(tmp_fd)
    count = 0
    try:
        try:
            download_to_file(src, tmp_path, timeout=300, progress=progress)
        except Exception as exc:
            _logger.error("Failed to download OSV export: %s", exc)
            raise

        with zipfile.ZipFile(tmp_path) as zf:
            names = zf.namelist()
            _logger.info("OSV zip contains %d files", len(names))
            for name in names:
                if max_entries and count >= max_entries:
                    break
                if not name.endswith(".json"):
                    continue
                content = zf.read(name)
                ingested = _ingest_osv_file(conn, content, name)
                count += ingested
                if count % _BATCH_SIZE == 0 and count > 0:
                    conn.commit()
                    _logger.debug("Ingested %d OSV advisories …", count)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    conn.commit()
    if max_entries > 0:
        metadata = {"coverage": "partial", "ecosystems": []}
    elif canonical_ecosystem is None:
        metadata = {"coverage": "all_ecosystems"}
    else:
        previous = _read_sync_metadata(conn, "osv")
        if previous.get("coverage") == "all_ecosystems":
            metadata = previous
        else:
            selected = {
                _canonical_osv_ecosystem(str(item))
                for item in previous.get("ecosystems", [])
                if isinstance(item, str) and item.strip().lower() in {e.lower() for e in OSV_APPLICATION_ECOSYSTEMS}
            }
            selected.add(canonical_ecosystem)
            metadata = {
                "coverage": "selected_ecosystems",
                "ecosystems": sorted(selected, key=str.lower),
            }
    _update_sync_meta(conn, "osv", count, metadata)
    _logger.info("OSV sync complete: %d advisories ingested", count)
    return count


def _ingest_ghsa_advisory(
    conn: sqlite3.Connection,
    advisory: dict,
    normalize_package_name: object,
) -> bool:
    """Ingest a single GHSA advisory into the DB. Returns True if ingested."""
    ghsa_id = advisory.get("ghsa_id", "")
    cve_id = advisory.get("cve_id") or ""
    # Use CVE ID if available (allows dedup with OSV entries), else GHSA ID
    vuln_id = cve_id if cve_id else ghsa_id
    if not vuln_id:
        return False

    # The REST listing includes withdrawn advisories (``withdrawn_at`` set).
    # Retract a copy this source ingested earlier, as the OSV path does, but
    # leave a record another source owns under the same id.
    if advisory.get("withdrawn_at"):
        if conn.execute("SELECT 1 FROM vulns WHERE id = ? AND source = 'ghsa'", (vuln_id,)).fetchone():
            conn.execute("DELETE FROM affected WHERE vuln_id = ?", (vuln_id,))
            conn.execute("DELETE FROM vulns WHERE id = ?", (vuln_id,))
        return False

    summary = (advisory.get("summary") or "")[:500]
    severity_raw = (advisory.get("severity") or "unknown").lower()
    severity = severity_raw if severity_raw in ("critical", "high", "medium", "low") else "unknown"

    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_obj = advisory.get("cvss") or {}
    if cvss_obj:
        cvss_vector = cvss_obj.get("vector_string")
        cvss_score = _normalize_sync_cvss_score(cvss_obj.get("score"))
        if cvss_score is None:
            cvss_score = _normalize_sync_cvss_score(cvss_vector)

    # If CVSS score present but severity not, derive it
    if severity == "unknown" and cvss_score is not None:
        severity = _cvss_to_severity(cvss_score)

    published = advisory.get("published_at") or ""
    modified = advisory.get("updated_at") or ""

    # Collect affected package rows
    vulnerabilities = advisory.get("vulnerabilities") or []
    fixed_version: Optional[str] = None
    affected_rows: list[dict] = []

    for vuln in vulnerabilities:
        pkg = vuln.get("package") or {}
        ecosystem = pkg.get("ecosystem", "")
        pkg_name = pkg.get("name", "")
        if not ecosystem or not pkg_name:
            continue

        db_ecosystem = _normalize_ghsa_db_ecosystem(str(ecosystem))
        norm_name = normalize_package_name(pkg_name, db_ecosystem)  # type: ignore[operator]
        version_range = vuln.get("vulnerable_version_range") or ""
        patched = vuln.get("first_patched_version") or ""
        introduced, fixed = _parse_ghsa_version_range(version_range)

        # Prefer explicit patched version over parsed fixed
        if patched and not fixed:
            fixed = patched
        if fixed and fixed_version is None:
            fixed_version = fixed

        affected_rows.append(
            {
                "vuln_id": vuln_id,
                "ecosystem": db_ecosystem,
                "package_name": norm_name,
                "introduced": introduced,
                "fixed": fixed,
                "last_affected": "",
            }
        )

    # Extract CWE IDs from GHSA advisory
    ghsa_cwes: list[str] = []
    for cwe_entry in advisory.get("cwes", []):
        cwe_val = cwe_entry.get("cwe_id", "") if isinstance(cwe_entry, dict) else ""
        if cwe_val.startswith("CWE-"):
            ghsa_cwes.append(cwe_val)

    conn.execute(
        """
        INSERT OR REPLACE INTO vulns
            (id, summary, severity, cvss_score, cvss_vector, fixed_version, cwe_ids, aliases, published, modified, source)
        VALUES
            (:id, :summary, :severity, :cvss_score, :cvss_vector, :fixed_version, :cwe_ids, :aliases, :published, :modified, :source)
        """,
        {
            "id": vuln_id,
            "summary": summary,
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "fixed_version": fixed_version,
            "cwe_ids": ",".join(ghsa_cwes),
            "aliases": ",".join(filter(None, [ghsa_id if vuln_id != ghsa_id else "", cve_id if vuln_id != cve_id else ""])),
            "published": published,
            "modified": modified,
            "source": "ghsa",
        },
    )
    for aff in affected_rows:
        conn.execute(
            """
            INSERT OR REPLACE INTO affected
                (vuln_id, ecosystem, package_name, introduced, fixed, last_affected)
            VALUES
                (:vuln_id, :ecosystem, :package_name, :introduced, :fixed, :last_affected)
            """,
            aff,
        )
    return True


def sync_ghsa(
    conn: sqlite3.Connection,
    url: Optional[str] = None,
    github_token: Optional[str] = None,
    max_entries: int = 5000,
    ecosystems: Optional[list[str]] = None,
) -> int:
    """Fetch GitHub Security Advisories across all supported ecosystems and store in DB.

    Iterates over each ecosystem (pip, npm, go, maven, nuget, rubygems, rust)
    and paginates through ALL reviewed advisories.  No package-name filtering is
    applied — every advisory for the requested ecosystems is ingested.

    Uses the GHSA REST API (``GET /advisories``).  If *github_token* is provided
    (or ``GITHUB_TOKEN`` env var is set), higher rate limits apply (5000/hr vs 60/hr).

    Args:
        conn: open DB connection.
        url: base URL override (for testing — must be HTTPS).
        github_token: GitHub personal access token or Actions token.
        max_entries: maximum total advisories to ingest across all ecosystems (default 5000).
        ecosystems: list of GHSA ecosystem names to sync (default: all from GHSA_ECOSYSTEMS).

    Returns the number of advisories ingested.
    """
    import os
    import time

    from agent_bom.http_client import fetch_json

    base_url = url or _GHSA_REST_URL
    _validate_sync_url(base_url, "ghsa url")

    token = github_token or os.environ.get("GITHUB_TOKEN")
    target_ecosystems = [ecosystem.lower() for ecosystem in (ecosystems or list(GHSA_ECOSYSTEMS))]
    unsupported = sorted(set(target_ecosystems) - set(GHSA_ECOSYSTEMS))
    if unsupported:
        supported = ", ".join(GHSA_ECOSYSTEMS)
        raise ValueError(f"Unsupported GHSA ecosystem(s): {', '.join(unsupported)}. Supported ecosystems: {supported}")

    _logger.info(
        "Fetching GHSA advisories from %s for ecosystems: %s",
        base_url,
        ", ".join(target_ecosystems),
    )

    count = 0
    per_page = 100
    eco_counts: dict[str, int] = {}

    from agent_bom.package_utils import normalize_package_name

    cap_hit = False
    sync_failed = False
    for ecosystem in target_ecosystems:
        if count >= max_entries:
            cap_hit = True
            break

        eco_count = 0
        page = 1

        while count < max_entries:
            fetch_url = f"{base_url}?type=reviewed&ecosystem={ecosystem}&per_page={per_page}&page={page}"
            hdrs: dict[str, str] = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            if token:
                hdrs["Authorization"] = f"Bearer {token}"

            try:
                advisories = fetch_json(fetch_url, timeout=30, headers=hdrs)
            except Exception as exc:
                # Don't silently abandon: record that this sync is incomplete so
                # the metadata reflects degraded coverage and a reader/operator
                # can see the gap (mirrors the NVD/Alpine sync_failed pattern).
                _logger.error("Failed to fetch GHSA page %d for %s: %s", page, ecosystem, exc)
                sync_failed = True
                break

            if not advisories:
                break  # No more pages for this ecosystem

            for advisory in advisories:
                if count >= max_entries:
                    cap_hit = True
                    break

                if _ingest_ghsa_advisory(conn, advisory, normalize_package_name):
                    count += 1
                    eco_count += 1

                    if count % _BATCH_SIZE == 0:
                        conn.commit()
                        _logger.debug("Ingested %d GHSA advisories …", count)

            page += 1

            # Respect GitHub unauthenticated rate limit — brief pause between pages
            if not token:
                time.sleep(1)

        eco_counts[ecosystem] = eco_count

    conn.commit()
    _update_sync_meta(
        conn,
        "ghsa",
        count,
        {
            "ecosystems_requested": target_ecosystems,
            "ecosystem_counts": eco_counts,
            "max_entries": max_entries,
            "cap_hit": cap_hit,
            "sync_failed": sync_failed,
            "coverage": "partial" if sync_failed else ("truncated" if cap_hit else "complete_for_requested_pages"),
        },
    )
    if cap_hit:
        _logger.warning(
            "GHSA sync hit max_entries=%d; coverage is truncated. Increase --max-ghsa-entries for fuller coverage.",
            max_entries,
        )
    eco_summary = ", ".join(f"{e}={c}" for e, c in eco_counts.items() if c > 0)
    _logger.info(
        "GHSA sync complete: ingested %d advisories across %d ecosystems (%s)",
        count,
        len([c for c in eco_counts.values() if c > 0]),
        eco_summary or "none",
    )
    return count


def sync_nvd(
    conn: sqlite3.Connection,
    nvd_api_key: Optional[str] = None,
    url: Optional[str] = None,
    max_entries: int = 1000,
    limiter: Optional[NvdRateLimiter] = None,
) -> int:
    """Enrich local DB entries missing CVSS data using the NVD API.

    Queries the DB for CVE-backed rows with unknown severity, then fetches
    CVSS v3.1 data from NVD and updates the ``vulns`` table in-place. Distro
    advisory rows such as ``DEBIAN-CVE-*`` are resolved through their embedded
    or aliased canonical CVE ID so native image scans do not stay unknown.

    Rate limiting:
        - Without key: 5 requests per rolling 30s
        - With ``NVD_API_KEY``: 50 requests per rolling 30s

    Args:
        conn: open DB connection.
        nvd_api_key: NVD API key (or set ``NVD_API_KEY`` env var).
        url: base URL override for the NVD API (must be HTTPS).
        max_entries: maximum number of CVEs to enrich (default 1000).

    Returns the number of CVEs successfully enriched.
    """
    import os
    import urllib.parse

    from agent_bom.http_client import fetch_json

    base_url = url or _NVD_API_URL
    _validate_sync_url(base_url, "nvd url")

    api_key = nvd_api_key or os.environ.get("NVD_API_KEY")
    # Rolling NVD budget (5 or 50 requests / 30s), shared with the window sync when passed in.
    limiter = limiter or NvdRateLimiter.for_key(api_key)

    # Find CVE-backed rows in our DB that are missing CVSS data. Some OSV
    # distro advisories use IDs such as DEBIAN-CVE-2014-6271 but still map to
    # the canonical CVE in aliases or in the ID suffix.
    total_candidates = conn.execute(
        """
        SELECT COUNT(*) FROM vulns
        WHERE (severity = 'unknown' OR cvss_score IS NULL) AND source != 'nvd'
          AND (id LIKE '%CVE-%' OR aliases LIKE '%CVE-%')
        """
    ).fetchone()[0]
    rows = conn.execute(
        """
        SELECT id, COALESCE(aliases, '') AS aliases FROM vulns
        WHERE (severity = 'unknown' OR cvss_score IS NULL) AND source != 'nvd'
          AND (id LIKE '%CVE-%' OR aliases LIKE '%CVE-%')
        LIMIT :max_entries
        """,
        {"max_entries": max_entries},
    ).fetchall()

    row_targets: list[tuple[str, str]] = []
    for row in rows:
        candidates = _nvd_cve_candidates(row["id"], row["aliases"])
        if candidates:
            row_targets.append((row["id"], candidates[0]))

    if not row_targets:
        _logger.info("NVD enrichment: no CVEs missing CVSS data — nothing to do")
        _update_sync_meta(
            conn,
            "nvd",
            0,
            {
                "mode": "enrichment_only",
                "candidate_rows": total_candidates,
                "selected_rows": 0,
                "max_entries": max_entries,
                "cap_hit": total_candidates > max_entries,
            },
        )
        return 0

    _logger.info("NVD enrichment: fetching CVSS data for %d CVE-backed rows …", len(row_targets))

    enriched = 0

    for row_id, cve_id in row_targets:
        fetch_url = f"{base_url}?{urllib.parse.urlencode({'cveId': cve_id})}"
        # NVD API 2.0 honours the key only in the apiKey header; never the URL.
        headers = {"Accept": "application/json", **({"apiKey": api_key} if api_key else {})}
        limiter.acquire()

        try:
            data = fetch_json(fetch_url, timeout=30, headers=headers)
        except Exception as exc:
            _logger.debug("NVD API error for %s: %s", cve_id, exc)
            continue

        # Extract CVSS v3.1 metrics
        cve_items = data.get("vulnerabilities") or []
        if not cve_items:
            continue

        cve_data = cve_items[0].get("cve") or {}
        metrics = cve_data.get("metrics") or {}
        cvss_score: Optional[float] = None
        cvss_vector: Optional[str] = None
        severity: Optional[str] = None

        # Prefer CVSSv31, fall back to CVSSv30, then CVSSv2
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key) or []
            if not metric_list:
                continue
            cvss_data = metric_list[0].get("cvssData") or {}
            raw_score = cvss_data.get("baseScore")
            if raw_score is not None:
                try:
                    cvss_score = float(raw_score)
                except (TypeError, ValueError):
                    pass
            cvss_vector = cvss_data.get("vectorString")
            raw_sev = (cvss_data.get("baseSeverity") or "").lower()
            if raw_sev in ("critical", "high", "medium", "low"):
                severity = raw_sev
            break

        # Extract CWE IDs from NVD weaknesses
        nvd_cwes: list[str] = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_val = desc.get("value", "")
                if cwe_val.startswith("CWE-") and cwe_val not in nvd_cwes:
                    nvd_cwes.append(cwe_val)

        if cvss_score is None and not nvd_cwes:
            continue

        if not severity and cvss_score is not None:
            severity = _cvss_to_severity(cvss_score)

        # Merge NVD CWE IDs with any existing ones (from OSV/GHSA)
        if nvd_cwes:
            existing_cwes_raw = conn.execute("SELECT cwe_ids FROM vulns WHERE id=?", (row_id,)).fetchone()
            existing_cwes = set((existing_cwes_raw[0] or "").split(",")) if existing_cwes_raw and existing_cwes_raw[0] else set()
            existing_cwes.discard("")
            merged = list(existing_cwes | set(nvd_cwes))
            merged_str = ",".join(sorted(merged))
        else:
            merged_str = None  # no update needed

        if cvss_score is not None:
            if merged_str is not None:
                conn.execute(
                    "UPDATE vulns SET cvss_score=?, cvss_vector=?, severity=?, cwe_ids=? WHERE id=?",
                    (cvss_score, cvss_vector, severity, merged_str, row_id),
                )
            else:
                conn.execute(
                    "UPDATE vulns SET cvss_score=?, cvss_vector=?, severity=? WHERE id=?",
                    (cvss_score, cvss_vector, severity, row_id),
                )
        elif merged_str is not None:
            conn.execute(
                "UPDATE vulns SET cwe_ids=? WHERE id=?",
                (merged_str, row_id),
            )
        enriched += 1

        if enriched % _BATCH_SIZE == 0:
            conn.commit()
            _logger.debug("NVD enriched %d CVEs …", enriched)

    conn.commit()
    _update_sync_meta(
        conn,
        "nvd",
        enriched,
        {
            "mode": "enrichment_only",
            "candidate_rows": total_candidates,
            "selected_rows": len(row_targets),
            "max_entries": max_entries,
            "cap_hit": total_candidates > max_entries,
        },
    )
    _logger.info("NVD enrichment complete: %d CVEs updated", enriched)
    return enriched


def _sync_nvd_keyless(conn: sqlite3.Connection, url: Optional[str], max_entries: Optional[int]) -> int:
    """Keyless NVD: the bounded new-CVE window first, then the CVSS/CWE backfill.

    Both phases share one anonymous rate budget. The window's checkpoint and
    status stay the source-level ``nvd`` metadata; the backfill is nested under
    ``enrichment`` so it can never overwrite the window cursor.
    """
    limiter = NvdRateLimiter.for_key(None)
    ingested = sync_nvd_incremental(conn, url=url, max_results=max_entries, limiter=limiter)
    window_meta = _read_sync_metadata(conn, "nvd")
    backfilled = sync_nvd(conn, url=url, max_entries=max_entries or 1000, limiter=limiter)
    _update_sync_meta(conn, "nvd", ingested + backfilled, {**window_meta, "enrichment": _read_sync_metadata(conn, "nvd")})
    return ingested + backfilled


# NVD is a default source: it carries CVEs (and CPE ranges for runtimes such as
# PHP) that no other feed has yet. Its sync is incremental and newest first.
DEFAULT_SYNC_SOURCES: tuple[str, ...] = ("osv", "alpine", "debian", "epss", "kev", "nvd")


def sync_db(
    path: Optional[Path] = None,
    sources: Optional[list[str]] = None,
    osv_url: Optional[str] = None,
    epss_url: Optional[str] = None,
    kev_url: Optional[str] = None,
    ghsa_url: Optional[str] = None,
    nvd_url: Optional[str] = None,
    debian_url: Optional[str] = None,
    debian_elts_url: Optional[str] = None,
    max_osv_entries: int = 0,
    max_ghsa_entries: int = 5000,
    max_nvd_entries: Optional[int] = None,
    github_token: Optional[str] = None,
    nvd_api_key: Optional[str] = None,
    ghsa_ecosystems: Optional[list[str]] = None,
    osv_ecosystems: Optional[list[str]] = None,
    progress: Callable[[str, str, int, int | None], None] | None = None,
) -> dict:
    """Sync the local vuln DB from all (or selected) upstream sources.

    Args:
        path: DB file path (default: DB_PATH from schema.py).
        sources: list of source names to sync, e.g. ["osv", "kev"]. Default: ``DEFAULT_SYNC_SOURCES``.
                 Note: "nvd" is NOT in the default set — it is slow without an API key.
                 Keyless "nvd" ingests a 14-day window of new/modified CVEs then
                 backfills CVSS/CWE; with a key it ingests a 120-day window.
        osv_url / epss_url / kev_url / ghsa_url / nvd_url: URL overrides (for testing).
        max_osv_entries: limit for OSV entries (0 = unlimited; for tests).
        max_ghsa_entries: limit for GHSA entries (default 5000).
        max_nvd_entries: NVD records read per window run (default: whole window keyed,
                 60,000 keyless) and the keyless CVSS backfill cap (default 1000).
        github_token: override GITHUB_TOKEN env var for GHSA fetches.
        nvd_api_key: override NVD_API_KEY env var for NVD fetches.
        ghsa_ecosystems: list of GHSA ecosystem names to sync (default: all supported).
        osv_ecosystems: selected OSV application ecosystems (default: all ecosystems).
        progress: optional callback receiving ``(source, phase, current, total)``.
            Phases are ``start``, ``download`` (OSV bytes), and ``complete``.

    Returns a dict of {source: record_count}.
    """
    import os

    from agent_bom.db.schema import DB_PATH, init_db

    db_path = path or DB_PATH
    # The update rewrites the database, so it is the right place to pay for a
    # full integrity check — and the only place that still does.
    conn = init_db(db_path, verify_integrity=True)
    enabled = set(sources or DEFAULT_SYNC_SOURCES)
    results: dict[str, int] = {}

    def notify(source: str, phase: str, current: int = 0, total: int | None = None) -> None:
        if progress is not None:
            progress(source, phase, current, total)

    def run_source(source: str, sync: Callable[[], int]) -> None:
        notify(source, "start")
        count = sync()
        results[source] = count
        partial = _read_sync_metadata(conn, source).get("status") == "partial"
        notify(source, "partial" if partial else "complete", count)

    try:
        if "osv" in enabled:
            if osv_ecosystems:
                canonical_scopes = list(dict.fromkeys(_canonical_osv_ecosystem(item) for item in osv_ecosystems))
                total_osv = 0
                for ecosystem in canonical_scopes:
                    label = f"osv:{ecosystem}"

                    def scoped_progress(current: int, total: int | None, source: str = label) -> None:
                        notify(source, "download", current, total)

                    notify(label, "start")
                    count = sync_osv(
                        conn,
                        url=osv_url,
                        max_entries=max_osv_entries,
                        progress=scoped_progress,
                        ecosystem=ecosystem,
                    )
                    total_osv += count
                    notify(label, "complete", count)
                results["osv"] = total_osv
                # ``sync_meta`` is source-level, so a multi-ecosystem update
                # must report the aggregate operation rather than whichever
                # scoped archive happened to run last. Preserve the coverage
                # metadata accumulated by ``sync_osv``.
                _update_sync_meta(conn, "osv", total_osv, _read_sync_metadata(conn, "osv"))
            else:
                run_source(
                    "osv",
                    lambda: sync_osv(
                        conn,
                        url=osv_url,
                        max_entries=max_osv_entries,
                        progress=lambda current, total: notify("osv", "download", current, total),
                    ),
                )
        if "alpine" in enabled:
            run_source("alpine", lambda: sync_alpine_secdb(conn))
        # Debian tracker runs after OSV so its authoritative per-release backports
        # override OSV's sparser/absent distro rows (and preserve OSV severity via
        # INSERT OR IGNORE on the shared DEBIAN-CVE-* id).
        if "debian" in enabled:
            run_source("debian", lambda: sync_debian_tracker(conn, url=debian_url, elts_url=debian_elts_url))
        if "epss" in enabled:
            run_source("epss", lambda: sync_epss(conn, url=epss_url))
        if "kev" in enabled:
            run_source("kev", lambda: sync_kev(conn, url=kev_url))
        if "ghsa" in enabled:
            token = github_token or os.environ.get("GITHUB_TOKEN")
            run_source(
                "ghsa",
                lambda: sync_ghsa(
                    conn,
                    url=ghsa_url,
                    github_token=token,
                    max_entries=max_ghsa_entries,
                    ecosystems=ghsa_ecosystems,
                ),
            )
        if "nvd" in enabled:
            key = nvd_api_key or os.environ.get("NVD_API_KEY")
            if key:
                run_source(
                    "nvd",
                    lambda: sync_nvd_incremental(
                        conn,
                        nvd_api_key=key,
                        url=nvd_url,
                        max_results=max_nvd_entries,
                    ),
                )
            else:
                run_source("nvd", lambda: _sync_nvd_keyless(conn, nvd_url, max_nvd_entries))
    finally:
        # Fold the (potentially large) -wal back into the main DB so concurrent
        # readers don't race a big write-ahead log right after a sync.
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error as exc:
            _logger.debug("WAL checkpoint after sync_db skipped: %s", exc)
        conn.close()

    return results


_EXPORTS = {
    "_EPSS_CSV_URL": "agent_bom.db.sync_common",
    "_EPSS_REDIRECT_HOSTS": "agent_bom.db.sync_common",
    "_KEV_JSON_URL": "agent_bom.db.sync_common",
    "_ALPINE_SECDB_BASE_URL": "agent_bom.db.sync_common",
    "_ALPINE_SECDB_REPOS": "agent_bom.db.sync_common",
    "_DEBIAN_TRACKER_JSON_URL": "agent_bom.db.sync_common",
    "_DEBIAN_ELTS_TRACKER_JSON_URL": "agent_bom.db.sync_common",
    "_DEBIAN_CODENAME_TO_RELEASE": "agent_bom.db.sync_common",
    "_AI_ML_PACKAGES": "agent_bom.db.sync_common",
    "_GHSA_API_TO_DB_ECOSYSTEM": "agent_bom.db.sync_common",
    "_CVE_ID_RE": "agent_bom.db.sync_common",
    "_DEBIAN_CVE_ID_RE": "agent_bom.db.sync_common",
    "_now_utc": "agent_bom.db.sync_common",
    "_iter_alpine_secfix_ids": "agent_bom.db.sync_distributions",
    "_upsert_alpine_vuln_stub": "agent_bom.db.sync_distributions",
    "_ingest_alpine_secdb_payload": "agent_bom.db.sync_distributions",
    "_upsert_debian_tracker_vuln_stub": "agent_bom.db.sync_distributions",
    "_ingest_debian_tracker_payload": "agent_bom.db.sync_distributions",
    "_resolve_epss_redirect": "agent_bom.db.sync_exploit_feeds",
    "_fetch_epss_csv_bytes": "agent_bom.db.sync_exploit_feeds",
    "_sync_meta_has_metadata_column": "agent_bom.db.sync_common",
}


def __getattr__(name: str) -> Any:
    module = _EXPORTS.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module), name)
    globals()[name] = value
    return value
