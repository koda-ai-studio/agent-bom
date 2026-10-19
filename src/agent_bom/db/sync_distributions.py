"""Alpine and Debian distribution advisory ingestion."""

from __future__ import annotations

import json
import sqlite3
from typing import Optional

from agent_bom.db.sync_common import (
    _ALPINE_SECDB_BASE_URL,
    _ALPINE_SECDB_REPOS,
    _BATCH_SIZE,
    _DEBIAN_CODENAME_TO_RELEASE,
    _DEBIAN_ELTS_TRACKER_JSON_URL,
    _DEBIAN_TRACKER_JSON_URL,
    _logger,
    _update_sync_meta,
    _validate_sync_url,
)
from agent_bom.db.sync_parsing import _parse_alpine_secfix_tokens as _parse_alpine_secfix_tokens
from agent_bom.db.sync_parsing import _parse_debian_tracker_release_entry as _parse_debian_tracker_release_entry
from agent_bom.package_utils import ALPINE_SECDB_BRANCHES as _ALPINE_SECDB_BRANCHES


def _iter_alpine_secfix_ids(secfixes: object) -> dict[str, list[str]]:
    """Return {fixed_version: [vuln_ids...]} for one Alpine secdb package."""
    if not isinstance(secfixes, dict):
        return {}

    parsed: dict[str, list[str]] = {}
    for fixed_version, raw_ids in secfixes.items():
        if not isinstance(fixed_version, str):
            continue
        vuln_ids: list[str] = []
        if isinstance(raw_ids, list):
            for item in raw_ids:
                vuln_ids.extend(_parse_alpine_secfix_tokens(item))
        if vuln_ids:
            parsed[fixed_version] = vuln_ids
    return parsed


def _upsert_alpine_vuln_stub(
    conn: sqlite3.Connection,
    vuln_id: str,
    package_name: str,
    fixed_version: str,
) -> None:
    """Insert a minimal vulnerability row unless a richer row already exists."""
    conn.execute(
        """
        INSERT OR IGNORE INTO vulns
            (id, summary, severity, cvss_score, cvss_vector, fixed_version, published, modified, source, cwe_ids, aliases)
        VALUES
            (?, ?, 'unknown', NULL, NULL, ?, '', '', 'alpine-secdb', '', '')
        """,
        (
            vuln_id,
            f"Alpine Linux secdb advisory for {package_name}",
            fixed_version,
        ),
    )
    conn.execute(
        """
        UPDATE vulns
        SET fixed_version = CASE
            WHEN fixed_version IS NULL OR fixed_version = '' THEN ?
            ELSE fixed_version
        END
        WHERE id = ?
        """,
        (fixed_version, vuln_id),
    )


def _ingest_alpine_secdb_payload(
    conn: sqlite3.Connection,
    payload: dict,
    *,
    distro_version: str,
    repository: str,
) -> int:
    """Ingest one Alpine secdb JSON document into the local DB.

    Returns the number of affected package/version mappings processed.
    """
    from agent_bom.package_utils import normalize_package_name

    ecosystem = f"alpine:{distro_version}".lower()
    processed = 0

    for package_entry in payload.get("packages", []):
        if not isinstance(package_entry, dict):
            continue
        pkg = package_entry.get("pkg", {})
        if not isinstance(pkg, dict):
            continue
        package_name = pkg.get("name", "")
        if not isinstance(package_name, str) or not package_name:
            continue

        normalized_name = normalize_package_name(package_name, "apk")
        secfixes = _iter_alpine_secfix_ids(pkg.get("secfixes"))
        for fixed_version, vuln_ids in secfixes.items():
            for vuln_id in vuln_ids:
                _upsert_alpine_vuln_stub(conn, vuln_id, normalized_name, fixed_version)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO affected
                        (vuln_id, ecosystem, package_name, introduced, fixed, last_affected)
                    VALUES
                        (?, ?, ?, '0', ?, '')
                    """,
                    (vuln_id, ecosystem, normalized_name, fixed_version),
                )
                processed += 1

    _logger.debug(
        "Ingested %d Alpine secdb mappings for %s/%s",
        processed,
        distro_version,
        repository,
    )
    return processed


def sync_alpine_secdb(
    conn: sqlite3.Connection,
    *,
    base_url: Optional[str] = None,
    branches: tuple[str, ...] = _ALPINE_SECDB_BRANCHES,
    repositories: tuple[str, ...] = _ALPINE_SECDB_REPOS,
) -> int:
    """Download and ingest Alpine Linux secdb feeds.

    Alpine secdb carries package-level fix metadata for apk packages and is often
    fresher than OSV for distro-specific Alpine advisories.
    """
    from agent_bom.http_client import fetch_json

    root = (base_url or _ALPINE_SECDB_BASE_URL).rstrip("/")
    _validate_sync_url(root, "alpine secdb base url")

    count = 0
    for branch in branches:
        for repository in repositories:
            url = f"{root}/{branch}/{repository}.json"
            _validate_sync_url(url, "alpine secdb url")
            _logger.info("Downloading Alpine secdb from %s …", url)
            data = fetch_json(url, timeout=30)
            if not isinstance(data, dict):
                raise ValueError(f"Unexpected Alpine secdb payload type for {url}: {type(data)!r}")
            count += _ingest_alpine_secdb_payload(
                conn,
                data,
                distro_version=branch,
                repository=repository,
            )
            conn.commit()

    _update_sync_meta(conn, "alpine", count)
    _logger.info("Alpine secdb sync complete: %d package advisory mappings ingested", count)
    return count


def _upsert_debian_tracker_vuln_stub(
    conn: sqlite3.Connection,
    vuln_id: str,
    cve_id: str,
    summary: str,
    source: str,
) -> None:
    """Insert a minimal vuln row, preserving any richer existing record.

    The tracker shares OSV's ``DEBIAN-CVE-*`` identifier scheme, so when OSV has
    already ingested the same advisory (supported releases) ``INSERT OR IGNORE``
    keeps OSV's severity/CVSS. For EOL releases OSV has nothing, so this seeds a
    stub whose CVE alias lets EPSS/KEV/NVD enrichment fill severity later.
    """
    conn.execute(
        """
        INSERT OR IGNORE INTO vulns
            (id, summary, severity, cvss_score, cvss_vector, fixed_version, published, modified, source, cwe_ids, aliases)
        VALUES
            (?, ?, 'unknown', NULL, NULL, NULL, '', '', ?, '', ?)
        """,
        (vuln_id, summary or f"Debian security tracker advisory for {cve_id}", source, cve_id),
    )
    # Backfill alias/summary on a pre-existing stub that lacked them; never
    # overwrite data already present (keeps OSV/NVD enrichment intact).
    conn.execute(
        """
        UPDATE vulns
        SET aliases = CASE WHEN aliases IS NULL OR aliases = '' THEN ? ELSE aliases END,
            summary = CASE WHEN summary IS NULL OR summary = '' THEN ? ELSE summary END
        WHERE id = ?
        """,
        (cve_id, summary or f"Debian security tracker advisory for {cve_id}", vuln_id),
    )


def _ingest_debian_tracker_payload(
    conn: sqlite3.Connection,
    payload: dict,
    *,
    source: str,
) -> int:
    """Ingest one Debian tracker JSON document (``{src_pkg: {cve: {...}}}``).

    Rows are keyed by Debian *source* package name (matching OSV's Debian data
    and how image/filesystem scans resolve binary→source). Returns the number of
    per-release advisory mappings written.
    """
    from agent_bom.package_utils import normalize_package_name

    processed = 0
    pending = 0
    for src_pkg, cves in payload.items():
        if not isinstance(src_pkg, str) or not src_pkg or not isinstance(cves, dict):
            continue
        norm_src = normalize_package_name(src_pkg, "deb")
        for cve_id, info in cves.items():
            if not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-") or not isinstance(info, dict):
                continue
            releases = info.get("releases")
            if not isinstance(releases, dict):
                continue
            canonical_cve = cve_id.upper()
            vuln_id = f"DEBIAN-{canonical_cve}"
            summary = str(info.get("description") or "")[:500]
            stub_written = False

            for codename, rel_entry in releases.items():
                release = _DEBIAN_CODENAME_TO_RELEASE.get(str(codename).strip().lower())
                if release is None:
                    continue
                parsed = _parse_debian_tracker_release_entry(rel_entry)
                if parsed is None:
                    continue
                status, fixed = parsed

                if not stub_written:
                    _upsert_debian_tracker_vuln_stub(conn, vuln_id, canonical_cve, summary, source)
                    stub_written = True

                ecosystem = f"debian:{release}"
                if status == "resolved":
                    # The tracker's backported fix is authoritative for Debian —
                    # overwrite any sparser OSV row for the same release.
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO affected
                            (vuln_id, ecosystem, package_name, introduced, fixed, last_affected)
                        VALUES (?, ?, ?, '0', ?, '')
                        """,
                        (vuln_id, ecosystem, norm_src, fixed),
                    )
                else:  # open — affected, no fix for this release
                    # Never clobber an existing (OSV) fixed row with "no fix".
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO affected
                            (vuln_id, ecosystem, package_name, introduced, fixed, last_affected)
                        VALUES (?, ?, ?, '0', '', '')
                        """,
                        (vuln_id, ecosystem, norm_src),
                    )
                processed += 1
                pending += 1
                if pending >= _BATCH_SIZE:
                    conn.commit()
                    pending = 0

    conn.commit()
    _logger.debug("Ingested %d Debian tracker mappings from %s", processed, source)
    return processed


def sync_debian_tracker(
    conn: sqlite3.Connection,
    *,
    url: Optional[str] = None,
    elts_url: Optional[str] = None,
    include_elts: bool = True,
) -> int:
    """Download and ingest the Debian Security Tracker feed(s).

    Ingests the main tracker (supported releases) and, by default, the Extended
    LTS tracker (end-of-life releases such as buster/Debian 10). The ELTS feed is
    best-effort: a failure there degrades only EOL coverage and never aborts the
    sync. Returns the total number of per-release advisory mappings ingested.
    """
    from agent_bom.http_client import fetch_bytes

    feeds: list[tuple[str, str]] = [(url or _DEBIAN_TRACKER_JSON_URL, "debian-tracker")]
    if include_elts:
        feeds.append((elts_url or _DEBIAN_ELTS_TRACKER_JSON_URL, "debian-elts-tracker"))

    total = 0
    for feed_url, feed_source in feeds:
        _validate_sync_url(feed_url, "debian tracker url")
        best_effort = feed_source == "debian-elts-tracker"
        _logger.info("Downloading Debian security tracker from %s …", feed_url)
        try:
            raw = fetch_bytes(feed_url, timeout=120)
            payload = json.loads(raw)
        except Exception as exc:
            if best_effort:
                _logger.warning("Debian ELTS tracker unavailable (EOL coverage degraded): %s", exc)
                continue
            _logger.error("Failed to download Debian security tracker: %s", exc)
            raise
        if not isinstance(payload, dict):
            if best_effort:
                _logger.warning("Debian ELTS tracker returned unexpected payload type: %s", type(payload).__name__)
                continue
            raise ValueError(f"Unexpected Debian tracker payload type for {feed_url}: {type(payload)!r}")
        total += _ingest_debian_tracker_payload(conn, payload, source=feed_source)

    _update_sync_meta(
        conn,
        "debian",
        total,
        {
            "releases": sorted(set(_DEBIAN_CODENAME_TO_RELEASE.values())),
            "feeds": [name for _u, name in feeds],
            "coverage": "per_release_status_with_backported_fixes",
        },
    )
    _logger.info("Debian security tracker sync complete: %d release advisory mappings ingested", total)
    return total
