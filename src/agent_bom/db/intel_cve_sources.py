"""CVE records from the enrichment feeds when the advisory tables hold none.

CISA KEV, FIRST EPSS and the Node.js core index each know something about a
CVE that may have no OSV record (Log4Shell is in KEV and EPSS but in no
PyPI/npm advisory; Node.js core CVEs live only in the Node.js index). A lookup
that only read the advisory tables answered "not found" for them although the
synced database held them. The record built here says which source supplied
each field and leaves the rest empty rather than guessing.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any, Callable

from agent_bom.db.intel_catalog import CANONICAL_INTEL_SOURCES, sync_coverage, sync_meta_source_label
from agent_bom.scanners import nodejs_advisory_data

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_FEED_SOURCES = ("kev", "epss", "nodejs")


def _synced_sources(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute("SELECT source FROM sync_meta WHERE record_count > 0 ORDER BY source").fetchall()
    return [str(row[0]) for row in rows]


def searched_sources(conn: sqlite3.Connection, db_path: Path) -> list[str]:
    """Synced sources a CVE lookup actually reads: advisory tables first, then the feeds."""
    synced = _synced_sources(conn)
    advisory = [source for source in synced if source not in _FEED_SOURCES]
    feeds = [source for source in _FEED_SOURCES if source in synced]
    if "nodejs" in feeds and not (db_path.parent / nodejs_advisory_data.SNAPSHOT_FILENAME).is_file():
        feeds.remove("nodejs")
    return [*advisory, *feeds]


def _join_labels(sources: list[str]) -> str:
    labels = [sync_meta_source_label(source) for source in sources]
    return labels[0] if len(labels) == 1 else f"{', '.join(labels[:-1])} or {labels[-1]}"


def miss_note(advisory_id: str, searched: list[str]) -> str:
    return f"No record of {advisory_id} in {_join_labels(searched)}."


def _kev_record(conn: sqlite3.Connection, cve_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT date_added, due_date, product, vendor_project FROM kev_entries WHERE cve_id = ?", (cve_id,)).fetchone()
    if row is None:
        return None
    return {"source": "kev", "date_added": row[0], "due_date": row[1], "product": row[2], "vendor_project": row[3]}


def _epss_record(conn: sqlite3.Connection, cve_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT probability, percentile, updated_at FROM epss_scores WHERE cve_id = ?", (cve_id,)).fetchone()
    if row is None:
        return None
    return {"source": "epss", "probability": row[0], "percentile": row[1], "updated_at": row[2]}


def _nodejs_entries(db_path: Path, cve_id: str) -> list[dict[str, Any]]:
    try:
        index = nodejs_advisory_data.load_snapshot(db_path.parent / nodejs_advisory_data.SNAPSHOT_FILENAME, origin="synced_snapshot")
    except ValueError:
        return []
    matches: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in index.entries.values():
        if cve_id in entry.get("cve", []):
            matches.setdefault((entry["vulnerable"], entry["patched"]), entry)
    return list(matches.values())


def _nodejs_record(entries: list[dict[str, Any]]) -> dict[str, Any]:
    first = entries[0]
    return {
        "source": "nodejs",
        "description": first.get("description"),
        "severity": str(first.get("severity", "unknown")).strip().lower(),
        "affected_environments": sorted({env for entry in entries for env in entry.get("affectedEnvironments", [])}),
        "reference": first.get("ref"),
    }


def feed_cve_record(conn: sqlite3.Connection, db_path: Path, advisory_id: str, searched: list[str]) -> dict[str, Any] | None:
    """A partial advisory for a CVE known only to the enrichment feeds, or ``None``."""
    cve_id = advisory_id.strip().upper()
    if not _CVE_RE.match(cve_id):
        return None
    kev = _kev_record(conn, cve_id) if "kev" in searched else None
    epss = _epss_record(conn, cve_id) if "epss" in searched else None
    node_entries = _nodejs_entries(db_path, cve_id) if "nodejs" in searched else []
    node = _nodejs_record(node_entries) if node_entries else None
    record_sources = [record for record in (node, kev, epss) if record is not None]
    if not record_sources:
        return None
    severity = node["severity"] if node and node["severity"] not in {"unknown", "none"} else None
    supplied = [record["source"] for record in record_sources]
    links = [{"kind": "cve", "id": cve_id, "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"}]
    if epss:
        links.append({"kind": "epss", "id": cve_id, "url": f"https://api.first.org/data/v1/epss?cve={cve_id}"})
    if node and node.get("reference"):
        links.append({"kind": "nodejs", "id": cve_id, "url": str(node["reference"])})
    return {
        "id": cve_id,
        "canonical_ids": {"cves": [cve_id], "ghsas": [], "osv": [], "cwes": []},
        "summary": node["description"] if node else None,
        "severity": severity,
        "cvss_score": None,
        "cvss_vector": None,
        "fixed_version": None,
        "source": supplied[0],
        "published_at": None,
        "modified_at": None,
        "epss_probability": epss["probability"] if epss else None,
        "epss_percentile": epss["percentile"] if epss else None,
        "is_kev": kev is not None,
        "kev_date_added": kev["date_added"] if kev else None,
        "affected": [
            {
                "ecosystem": "nodejs-core",
                "package_name": "node",
                "introduced": None,
                "fixed": None,
                "last_affected": None,
                "vulnerable": entry["vulnerable"],
                "patched": entry["patched"],
            }
            for entry in node_entries
        ],
        "record_completeness": "partial",
        "record_sources": record_sources,
        "not_found_in": [source for source in searched if source not in supplied],
        "matched_by": "cve_feed",
        "match_method": "cve_feed",
        "match_confidence": "high",
        "match_reason": (
            f"No advisory record holds {cve_id}; {_join_labels(supplied).replace(' or ', ' and ')} list it. "
            "Fields those sources do not carry are left empty."
        ),
        "evidence_links": links,
    }


def feed_or_miss(
    conn: sqlite3.Connection, db_path: Path, raw_id: str, *, source_policy: Callable[[str | None], dict[str, Any]]
) -> dict[str, Any]:
    """The lookup answer when no advisory row matched: a feed record, or a miss naming what was searched."""
    searched = searched_sources(conn, db_path)
    record = feed_cve_record(conn, db_path, raw_id, searched)
    if record is not None:
        catalog_id = next((s.source_id for s in CANONICAL_INTEL_SOURCES if s.sync_meta_source == record["source"]), record["source"])
        record["source_policy"] = source_policy(catalog_id)
        return {"schema_version": "intel.lookup.v1", "found": True, "query": raw_id, "advisory": record}
    database = sync_coverage(conn)
    if database["synced"]:
        database = {**database, "searched": searched, "note": miss_note(raw_id, searched)}
    return {"schema_version": "intel.lookup.v1", "found": False, "query": raw_id, "advisory": None, "database": database}
