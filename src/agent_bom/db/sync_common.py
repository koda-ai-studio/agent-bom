"""Advisory normalization, persistence and source metadata for database sync."""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

from agent_bom.core.cvss import normalize_cvss_score
from agent_bom.db.sync_parsing import _parse_osv_entry as _parse_osv_entry

_logger = logging.getLogger("agent_bom.db.sync")
_normalize_sync_cvss_score = normalize_cvss_score


def _validate_sync_url(url: str, param_name: str = "url") -> None:
    """Reject non-HTTPS URLs for sync sources.

    All sync sources must use HTTPS.  Accepting ``file://`` or ``http://``
    custom URLs would allow an attacker who controls the environment to point
    the syncer at a malicious local file or a plaintext server.

    Raises ``ValueError`` with a descriptive message on invalid URLs.
    """
    if not url.startswith("https://"):
        raise ValueError(
            f"{param_name} must use https:// — got {url!r}. Only HTTPS URLs are accepted for vulnerability database sync sources."
        )


_OSV_ALL_ZIP_URL = "https://osv-vulnerabilities.storage.googleapis.com/all.zip"


OSV_APPLICATION_ECOSYSTEMS = (
    "PyPI",
    "npm",
    "Go",
    "Maven",
    "crates.io",
    "NuGet",
    "RubyGems",
    "Packagist",
)


_EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


_EPSS_REDIRECT_HOSTS = {"epss.cyentia.com", "epss.empiricalsecurity.com"}


_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


_GHSA_REST_URL = "https://api.github.com/advisories"


_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


_ALPINE_SECDB_BASE_URL = "https://secdb.alpinelinux.org"


_ALPINE_SECDB_REPOS = ("main", "community")


def _canonical_osv_ecosystem(ecosystem: str) -> str:
    by_lower = {item.lower(): item for item in OSV_APPLICATION_ECOSYSTEMS}
    canonical = by_lower.get(ecosystem.strip().lower())
    if canonical is None:
        supported = ", ".join(OSV_APPLICATION_ECOSYSTEMS)
        raise ValueError(f"unsupported OSV ecosystem {ecosystem!r}; supported OSV ecosystems: {supported}")
    return canonical


def _osv_bulk_url(ecosystem: str) -> str:
    """Return the official bulk archive URL for one allowlisted ecosystem."""
    canonical = _canonical_osv_ecosystem(ecosystem)
    return f"https://osv-vulnerabilities.storage.googleapis.com/{quote(canonical, safe='.')}/all.zip"


_DEBIAN_TRACKER_JSON_URL = "https://security-tracker.debian.org/tracker/data/json"


_DEBIAN_ELTS_TRACKER_JSON_URL = "https://deb.freexian.com/extended-lts/tracker/data/json"


_DEBIAN_CODENAME_TO_RELEASE = {
    "buster": "10",
    "bullseye": "11",
    "bookworm": "12",
    "trixie": "13",
    "forky": "14",
}


_AI_ML_PACKAGES = frozenset(
    [
        "torch",
        "torchvision",
        "torchaudio",
        "transformers",
        "langchain",
        "langchain-core",
        "openai",
        "anthropic",
        "llama-index",
        "llamaindex",
        "fastapi",
        "uvicorn",
        "numpy",
        "scipy",
        "pandas",
        "scikit-learn",
        "tensorflow",
        "keras",
        "jax",
        "jaxlib",
        "vllm",
        "ray",
        "mlflow",
        "wandb",
        "boto3",
        "azure-ai",
        "google-cloud",
        "huggingface-hub",
        "diffusers",
        "sentence-transformers",
        "pydantic",
        "httpx",
        "requests",
        "aiohttp",
        "cryptography",
        "pillow",
        "opencv-python",
        "mcp",
        "claude-code",
        "crewai",
        "autogen",
        "semantic-kernel",
        "haystack",
        "langflow",
        "flowise",
        "instructor",
        "dspy",
        "pydantic-ai",
        "litellm",
        "agno",
        "smolagents",
        "phidata",
        "agentops",
    ]
)


GHSA_ECOSYSTEMS = (
    "pip",
    "npm",
    "go",
    "maven",
    "nuget",
    "rubygems",
    "rust",
    "composer",
    "swift",
    "pub",
    "erlang",
    "actions",
)


_GHSA_API_TO_DB_ECOSYSTEM = {
    "actions": "actions",
    "composer": "packagist",
    "erlang": "hex",
    "go": "go",
    "maven": "maven",
    "npm": "npm",
    "nuget": "nuget",
    "pip": "pypi",
    "pub": "pub",
    "rubygems": "rubygems",
    "rust": "crates.io",
    "swift": "swifturl",
}


def _normalize_ghsa_db_ecosystem(ecosystem: str) -> str:
    """Map GitHub advisory ecosystem names to local DB/scanner ecosystem keys."""
    eco = (ecosystem or "").strip().lower()
    return _GHSA_API_TO_DB_ECOSYSTEM.get(eco, eco)


_BATCH_SIZE = 500


_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


_DEBIAN_CVE_ID_RE = re.compile(r"^DEBIAN-(CVE-\d{4}-\d{4,})$", re.IGNORECASE)


def _nvd_cve_candidates(vuln_id: str, raw_aliases: str = "") -> list[str]:
    """Return canonical CVE IDs that NVD can resolve for a local DB row."""

    candidates: list[str] = []

    def add(value: Any) -> None:
        candidate = str(value or "").strip().upper()
        debian_match = _DEBIAN_CVE_ID_RE.match(candidate)
        if debian_match:
            candidate = debian_match.group(1)
        if _CVE_ID_RE.match(candidate) and candidate not in candidates:
            candidates.append(candidate)

    add(vuln_id)
    for alias in (raw_aliases or "").split(","):
        add(alias)
    return candidates


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ingest_osv_file(conn: sqlite3.Connection, content: bytes, filename: str) -> int:
    """Parse a single OSV JSON file (one advisory per file) and upsert into DB."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        _logger.debug("Skipping invalid JSON: %s", filename)
        return 0

    # OSV keeps withdrawn records in its feed so downstream databases can
    # retract advisories they ingested before the withdrawal. Merely skipping
    # the new payload leaves the stale vulnerability and package ranges active
    # forever. Remove the exact advisory ID before returning; affected rows are
    # deleted explicitly as well as by the schema's cascade so this helper stays
    # correct for callers using an externally-created SQLite connection.
    vuln_id = data.get("id", "")
    if vuln_id and data.get("withdrawn"):
        conn.execute("DELETE FROM affected WHERE vuln_id = ?", (vuln_id,))
        conn.execute("DELETE FROM vulns WHERE id = ?", (vuln_id,))
        return 0

    parsed = _parse_osv_entry(data)
    if parsed is None:
        return 0

    vuln_row, affected_rows = parsed

    conn.execute(
        """
        INSERT OR REPLACE INTO vulns
            (id, summary, severity, cvss_score, cvss_vector, fixed_version, cwe_ids, aliases, upstream_ids, published, modified, source)
        VALUES
            (:id, :summary, :severity, :cvss_score, :cvss_vector, :fixed_version, :cwe_ids, :aliases,
             :upstream_ids, :published, :modified, :source)
        """,
        vuln_row,
    )
    for aff in affected_rows:
        conn.execute(
            """
            INSERT OR REPLACE INTO affected
                (vuln_id, ecosystem, package_name, introduced, fixed, last_affected, limit_version)
            VALUES
                (:vuln_id, :ecosystem, :package_name, :introduced, :fixed, :last_affected, :limit_version)
            """,
            aff,
        )
    return 1


def _read_sync_metadata(conn: sqlite3.Connection, source: str) -> dict[str, Any]:
    """Return parsed sync metadata for one source, or an empty dict."""
    if not _sync_meta_has_metadata_column(conn):
        return {}
    row = conn.execute("SELECT metadata_json FROM sync_meta WHERE source = ?", (source,)).fetchone()
    if not row or not row[0]:
        return {}
    try:
        payload = json.loads(row[0])
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _nvd_api_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _upsert_cpe_matches(conn: sqlite3.Connection, cve_id: str, rows: list[dict[str, Any]]) -> int:
    """Replace the stored CPE applicability rows for one CVE."""
    conn.execute("DELETE FROM cpe_matches WHERE cve_id = ?", (cve_id,))
    if not rows:
        return 0
    conn.executemany(
        """
        INSERT OR IGNORE INTO cpe_matches
            (cve_id, criteria, vendor, product, version, version_start, version_start_op, version_end, version_end_op)
        VALUES (:cve_id, :criteria, :vendor, :product, :version, :version_start, :version_start_op, :version_end, :version_end_op)
        """,
        [{"cve_id": cve_id, **r} for r in rows],
    )
    return len(rows)


def _upsert_nvd_enrichment_row(conn: sqlite3.Connection, cve_id: str, fields: dict[str, Any]) -> bool:
    """Insert or update one CVE row from parsed NVD fields.

    Returns ``True`` only when this call adds a *new* CVE row (the INSERT
    actually inserted). Refreshing an already-present row still runs the UPDATE
    but returns ``False`` so callers can count genuinely-new work. The
    incremental sync relies on this to make forward progress across capped
    runs: a re-run pages past the already-synced head (which no longer counts
    toward the cap) and reaches the unsynced tail instead of re-saturating the
    cap on the same head forever.
    """
    if fields.get("cvss_score") is None and not fields.get("cwe_ids"):
        return False

    summary = fields.get("summary") or f"NVD entry for {cve_id}"
    cur = conn.execute(
        """
        INSERT OR IGNORE INTO vulns
            (id, summary, severity, cvss_score, cvss_vector, fixed_version, published, modified, source, cwe_ids, aliases)
        VALUES (?, ?, 'unknown', NULL, NULL, NULL, '', '', 'nvd', '', '')
        """,
        (cve_id, summary),
    )
    inserted = cur.rowcount == 1

    merged_cwes = ",".join(sorted(fields.get("cwe_ids") or [])) or None
    if fields.get("cvss_score") is not None:
        if merged_cwes:
            conn.execute(
                "UPDATE vulns SET cvss_score=?, cvss_vector=?, severity=?, summary=?, cwe_ids=? WHERE id=?",
                (fields["cvss_score"], fields.get("cvss_vector"), fields.get("severity"), summary, merged_cwes, cve_id),
            )
        else:
            conn.execute(
                "UPDATE vulns SET cvss_score=?, cvss_vector=?, severity=?, summary=? WHERE id=?",
                (fields["cvss_score"], fields.get("cvss_vector"), fields.get("severity"), summary, cve_id),
            )
    elif merged_cwes:
        conn.execute("UPDATE vulns SET summary=?, cwe_ids=? WHERE id=?", (summary, merged_cwes, cve_id))
    return inserted


def _sync_meta_has_metadata_column(conn: sqlite3.Connection) -> bool:
    return any(row[1] == "metadata_json" for row in conn.execute("PRAGMA table_info(sync_meta)").fetchall())


def _update_sync_meta(conn: sqlite3.Connection, source: str, count: int, metadata: dict[str, Any] | None = None) -> None:
    metadata_json = json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"))
    if _sync_meta_has_metadata_column(conn):
        conn.execute(
            "INSERT OR REPLACE INTO sync_meta(source, last_synced, record_count, metadata_json) VALUES (?, ?, ?, ?)",
            (source, _now_utc(), count, metadata_json),
        )
    else:
        conn.execute(
            "INSERT OR REPLACE INTO sync_meta(source, last_synced, record_count) VALUES (?, ?, ?)",
            (source, _now_utc(), count),
        )
    conn.commit()
