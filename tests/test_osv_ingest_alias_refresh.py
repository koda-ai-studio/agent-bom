"""OSV ingestion stores each record's own aliases and a re-sync replaces stale ones.

A stale fused alias group (upstream briefly linked two advisories) must
disappear from the local DB once ``agent-bom db update`` ingests the
corrected records; ingestion must never union aliases across records.
"""

from __future__ import annotations

import json

from agent_bom.db.schema import init_db
from agent_bom.db.sync import _ingest_osv_file


def _record(vuln_id: str, aliases: list[str], introduced: str, fixed: str) -> bytes:
    return json.dumps(
        {
            "id": vuln_id,
            "aliases": aliases,
            "summary": f"lodash advisory {vuln_id}",
            "modified": "2026-10-17T02:56:15Z",
            "affected": [
                {
                    "package": {"ecosystem": "npm", "name": "lodash"},
                    "ranges": [{"type": "SEMVER", "events": [{"introduced": introduced}, {"fixed": fixed}]}],
                }
            ],
        }
    ).encode()


def _aliases(conn, vuln_id: str) -> str:
    return conn.execute("SELECT aliases FROM vulns WHERE id = ?", (vuln_id,)).fetchone()[0]


def _ranges(conn, vuln_id: str) -> set[tuple[str, str]]:
    return {(row[0], row[1]) for row in conn.execute("SELECT introduced, fixed FROM affected WHERE vuln_id = ?", (vuln_id,))}


def test_ingestion_stores_only_each_records_own_aliases(tmp_path):
    conn = init_db(tmp_path / "vulns.db")
    _ingest_osv_file(conn, _record("GHSA-35jh-r3h4-6jhm", ["CVE-2021-23337"], "0", "4.17.21"), "a.json")
    _ingest_osv_file(conn, _record("GHSA-r5fr-rjxr-66jc", ["CVE-2026-4800"], "4.0.0", "4.18.0"), "b.json")

    assert _aliases(conn, "GHSA-35jh-r3h4-6jhm") == "CVE-2021-23337"
    assert _aliases(conn, "GHSA-r5fr-rjxr-66jc") == "CVE-2026-4800"


def test_resync_replaces_a_stale_fused_alias_group(tmp_path):
    conn = init_db(tmp_path / "vulns.db")
    fused = ["CVE-2021-23337", "CVE-2026-4800", "GHSA-35jh-r3h4-6jhm"]
    _ingest_osv_file(conn, _record("GHSA-r5fr-rjxr-66jc", fused, "0", "4.17.21"), "old.json")
    fused_peer = ["CVE-2021-23337", "CVE-2026-4800", "GHSA-r5fr-rjxr-66jc"]
    _ingest_osv_file(conn, _record("GHSA-35jh-r3h4-6jhm", fused_peer, "0", "4.17.21"), "old2.json")
    conn.commit()

    _ingest_osv_file(conn, _record("GHSA-r5fr-rjxr-66jc", ["CVE-2026-4800"], "4.0.0", "4.18.0"), "new.json")
    _ingest_osv_file(conn, _record("GHSA-35jh-r3h4-6jhm", ["CVE-2021-23337"], "0", "4.17.21"), "new2.json")
    conn.commit()

    assert _aliases(conn, "GHSA-r5fr-rjxr-66jc") == "CVE-2026-4800"
    assert _aliases(conn, "GHSA-35jh-r3h4-6jhm") == "CVE-2021-23337"
    # The superseded window must not linger next to the corrected one.
    assert _ranges(conn, "GHSA-r5fr-rjxr-66jc") == {("4.0.0", "4.18.0")}
