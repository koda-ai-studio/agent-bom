"""Explicitly synthetic feed receipts in the isolated demo database only."""

from __future__ import annotations

import json

from agent_bom.storage.state_home import demo_estate_requested, demo_state_isolated, state_dir


def seed_demo_feed_receipts() -> int:
    from agent_bom.db.schema import init_db
    from agent_bom.demo_advisories import DEMO_ADVISORIES, DEMO_EPSS_AS_OF, demo_epss, seed_demo_advisories
    from agent_bom.intel_lookup import resolve_intel_db_path

    if not demo_estate_requested() or not demo_state_isolated():
        return 0
    path = resolve_intel_db_path()
    if not path.resolve().is_relative_to(state_dir().resolve()):
        return 0  # An explicit operator DB override is never seeded.
    conn = init_db(path)
    try:
        # Refuse any real evidence, including a partially synchronized DB.
        if conn.execute("SELECT 1 FROM vulns WHERE source != 'demo-advisory' LIMIT 1").fetchone():
            return 0
        rows = conn.execute("SELECT metadata_json FROM sync_meta").fetchall()
        if any(not json.loads(row[0] or "{}").get("synthetic") for row in rows):
            return 0
        if rows:
            return 0
        seed_demo_advisories(conn)
        counts = {
            "osv": len({a.vuln_id for a in DEMO_ADVISORIES}),
            "epss": len({a.vuln_id for a in DEMO_ADVISORIES if demo_epss(a) is not None}),
            "kev": len({a.vuln_id for a in DEMO_ADVISORIES if a.is_kev}),
        }
        metadata = json.dumps(
            {
                "synthetic": True,
                "status": "partial",
                "partial_reason": "synthetic_demo_fixture_not_live_sync",
                "validation_status": "synthetic_demo_fixture",
            }
        )
        for source, count in counts.items():
            conn.execute(
                "INSERT INTO sync_meta(source,last_synced,record_count,metadata_json) VALUES (?,?,?,?)",
                (source, DEMO_EPSS_AS_OF, count, metadata),
            )
        conn.commit()
        return len(counts)
    finally:
        conn.close()
