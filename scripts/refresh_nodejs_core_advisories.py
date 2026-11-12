#!/usr/bin/env python3
"""Regenerate the bundled Node.js core advisory snapshot.

A thin maintainer entrypoint over ``agent_bom.scanners.nodejs_advisory_data``:
it fetches ``vuln/core/index.json`` from the Node.js security working group
repository (github.com/nodejs/security-wg, MIT licensed), validates every entry
(CVE ids, npm ranges, severity, platforms) and writes
``src/agent_bom/data/nodejs_core_vulns.json`` with the fetch time and the
sha256 of the upstream bytes. A failed or malformed fetch writes nothing.

Scans ignore a snapshot older than ``AGENT_BOM_DB_STALE_DAYS`` (14 days by
default), so the bundled copy only helps offline scans of a recent release;
``agent-bom db update`` keeps a fresher copy next to the local DB.

Usage:
    python scripts/refresh_nodejs_core_advisories.py           # fetch and rewrite
    python scripts/refresh_nodejs_core_advisories.py --check   # validate the bundled copy (no network)
"""

from __future__ import annotations

import argparse
import sys

from agent_bom.scanners.nodejs_advisory_data import bundled_snapshot_path, load_snapshot, sync_snapshot


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="validate the bundled snapshot without network access")
    args = parser.parse_args(argv)
    path = bundled_snapshot_path()
    if not args.check:
        sync_snapshot(path)
    try:
        snapshot = load_snapshot(path, origin="bundled_snapshot")
    except ValueError as exc:
        print(f"invalid bundled Node.js core advisory snapshot: {exc}", file=sys.stderr)
        return 1
    print(f"{path.name}: {len(snapshot.entries)} entries, fetched {snapshot.fetched_at.isoformat()}, sha256 {snapshot.sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
