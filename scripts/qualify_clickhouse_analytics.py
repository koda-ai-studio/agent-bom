#!/usr/bin/env python3
"""Qualify the optional analytics sink against a disposable loopback ClickHouse.

Creates a uniquely named database and retains it for inspection. No operational
state is moved from SQLite/PostgreSQL. This is a bounded local integration run.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from agent_bom.api.clickhouse_store import ClickHouseAnalyticsStore
from scripts.run_graph_mixed_scale_evidence import percentiles


def loopback_url(value: str) -> str:
    parts = urlsplit(value)
    if (
        parts.scheme != "http"
        or parts.hostname not in {"localhost", "127.0.0.1", "::1"}
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or parts.path not in {"", "/"}
    ):
        raise argparse.ArgumentTypeError("A disposable loopback HTTP ClickHouse origin is required")
    return value


def run(url: str, output: Path) -> dict:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as stream:
        database = "qualification_" + uuid4().hex
        receipt = {
            "schema_version": "clickhouse.qualification.v1",
            "database": database,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "passed": False,
            "evidence": "synthetic-rows/loopback-HTTP/real-ClickHouse",
            "production_capacity": False,
        }
        try:
            store = ClickHouseAnalyticsStore(url=url, database=database, user="default", timeout=10)

            def write(index):
                started = time.perf_counter()
                tenant = f"tenant-{index % 2}"
                store.record_event({"event_id": f"shared-{index // 2}", "event_type": tenant, "severity": "low"}, tenant_id=tenant)
                return (time.perf_counter() - started) * 1000

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                timings = list(pool.map(write, list(range(40)) * 2))
            # Reopen the client/schema; replay must still collapse in public reads.
            reopened = ClickHouseAnalyticsStore(url=url, database=database, user="default", timeout=10)
            checks = {}
            for tenant in ("tenant-0", "tenant-1"):
                rows = reopened.query_event_summary(tenant_id=tenant)
                checks[tenant] = len(rows) == 1 and rows[0]["event_type"] == tenant and int(rows[0]["cnt"]) == 20
            checks["unseen_tenant_empty"] = reopened.query_event_summary(tenant_id="unseen") == []
            finding = {"cve_id": "CVE-2099-9999", "package_name": "synthetic-fixture", "package_version": "1", "severity": "high"}
            for _ in range(2):
                reopened.record_scan("scan", "fixture", [finding], tenant_id="tenant-0")
            cves = reopened.query_top_cves(tenant_id="tenant-0")
            checks["scan_replay"] = len(cves) == 1 and int(cves[0]["cnt"]) == 1
            checks["scan_tenant_isolation"] = reopened.query_top_cves(tenant_id="tenant-1") == []
            receipt.update(
                {
                    "checks": checks,
                    "passed": all(checks.values()),
                    "write_requests": len(timings),
                    "concurrent_workers": 4,
                    "write_latency_ms": percentiles(timings),
                }
            )
        except Exception as exc:
            receipt["error_type"] = type(exc).__name__
        stream.write(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", type=loopback_url, required=True)
    parser.add_argument("--output", type=Path, required=True)
    result = run(**vars(parser.parse_args()))
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
