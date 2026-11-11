"""Child-process phases for ``scripts/run_workflow_resource_benchmark.py``.

Every phase writes ``<workdir>/<phase>.json``. Stores come from the environment
the parent sets (``AGENT_BOM_DB`` or ``AGENT_BOM_POSTGRES_URL``), as a deployed
API process would configure them.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

import httpx

from scripts.generate_graph_benchmark_estate import generate_estate
from scripts.perf.workflow_budget import (
    GRAPH_READS,
    _graph_reads,
    _Http,
    _push,
    _run_cli_scan,
    findings_digest,
    mocked_upstream,
    network_guard,
    postgres_footprint,
    run_workflow,
    sqlite_footprint,
    stored_findings,
)
from scripts.perf.workflow_profiles import (
    PROFILES,
    MockUpstream,
    WorkflowProfile,
    expected_findings,
    inventory_from_estate,
    vulnerable_versions,
)


def _footprint(workdir: Path) -> Any:
    dsn = os.environ.get("AGENT_BOM_POSTGRES_URL")
    return postgres_footprint(dsn) if dsn else sqlite_footprint(workdir / "db", workdir / "state")


def _client() -> httpx.AsyncClient:
    from agent_bom.api.server import app

    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://workflow", timeout=1800)


def _sqlite_integrity(workdir: Path) -> dict[str, str]:
    results = {}
    for path in sorted((workdir / "db").glob("*.db")) + sorted((workdir / "state").glob("*.db")):
        if path.name.startswith("scan-cache"):
            continue
        with sqlite3.connect(path) as connection:
            results[path.name] = str(connection.execute("PRAGMA integrity_check").fetchone()[0])
    return results


async def _latest_findings(http: _Http) -> dict[str, Any]:
    jobs = (await http.call("GET", "/v1/jobs?limit=50"))[0].json()
    rows = jobs.get("jobs", jobs) if isinstance(jobs, dict) else jobs
    statuses = [row.get("status") for row in rows]
    done = [row for row in rows if row.get("status") == "done"]
    if not done:
        return {"jobs": len(rows), "statuses": statuses, "stored_findings": 0, "stored_digest": None}
    newest = max(done, key=lambda row: str(row.get("completed_at") or row.get("created_at") or ""))
    keys = await stored_findings(http, newest["job_id"])
    return {"jobs": len(rows), "statuses": statuses, "stored_findings": len(keys), "stored_digest": findings_digest(keys)}


async def _restart(profile: WorkflowProfile, workdir: Path) -> dict[str, Any]:
    began = time.perf_counter()
    async with _client() as client:
        http = _Http(client)
        first, first_s = await http.call("GET", GRAPH_READS["graph_page"])
        state = await _latest_findings(http)
        reads = await _graph_reads(http, profile.query_repeats)
    warm = json.loads((workdir / "warm.json").read_text(encoding="utf-8"))
    return {
        "first_graph_read_ms": round(first_s * 1000, 1),
        "first_graph_read_status": first.status_code,
        "reads": reads,
        **state,
        "findings_match_before_restart": state["stored_digest"] == warm["accuracy"]["stored_digest"],
        "wall_seconds": round(time.perf_counter() - began, 3),
    }


def _scan_estate(profile: WorkflowProfile, workdir: Path) -> tuple[bytes, set[tuple[str, str, str]], dict[str, Any]]:
    report, _summary = generate_estate(agents=profile.agents, seed=profile.seed, vulnerable_package_rate=profile.vulnerable_package_rate)
    inventory = inventory_from_estate(report)
    inventory_path = workdir / "cancel-inventory.json"
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    report_path = workdir / "cancel-report.json"
    upstream = MockUpstream(vulnerable=vulnerable_versions(report))
    with network_guard() as guard, mocked_upstream(upstream):
        _run_cli_scan(inventory_path, report_path)
    if guard.blocked:
        raise RuntimeError(f"scan attempted live network: {guard.blocked}")
    return report_path.read_bytes(), expected_findings(report, inventory), upstream.snapshot()


async def _cancel_victim(profile: WorkflowProfile, workdir: Path) -> dict[str, Any]:
    body, expected, _upstream = await asyncio.to_thread(_scan_estate, profile, workdir)
    (workdir / "cancel-expected.json").write_text(
        json.dumps({"digest": findings_digest(expected), "count": len(expected)}), encoding="utf-8"
    )
    async with _client() as client:
        response = await client.post(
            "/v1/results/push", content=body, headers={"Content-Type": "application/json", "Prefer": "respond-async"}
        )
        (workdir / "cancel-admitted").write_text(str(response.status_code), encoding="utf-8")
        await asyncio.sleep(3600)  # the parent kills this process here, mid-ingest
    return {}


async def _recover(workdir: Path) -> dict[str, Any]:
    integrity = None if os.environ.get("AGENT_BOM_POSTGRES_URL") else _sqlite_integrity(workdir)
    body = (workdir / "cancel-report.json").read_bytes()
    expected = json.loads((workdir / "cancel-expected.json").read_text(encoding="utf-8"))
    async with _client() as client:
        http = _Http(client)
        before = await _latest_findings(http)
        began = time.perf_counter()
        retried = await _push(http, body, 1800)
        retry_seconds = time.perf_counter() - began
        after = await _latest_findings(http)
    return {
        "integrity_check": integrity,
        "jobs_after_kill": before["jobs"],
        "statuses_after_kill": before["statuses"],
        "retry": retried,
        "retry_to_stored_seconds": round(retry_seconds, 3),
        "jobs_after_retry": after["jobs"],
        "findings_match_expected": after["stored_digest"] == expected["digest"],
        "expected_findings": expected["count"],
    }


def run_child(phase: str, profile_name: str, workdir: Path, *, replica_index: int = 0) -> int:
    profile = PROFILES[profile_name]
    if phase in {"cold", "warm"}:
        result = asyncio.run(run_workflow(profile, workdir / phase, footprint=_footprint(workdir)))
    elif phase == "replica":
        replica = dataclasses.replace(profile, seed=profile.seed + replica_index)
        # Tenant deletion would erase the other replicas' data; retention runs in the single-replica profiles.
        result = asyncio.run(run_workflow(replica, workdir / phase, footprint=_footprint(workdir), retention=False))
    elif phase == "restart":
        result = asyncio.run(_restart(profile, workdir))
    elif phase == "cancel":
        result = asyncio.run(_cancel_victim(profile, workdir))
    elif phase == "recover":
        result = asyncio.run(_recover(workdir))
    else:
        raise SystemExit(f"unknown phase {phase}")
    (workdir / f"{phase}.json").write_text(json.dumps(result, indent=2, sort_keys=True, default=str), encoding="utf-8")
    return 0
