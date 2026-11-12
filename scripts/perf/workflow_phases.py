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
    _finding_keys,
    _graph_reads,
    _Http,
    _push,
    findings_digest,
    postgres_footprint,
    run_workflow,
    scan_in_child,
    sqlite_footprint,
    stored_rows,
)
from scripts.perf.workflow_equivalence import projection_digest
from scripts.perf.workflow_profiles import (
    PROFILES,
    WORKFLOW_PUSH_SOURCE_ID,
    WorkflowProfile,
    cli_push_body,
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
        return {"jobs": len(rows), "statuses": statuses, "stored_findings": 0, "stored_digest": None, "stored_projection_digest": None}
    newest = max(done, key=lambda row: str(row.get("completed_at") or row.get("created_at") or ""))
    stored = await stored_rows(http, newest["job_id"])
    keys = _finding_keys(stored)
    return {
        "jobs": len(rows),
        "statuses": statuses,
        "stored_findings": len(keys),
        "stored_digest": findings_digest(keys),
        "stored_projection_digest": projection_digest(stored),
    }


def _final_digests(warm: dict[str, Any]) -> tuple[str | None, str | None]:
    """Digests of the last job the warm run stored: the update/delete push when it ran, else the ingest."""
    final = (warm.get("equivalence") or {}).get("update_delete") or warm["accuracy"]
    return final.get("stored_digest"), final.get("stored_projection_digest")


def _error_code(response: httpx.Response) -> str | None:
    try:
        error = response.json().get("error") or {}
    except ValueError:
        return None
    details = error.get("details")
    return str((details.get("code") if isinstance(details, dict) else None) or error.get("code") or "") or None


async def _first_graph_read(http: _Http, deadline_seconds: float = 300.0) -> dict[str, Any]:
    """The first graph read in a new process, then retries at ``Retry-After`` until one returns 200."""
    began = time.perf_counter()
    first, first_s = await http.call("GET", GRAPH_READS["graph_page"])
    response, retries = first, 0
    while response.status_code == 503 and time.perf_counter() - began < deadline_seconds:
        await asyncio.sleep(min(float(response.headers.get("Retry-After") or 1), 5.0))
        response, _ = await http.call("GET", GRAPH_READS["graph_page"])
        retries += 1
    return {
        "first_graph_read_ms": round(first_s * 1000, 1),
        "first_graph_read_status": first.status_code,
        "first_graph_read_code": _error_code(first) if first.status_code != 200 else None,
        "first_graph_read_retry_after": first.headers.get("Retry-After"),
        "graph_ready_status": response.status_code,
        "graph_ready_seconds": round(time.perf_counter() - began, 2),
        "graph_ready_retries": retries,
    }


async def _await_ready(http: _Http, deadline_seconds: float = 300.0, period_seconds: float = 0.5) -> dict[str, Any]:
    """Poll ``/readyz`` as the chart's readiness probe does; a Service routes no read before it answers 200."""
    began = time.perf_counter()
    reasons: list[str] = []
    while True:
        response, _ = await http.call("GET", "/readyz")
        if response.status_code == 200 or time.perf_counter() - began > deadline_seconds:
            break
        reason = str(response.json().get("reason") or response.json().get("status") or "")
        if reason and reason not in reasons:
            reasons.append(reason)
        await asyncio.sleep(period_seconds)
    return {"ready_status": response.status_code, "ready_seconds": round(time.perf_counter() - began, 2), "not_ready_reasons": reasons}


async def _restart(profile: WorkflowProfile, workdir: Path) -> dict[str, Any]:
    from agent_bom.api.server import app

    began = time.perf_counter()
    # A restarted deployment runs the lifespan (and its start-up graph prewarm);
    # the first read is routed once readiness answers 200.
    async with app.router.lifespan_context(app), _client() as client:
        http = _Http(client)
        ready = await _await_ready(http)
        first = {**ready, **await _first_graph_read(http)}
        state = await _latest_findings(http)
        reads = await _graph_reads(http, profile.query_repeats)
    warm = json.loads((workdir / "warm.json").read_text(encoding="utf-8"))
    return {
        **first,
        "reads": reads,
        **state,
        "findings_match_before_restart": (state["stored_digest"], state["stored_projection_digest"]) == _final_digests(warm),
        "wall_seconds": round(time.perf_counter() - began, 3),
    }


def _scan_estate(profile: WorkflowProfile, workdir: Path) -> tuple[bytes, set[tuple[str, str, str]], dict[str, Any]]:
    report, _summary = generate_estate(agents=profile.agents, seed=profile.seed, vulnerable_package_rate=profile.vulnerable_package_rate)
    inventory = inventory_from_estate(report)
    inventory_path = workdir / "cancel-inventory.json"
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    report_path = workdir / "cancel-report.json"
    receipt = scan_in_child(inventory_path, report_path, vulnerable_versions(report))
    if receipt["blocked_connections"]:
        raise RuntimeError(f"scan attempted live network: {receipt['blocked_connections']}")
    return cli_push_body(report_path.read_bytes()), expected_findings(report, inventory), receipt["upstream"]


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
    body = cli_push_body((workdir / "cancel-report.json").read_bytes())
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
        # Each replica is its own host. The shared tenant serves both estates, so the
        # single-estate equivalence checks run in the single-replica profiles.
        result = asyncio.run(
            run_workflow(
                replica,
                workdir / phase,
                footprint=_footprint(workdir),
                retention=False,
                check_equivalence=False,
                source_id=f"{WORKFLOW_PUSH_SOURCE_ID}-{replica_index}",
            )
        )
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
