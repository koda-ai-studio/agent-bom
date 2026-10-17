#!/usr/bin/env python3
"""Bounded in-process API qualification with synthetic provider pages and real SQL.

Run in a separate process against a disposable migrated database. This exercises
HTTP contracts through ASGI, not network/server capacity or a live provider.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import platform
import resource
import subprocess
import threading
import time
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import httpx
from fastapi.testclient import TestClient

from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
from agent_bom.api.runtime_event_store import SQLiteRuntimeEventStore, set_runtime_event_store
from agent_bom.api.server import app, configure_api
from agent_bom.api.storage.sql import PostgresBackend, SQLiteBackend
from agent_bom.api.trace_collection.langfuse import fetch_page
from agent_bom.api.trace_collection.store import TraceCollectionStore
from scripts.run_graph_mixed_scale_evidence import percentiles

ROOT = Path(__file__).resolve().parents[1]


@asynccontextmanager
async def _qualification_lifespan(_app):
    from agent_bom.api.server import _apply_worker_thread_limit

    # Fixture stores are already provisioned. Apply the production worker
    # budget on the single serving loop without provisioning external stores.
    _apply_worker_thread_limit()
    yield


def assess(attempts: list[dict], reconciled: bool, *, p95_limit_ms: float, slowdown_limit: float) -> dict:
    baseline = percentiles([a["ms"] for a in attempts if a["phase"] == "baseline"])
    mixed = percentiles([a["ms"] for a in attempts if a["operation"] == "status" and a["phase"] == "mixed"])
    ratio = mixed["p95"] / max(1, baseline["p95"]) if mixed["p95"] is not None and baseline["p95"] is not None else None
    return {
        "passed": bool(attempts)
        and reconciled
        and all(a["ok"] for a in attempts)
        and ratio is not None
        and mixed["p95"] <= p95_limit_ms
        and ratio <= slowdown_limit,
        "reconciled": reconciled,
        "baseline_light_ms": baseline,
        "mixed_light_ms": mixed,
        "light_p95_slowdown": ratio,
        "p95_limit_ms": p95_limit_ms,
        "slowdown_limit": slowdown_limit,
        "all_attempts_ms": percentiles([a["ms"] for a in attempts]),
    }


def run(output: Path, *, backend: str, workers: int, pages: int, rows: int, p95_limit_ms: float, slowdown_limit: float) -> dict:
    output.mkdir(parents=True, exist_ok=False)  # Preserve earlier failed receipts.
    prefix = "qual-" + uuid4().hex[:12]
    noisy, light = prefix + "-noisy", prefix + "-light"
    bindings = {f"noisy-{i}": noisy for i in range(workers)} | {"light": light}
    secret = uuid4().hex + uuid4().hex
    os.environ.update(
        {
            "AGENT_BOM_TRUST_PROXY_AUTH": "1",
            "AGENT_BOM_TRUST_PROXY_AUTH_SECRET": secret,
            "TRACE_QUAL_CREDENTIALS": json.dumps({"public_key": "fixture-project", "secret_key": "fixture-secret"}),
            "AGENT_BOM_TRACE_CONNECTIONS": json.dumps(
                {
                    key: {
                        "tenant_id": tenant,
                        "provider": "langfuse",
                        "display_name": key,
                        "endpoint": "https://cloud.langfuse.com",
                        "credentials_env": "TRACE_QUAL_CREDENTIALS",
                        "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                    }
                    for key, tenant in bindings.items()
                }
            ),
        }
    )
    pool = None
    if backend == "postgres":
        from agent_bom.api.postgres_common import _new_application_pool
        from agent_bom.api.postgres_runtime_event import PostgresRuntimeEventStore

        pool = _new_application_pool(min_size=1, max_size=workers + 3)
        runtime = PostgresRuntimeEventStore(pool)
        store = TraceCollectionStore(PostgresBackend(pool))
    else:
        from agent_bom.api.audit_log import SQLiteAuditLog, set_audit_log

        set_audit_log(SQLiteAuditLog(str(output / "audit.db")))
        runtime = SQLiteRuntimeEventStore(str(output / "runtime.db"))
        store = TraceCollectionStore(SQLiteBackend(str(output / "runtime.db")))
    # Provision fixture tables before requests: rejected/disabled routes must
    # reconcile as missing work and retain a failed receipt, not raise because
    # the service's lazy initialization was never reached.
    store.init_schema()
    set_runtime_event_store(runtime)
    configure_api(api_key=secret)
    attempts: list[dict] = []
    guard = threading.Lock()
    calls = 0

    def provider(request):
        nonlocal calls
        if request.url.path == "/api/public/projects":
            return httpx.Response(200, json={"data": [{"id": "fixture-project", "name": "Qualification"}]})
        with guard:
            calls += 1
        index = int(request.url.params.get("cursor", "0"))
        observed = datetime.fromisoformat(request.url.params["fromStartTime"]) + timedelta(hours=1)
        return httpx.Response(
            200,
            json={
                "data": [
                    {"id": f"{index}-{i}", "traceId": "shared-trace-id", "name": "read", "type": "TOOL", "startTime": observed.isoformat()}
                    for i in range(rows)
                ],
                "meta": {"cursor": str(index + 1) if index + 1 < pages else None},
            },
        )

    def request(connection, operation, phase):
        started = time.perf_counter()
        row = {"connection": connection, "operation": operation, "phase": phase, "ok": False, "status": None}
        try:
            headers = {"X-Agent-Bom-Role": "admin", "X-Agent-Bom-Tenant-ID": bindings[connection], "X-Agent-Bom-Proxy-Secret": secret}
            response = (
                client.post("/v1/traces/connectors/langfuse/collect", headers=headers, json={"connection_id": connection})
                if operation == "collect"
                else client.get("/v1/traces/connectors/langfuse/collection", headers=headers, params={"connection_id": connection})
            )
            row["status"] = response.status_code
            body = response.json()
            row["ok"] = (
                response.status_code == 200
                and body.get("connection_id") == connection
                and body.get("schema_version") == "trace.collection.v1"
                and body.get("status") in {"not_started", "collecting", "partial", "caught_up"}
            )
            row["persisted"] = body.get("persisted")
        except Exception as exc:
            row["error_type"] = type(exc).__name__  # No raw exception/provider/credential material.
        row["ms"] = (time.perf_counter() - started) * 1000
        with guard:
            attempts.append(row)
            with (output / "attempts.jsonl").open("a") as stream:
                stream.write(json.dumps(row) + "\n")
        return row["ok"]

    start = time.perf_counter()
    try:
        with (
            patch.object(app.router, "lifespan_context", _qualification_lifespan),
            TestClient(app) as client,
            httpx.Client(transport=httpx.MockTransport(provider)) as provider_client,
            patch(
                "agent_bom.api.trace_collection.service.fetch_page",
                side_effect=lambda *args: fetch_page(*args, client=provider_client),
            ),
        ):
            for _ in range(3):
                request("light", "status", "warmup")
            for _ in range(30):
                request("light", "status", "baseline")
            barrier = threading.Barrier(workers + 2)
            finished = threading.Event()

            def collect(connection):
                barrier.wait(timeout=30)
                for _ in range(pages):
                    if not request(connection, "collect", "mixed"):
                        break

            def read():
                barrier.wait(timeout=30)
                for _ in range(1000):
                    request("light", "status", "mixed")
                    if finished.is_set():
                        break
                    time.sleep(0.01)

            with concurrent.futures.ThreadPoolExecutor(max_workers=workers + 2) as executor:
                jobs = [executor.submit(collect, connection) for connection in bindings]
                reads = executor.submit(read)
                try:
                    for job in jobs:
                        job.result(timeout=300)
                finally:
                    finished.set()
                reads.result(timeout=30)
        checks = []
        for tenant in (noisy, light):
            token = set_current_tenant(tenant)
            try:
                expected = {
                    (connection, "fixture-project", "shared-trace-id", f"{p}-{r}")
                    for connection, owner in bindings.items()
                    if owner == tenant
                    for p in range(pages)
                    for r in range(rows)
                }
                with store.backend.transaction(read_only=True) as tx:
                    records = [
                        json.loads(row[0])
                        for row in tx.execute("SELECT data FROM runtime_observations WHERE tenant_id=?", (tenant,)).fetchall()
                    ]
                actual = {
                    tuple(row["metadata"].get(key) for key in ("connection_id", "project_id", "native_trace_id", "native_span_id"))
                    for row in records
                }
                checks.append(actual == expected and len(records) == len(expected))
                checks.append(all(row["tenant_id"] == tenant and row["surface"] == "imported_trace" for row in records))
                checks.append(len({row["observation_id"] for row in records}) == len(expected))
                for connection, owner in bindings.items():
                    if owner == tenant:
                        state = store.get(tenant, connection)
                        checks.append(
                            state is not None and state.persisted == pages * rows and state.pages == pages and state.cursor is None
                        )
            finally:
                reset_current_tenant(token)
        elapsed = time.perf_counter() - start
        from agent_bom import config

        receipt = {
            "schema": "trace.qualification.v1",
            "evidence": "synthetic-provider/in-process-ASGI/real-SQL",
            "source_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "backend": backend,
            "workers": workers,
            "worker_thread_limit": config.WORKER_THREAD_LIMIT,
            "serving_event_loops": 1,
            "pages_per_connection": pages,
            "rows_per_page": rows,
            "elapsed_seconds": elapsed,
            "expected_observations": (workers + 1) * pages * rows,
            "provider_attempts": calls,
            "requests": len(attempts),
            "failed_requests": sum(not a["ok"] for a in attempts),
            "process_peak_rss_bytes": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if platform.system() == "Darwin" else 1024),
            **assess(attempts, all(checks) and calls == (workers + 1) * pages, p95_limit_ms=p95_limit_ms, slowdown_limit=slowdown_limit),
        }
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        return receipt
    finally:
        set_runtime_event_store(None)
        if pool:
            pool.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--backend", choices=["sqlite", "postgres"], default="sqlite")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--pages", type=int, default=10)
    parser.add_argument("--rows", type=int, default=100)
    parser.add_argument("--p95-limit-ms", type=float, default=5000)
    parser.add_argument("--slowdown-limit", type=float, default=4)
    args = parser.parse_args()
    if not 1 <= args.workers <= 8 or not 2 <= args.pages <= 20 or not 1 <= args.rows <= 100:
        parser.error("workers 1..8, pages 2..20, rows 1..100 are required")
    if args.p95_limit_ms <= 0 or args.slowdown_limit <= 0:
        parser.error("thresholds must be positive")
    if args.backend == "postgres" and not all(
        os.environ.get(key) for key in ("AGENT_BOM_POSTGRES_URL", "AGENT_BOM_POSTGRES_MAINTENANCE_URL", "AGENT_BOM_AUDIT_HMAC_KEY")
    ):
        parser.error("PostgreSQL requires application and maintenance URLs plus an audit HMAC key for a disposable database")
    result = run(**vars(args))
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
