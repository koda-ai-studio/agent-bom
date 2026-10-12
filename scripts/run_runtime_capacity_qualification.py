#!/usr/bin/env python3
"""Qualify mixed runtime writes and status reads over disposable loopback HTTP.

Uses synthetic connection credentials and runtime events, real middleware and
SQL. This is a single-process local measurement, not EKS or provider parity.
PostgreSQL requires an already migrated disposable database and application role.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import platform
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import httpx
import uvicorn

from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant
from agent_bom.api.runtime_event_store import SQLiteRuntimeEventStore, set_runtime_event_store
from agent_bom.api.server import app, configure_api
from scripts.run_trace_collection_qualification import assess

ROOT = Path(__file__).resolve().parents[1]


def run(output: Path, *, backend: str) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    prefix = "capacity-" + uuid4().hex[:12]
    reader = prefix + "-reader"
    secret = uuid4().hex + uuid4().hex
    os.environ.update(
        AGENT_BOM_TRUST_PROXY_AUTH="1",
        AGENT_BOM_TRUST_PROXY_AUTH_SECRET=secret,
        AGENT_BOM_TRUST_PROXY_AUTH_ISSUER="local-qualification",
        RUNTIME_QUAL_CREDENTIALS=json.dumps({"public_key": "fixture", "secret_key": "fixture"}),
        AGENT_BOM_TRACE_CONNECTIONS=json.dumps(
            {
                "fixture": {
                    "tenant_id": reader,
                    "provider": "langfuse",
                    "display_name": "Synthetic connection; no provider access",
                    "endpoint": "https://cloud.langfuse.com",
                    "credentials_env": "RUNTIME_QUAL_CREDENTIALS",
                    "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
                }
            }
        ),
    )
    pool = None
    if backend == "postgres":
        from agent_bom.api.postgres_common import _new_application_pool
        from agent_bom.api.postgres_runtime_event import PostgresRuntimeEventStore

        pool = _new_application_pool(min_size=1, max_size=2)
        runtime = PostgresRuntimeEventStore(pool)
    else:
        from agent_bom.api.audit_log import SQLiteAuditLog, set_audit_log

        set_audit_log(SQLiteAuditLog(str(output / "audit.db")))
        runtime = SQLiteRuntimeEventStore(str(output / "runtime.db"))
    set_runtime_event_store(runtime)
    configure_api(api_key=secret)
    attempts = []
    guard = threading.Lock()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{listener.getsockname()[1]}"

    def request(tenant, phase, body=None):
        start = time.perf_counter()
        row = {"phase": phase, "operation": "status" if body is None else "write", "ok": False}
        try:
            # Match the deployment probe's fresh HTTP client per request.
            with httpx.Client(base_url=base, trust_env=False, timeout=30) as client:
                headers = {
                    "X-Agent-Bom-Role": "admin",
                    "X-Agent-Bom-Tenant-ID": tenant,
                    "X-Agent-Bom-Proxy-Secret": secret,
                    "X-Agent-Bom-Auth-Issuer": "local-qualification",
                }
                response = (
                    client.get("/v1/traces/connectors/langfuse/collection?connection_id=fixture", headers=headers)
                    if body is None
                    else client.post("/v1/runtime/events", headers=headers, json=body)
                )
            data = response.json()
            row["status"] = response.status_code
            row["ok"] = (
                response.status_code == 200 and data.get("connection_id") == "fixture"
                if body is None
                else response.status_code == 202 and data.get("persisted") == 50 and data.get("tenant_id") == tenant
            )
        except Exception as exc:
            row["error_type"] = type(exc).__name__
        row["ms"] = (time.perf_counter() - start) * 1000
        with guard:
            attempts.append(row)
            with (output / "attempts.jsonl").open("a") as stream:
                stream.write(json.dumps(row) + "\n")

    try:
        deadline = time.monotonic() + 15
        while not server.started:
            if not thread.is_alive() or time.monotonic() > deadline:
                raise RuntimeError("Qualification HTTP server did not start")
            time.sleep(0.01)
        for _ in range(3):
            request(reader, "warmup")
        for _ in range(30):
            request(reader, "baseline")

        def write(worker):
            for batch in range(10):
                request(
                    f"{prefix}-writer-{worker}",
                    "mixed",
                    [
                        {
                            "event_id": f"event-{worker}-{batch}-{index}",
                            "session_id": f"session-{worker}",
                            "trace_id": f"trace-{worker}-{batch}",
                            "tool_name": "qualification.noop",
                            "agent_name": "qualification",
                            "event_timestamp": "2026-10-12T06:00:00Z",
                            "message": "synthetic metadata",
                        }
                        for index in range(50)
                    ],
                )

        def read():
            for _ in range(80):
                request(reader, "mixed")

        started = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            jobs = [executor.submit(write, i) for i in range(4)] + [executor.submit(read) for _ in range(6)]
            for job in jobs:
                job.result(timeout=300)
        elapsed = time.perf_counter() - started
        counts = []
        for tenant in [reader, *(f"{prefix}-writer-{i}" for i in range(4))]:
            token = set_current_tenant(tenant)
            try:
                rows = runtime.list_observations(tenant, limit=1000)
                sessions = runtime.list_sessions(tenant)
                counts.append(len(rows) == (0 if tenant == reader else 500))
                counts.append(sum(s.observation_count for s in sessions) == len(rows))
                counts.append(all(row.tenant_id == tenant for row in rows))
            finally:
                reset_current_tenant(token)
        receipt = {
            "schema": "runtime.capacity.v1",
            "evidence": "synthetic-events/loopback-HTTP/real-SQL",
            "source_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "source_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True)),
            "backend": backend,
            "python": platform.python_version(),
            "platform": platform.platform(),
            "replicas": 1,
            "concurrency": 10,
            "write_requests": 40,
            "read_requests": 480,
            "write_batch": 50,
            "elapsed_seconds": elapsed,
            "requests_per_second": 520 / elapsed,
            **assess(attempts, all(counts), p95_limit_ms=5000, slowdown_limit=4),
        }
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        return receipt
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        listener.close()
        set_runtime_event_store(None)
        if pool is not None:
            pool.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--backend", choices=["sqlite", "postgres"], default="sqlite")
    args = parser.parse_args()
    if args.backend == "postgres" and not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        parser.error("PostgreSQL requires a migrated disposable application-role database")
    result = run(**vars(args))
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
