#!/usr/bin/env python3
"""Qualify mixed runtime writes and status reads over disposable loopback HTTP.

Uses synthetic connection credentials and runtime events, real middleware and
SQL. API replicas run separately from the load generator. This is a local
measurement, not EKS or provider parity.
PostgreSQL requires an already migrated disposable database and application role.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import multiprocessing
import os
import platform
import socket
import ssl
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


def _runtime(output: Path, backend: str):
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
    return runtime, pool


def _serve_replica(output: Path, backend: str, secret: str, ready):
    runtime, pool = _runtime(output, backend)
    set_runtime_event_store(runtime)
    configure_api(api_key=secret)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(128)
    ready.send(listener.getsockname()[1])
    ready.close()
    try:
        uvicorn.Server(uvicorn.Config(app, log_level="error", lifespan="off")).run(sockets=[listener])
    finally:
        listener.close()
        set_runtime_event_store(None)
        if pool is not None:
            pool.close()


def run(output: Path, *, backend: str, replicas: int = 1) -> dict:
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
    os.environ.setdefault("AGENT_BOM_AUDIT_HMAC_KEY", uuid4().hex + uuid4().hex)
    runtime, pool = _runtime(output, backend)
    attempts = []
    guard = threading.Lock()
    processes = []
    bases = []
    try:
        context = multiprocessing.get_context("spawn")
        for _ in range(replicas):
            parent, child = context.Pipe(duplex=False)
            process = context.Process(target=_serve_replica, args=(output, backend, secret, child))
            process.start()
            child.close()
            processes.append(process)
            if not parent.poll(30):
                parent.close()
                raise RuntimeError("Qualification HTTP server did not initialize")
            bases.append(f"http://127.0.0.1:{parent.recv()}")
            parent.close()
        request_index = 0
        # Certificate loading is setup, even for plaintext loopback HTTP. Sharing
        # its immutable context keeps fresh client/connection semantics without
        # serializing every worker on repeated trust-store parsing.
        tls_context = ssl.create_default_context()

        def request(tenant, phase, body=None):
            nonlocal request_index
            with guard:
                base = bases[request_index % len(bases)]
                request_index += 1
            start = time.perf_counter()
            row = {"phase": phase, "operation": "status" if body is None else "write", "ok": False}
            try:
                # Match the deployment probe's fresh HTTP client per request.
                with httpx.Client(base_url=base, trust_env=False, timeout=30, verify=tls_context) as client:
                    row["client_setup_ms"] = (time.perf_counter() - start) * 1000
                    sent = time.perf_counter()
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
                    row["response_ms"] = (time.perf_counter() - sent) * 1000
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

        for base in bases:
            deadline = time.monotonic() + 30
            with httpx.Client(base_url=base, trust_env=False, timeout=2) as client:
                while True:
                    try:
                        if client.get("/health").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    if time.monotonic() > deadline:
                        raise RuntimeError("Qualification HTTP server did not start")
                    time.sleep(0.05)
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
        from agent_bom.api.audit_log import get_audit_log

        counts = []
        audit_counts = []
        audit = get_audit_log()
        for tenant in [reader, *(f"{prefix}-writer-{i}" for i in range(4))]:
            token = set_current_tenant(tenant)
            try:
                rows = runtime.list_observations(tenant, limit=1000)
                sessions = runtime.list_sessions(tenant)
                counts.append(len(rows) == (0 if tenant == reader else 500))
                counts.append(sum(s.observation_count for s in sessions) == len(rows))
                counts.append(all(row.tenant_id == tenant for row in rows))
                expected_audit = 1026 if tenant == reader else 10
                entries = audit.list_entries(tenant_id=tenant, limit=2000)
                verified, tampered = audit.verify_integrity(tenant_id=tenant)
                audit_counts.append(len(entries))
                counts.append(len(entries) == expected_audit and verified == expected_audit and tampered == 0)
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
            "replicas": replicas,
            "load_generator_process": "separate-from-API",
            "client_transport": "fresh-client-and-connection/shared-TLS-context",
            "concurrency": 10,
            "audit_counts": audit_counts,
            "failed_requests": sum(not row["ok"] for row in attempts),
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
        for process in processes:
            process.terminate()
        for process in processes:
            process.join(timeout=10)
            if process.is_alive():
                process.kill()
                process.join(timeout=5)
        set_runtime_event_store(None)
        if pool is not None:
            pool.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--backend", choices=["sqlite", "postgres"], default="sqlite")
    parser.add_argument("--replicas", type=int, choices=[1, 2, 4], default=1)
    args = parser.parse_args()
    if args.replicas > 1 and args.backend != "postgres":
        parser.error("Multiple replicas require PostgreSQL")
    if args.backend == "postgres" and not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        parser.error("PostgreSQL requires a migrated disposable application-role database")
    result = run(**vars(args))
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
