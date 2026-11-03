#!/usr/bin/env python3
"""Measure report-push ingest with concurrent readers against a fresh SQLite control plane.

Pushes a deterministic synthetic estate (``generate_graph_benchmark_estate``)
through ``POST /v1/results/push`` in-process, retries the identical report once
(a client that timed out), and probes ``/health`` and ``/v1/jobs`` throughout.
Prints one JSON line and exits non-zero when a liveness or dedupe budget fails.

    python scripts/run_push_ingest_benchmark.py --agents 500 --mode async
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))


def _configure_environment(workdir: str) -> None:
    os.environ.setdefault("AGENT_BOM_DB", os.path.join(workdir, "control-plane.db"))
    os.environ.setdefault("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    os.environ.setdefault("AGENT_BOM_NO_AUTH_ROLE", "admin")


def _body(agents: int, seed: int) -> bytes:
    from scripts.generate_graph_benchmark_estate import generate_estate

    report, _summary = generate_estate(agents=agents, seed=seed, vulnerable_package_rate=0.08)
    report = {key: value for key, value in report.items() if key in {"agents", "blast_radius", "summary", "scan_id"}}
    report.update({"source_id": "push-benchmark", "idempotency_key": f"bench-{agents}-{seed}"})
    return json.dumps(report).encode()


def _quantile(values: list[float], pct: int) -> float:
    if len(values) < 2:
        return values[0] if values else 0.0
    return statistics.quantiles(values, n=100)[pct - 1]


async def _probe(client, path: str, out: list[float], stop: asyncio.Event) -> None:  # noqa: ANN001
    while not stop.is_set():
        began = time.monotonic()
        await client.get(path)
        out.append(time.monotonic() - began)
        await asyncio.sleep(0.05)


async def run(agents: int, seed: int, mode: str, readers: int) -> dict:
    import httpx

    from agent_bom.api.server import app

    body = _body(agents, seed)
    headers = {"Content-Type": "application/json"}
    if mode == "async":
        headers["Prefer"] = "respond-async"
    health: list[float] = []
    jobs: list[float] = []
    stop = asyncio.Event()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://bench", timeout=3600) as client:
        probes = [asyncio.create_task(_probe(client, "/health", health, stop))]
        probes += [asyncio.create_task(_probe(client, "/v1/jobs", jobs, stop)) for _ in range(max(0, readers - 1))]
        began = time.monotonic()
        first = asyncio.create_task(client.post("/v1/results/push", content=body, headers=headers))
        await asyncio.sleep(1.0)
        retry_began = time.monotonic()
        retry = await client.post("/v1/results/push", content=body, headers=headers)
        retry_seconds = time.monotonic() - retry_began
        response = await first
        response_seconds = time.monotonic() - began
        receipt = response.json()
        if response.status_code == 202:
            while (receipt := (await client.get(receipt["status_url"])).json()).get("status") not in {"stored", "failed"}:
                await asyncio.sleep(0.25)
        committed_seconds = time.monotonic() - began
        stop.set()
        await asyncio.gather(*probes)
    from agent_bom.api import stores

    return {
        "agents": agents,
        "mode": mode,
        "body_mb": round(len(body) / 1e6, 2),
        "first_status": response.status_code,
        "retry_status": retry.status_code,
        "retry_seconds": round(retry_seconds, 3),
        "time_to_response_seconds": round(response_seconds, 2),
        "time_to_committed_seconds": round(committed_seconds, 2),
        "ingest_status": receipt.get("status"),
        "jobs_stored": len(stores._get_store().list_all(all_tenants=True)),
        "health_p50_ms": round(_quantile(health, 50) * 1000, 1),
        "health_p99_ms": round(_quantile(health, 99) * 1000, 1),
        "jobs_read_p99_ms": round(_quantile(jobs, 99) * 1000, 1) if jobs else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--agents", type=int, default=50)
    parser.add_argument("--seed", type=int, default=2145)
    parser.add_argument("--mode", choices=("async", "sync"), default="async")
    parser.add_argument("--readers", type=int, default=4, help="concurrent probes: one /health plus N-1 /v1/jobs readers")
    parser.add_argument("--health-p99-ms", type=float, default=250.0)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="push-bench-") as workdir:
        _configure_environment(workdir)
        result = asyncio.run(run(args.agents, args.seed, args.mode, args.readers))
    print(json.dumps(result, sort_keys=True))
    ok = result["ingest_status"] == "stored" and result["jobs_stored"] == 1 and result["health_p99_ms"] < args.health_p99_ms
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
