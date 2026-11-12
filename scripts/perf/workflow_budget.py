"""Measure one end-to-end workflow in this process: collect, scan, ingest, store, query, export, retain, rebuild.

Callers configure the control-plane stores first (SQLite paths or
``AGENT_BOM_POSTGRES_URL``) and pass a ``footprint`` callable that reports the
store's on-disk size. Each stage records CPU-seconds, wall time and RSS; HTTP
stages also record request/response bytes and p50/p95 latency. The scan runs the
real ``agent-bom agents --inventory`` command against :class:`MockUpstream`, and
:func:`network_guard` refuses (and records) any non-loopback connection.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import importlib
import ipaddress
import json
import math
import os
import platform
import socket
import statistics
import subprocess
import sys
import threading
import time
import traceback
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import psutil

from scripts.generate_graph_benchmark_estate import generate_estate
from scripts.perf.workflow_equivalence import projection_digest
from scripts.perf.workflow_lifecycle import (
    equivalence_failures,
    findings_view,
    ingest_equivalence,
    known_gaps,
    rebuild_equivalence,
    stored_rows,
    update_delete,
)
from scripts.perf.workflow_profiles import (
    WORKFLOW_PUSH_SOURCE_ID,
    MockUpstream,
    WorkflowProfile,
    cli_push_body,
    expected_findings,
    inventory_from_estate,
    vulnerable_versions,
)

MIB = 1024 * 1024
TENANT = "default"
GRAPH_READS = {
    "graph_page": "/v1/graph?limit=100",
    "graph_search": "/v1/graph/search?q=agent&limit=25",
    "attack_paths": "/v1/graph/attack-paths?limit=25",
    "findings_page": "/v1/findings?limit=100",
    "jobs_page": "/v1/jobs?limit=25",
}


def percentile(values: list[float], pct: float) -> float:
    """Nearest-rank percentile: an observed sample, never an interpolation past the slowest one."""
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(pct / 100 * len(ordered)) - 1)]


class _Guard:
    def __init__(self) -> None:
        self.blocked: list[str] = []
        self.callers: list[str] = []


def _caller() -> str:
    """Innermost agent_bom frame that opened the refused connection."""
    for frame in reversed(traceback.extract_stack()):
        if "/agent_bom/" in frame.filename:
            return f"{frame.filename.rsplit('/agent_bom/', 1)[-1]}:{frame.name}"
    return "unknown"


def _is_local(address: Any) -> bool:
    if not isinstance(address, tuple):
        return True
    host = str(address[0])
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


@contextlib.contextmanager
def network_guard() -> Iterator[_Guard]:
    """Refuse non-loopback socket connections for the duration and record each attempt."""
    guard = _Guard()
    original = socket.socket.connect

    def _connect(sock: socket.socket, address: Any) -> Any:
        if not _is_local(address):
            guard.blocked.append(f"{address[0]}:{address[1]}")
            guard.callers.append(_caller())
            raise OSError("workflow benchmark: outbound network is disabled")
        return original(sock, address)

    socket.socket.connect = _connect  # type: ignore[method-assign,assignment]
    try:
        yield guard
    finally:
        socket.socket.connect = original  # type: ignore[method-assign]


class ResourceSampler:
    """Background RSS sampler for this process (psutil, 20 ms period)."""

    def __init__(self, period: float = 0.02) -> None:
        self._process = psutil.Process()
        self._period = period
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._samples: list[int] = []
        self._thread = threading.Thread(target=self._run, name="workflow-rss-sampler", daemon=True)

    def _run(self) -> None:
        while not self._stop.is_set():
            self.sample()
            self._stop.wait(self._period)

    def sample(self) -> int:
        rss = int(self._process.memory_info().rss)
        with self._lock:
            self._samples.append(rss)
        return rss

    def mark(self) -> int:
        with self._lock:
            return len(self._samples)

    def since(self, mark: int) -> list[int]:
        with self._lock:
            return list(self._samples[mark:])

    def __enter__(self) -> ResourceSampler:
        self.sample()
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2)


class StageRecorder:
    """Records CPU-seconds, wall time and RSS for named stages."""

    def __init__(self, sampler: ResourceSampler) -> None:
        self.sampler = sampler
        self.stages: dict[str, dict[str, Any]] = {}

    @contextlib.contextmanager
    def stage(self, name: str) -> Iterator[dict[str, Any]]:
        extra: dict[str, Any] = {}
        mark = self.sampler.mark()
        cpu, wall = time.process_time(), time.perf_counter()
        try:
            yield extra
        finally:
            end_rss = self.sampler.sample()
            rss = self.sampler.since(mark) or [end_rss]
            self.stages[name] = {
                "cpu_seconds": round(time.process_time() - cpu, 3),
                "wall_seconds": round(time.perf_counter() - wall, 3),
                "rss_peak_mib": round(max(rss) / MIB, 1),
                "rss_median_mib": round(statistics.median(rss) / MIB, 1),
                "rss_end_mib": round(end_rss / MIB, 1),
                **extra,
            }


@contextlib.contextmanager
def mocked_upstream(upstream: MockUpstream) -> Iterator[None]:
    """Route every advisory/registry client the scanner creates to ``upstream``."""
    importlib.import_module("agent_bom.cli")  # load the scan path so every module binding create_client is patched
    import agent_bom.enrichment  # noqa: F401
    import agent_bom.http_client as http_client

    def _client(*_args: Any, **kwargs: Any) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=upstream.transport(), timeout=kwargs.get("timeout") or 30.0, follow_redirects=False)

    real = http_client.create_client
    patched = [
        module
        for name, module in list(sys.modules.items())
        if name.startswith("agent_bom") and getattr(module, "create_client", None) is real
    ]
    for module in patched:
        module.create_client = _client  # type: ignore[attr-defined]
    try:
        yield
    finally:
        for module in patched:
            module.create_client = real  # type: ignore[attr-defined]


def _finding_keys(blast_radius: list[dict[str, Any]]) -> set[tuple[str, str, str]]:
    keys = set()
    for row in blast_radius:
        package = row.get("package")
        name = row.get("package_name") or (package.get("name") if isinstance(package, dict) else package)
        version = row.get("package_version") or (package.get("version") if isinstance(package, dict) else None)
        keys.add((str(row.get("vulnerability_id")), str(name), str(version)))
    return keys


def findings_digest(keys: set[tuple[str, str, str]]) -> str:
    """Order-independent digest of ``(advisory, package, version)`` keys."""
    return hashlib.sha256(json.dumps(sorted(keys)).encode()).hexdigest()


def _run_cli_scan(inventory_path: Path, output: Path) -> int:
    from click.testing import CliRunner

    from agent_bom.cli import main

    args = ["agents", "--inventory", str(inventory_path), "--no-discover", "-f", "json", "-o", str(output), "-q"]
    return CliRunner().invoke(main, args, catch_exceptions=False).exit_code


_SCAN_CHILD = Path(__file__).resolve().with_name("workflow_scan_child.py")
_ROOT = Path(__file__).resolve().parents[2]


def scan_in_child(
    inventory_path: Path, output: Path, vulnerable: dict[tuple[str, str], str], *, fail_first_batches: int = 0
) -> dict[str, Any]:
    """Run the CLI scan in its own process (see ``workflow_scan_child``); return its receipt and rusage."""
    spec = output.with_name(f"{output.name}.spec.json")
    triples = [[name, version, advisory] for (name, version), advisory in sorted(vulnerable.items())]
    request = {"inventory": str(inventory_path), "output": str(output), "vulnerable": triples, "fail_first_batches": fail_first_batches}
    spec.write_text(json.dumps(request), encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(_ROOT / "src"), str(_ROOT)])}
    process = subprocess.Popen([sys.executable, str(_SCAN_CHILD), str(spec)], env=env)
    _pid, status, usage = os.wait4(process.pid, 0)
    process.returncode = os.waitstatus_to_exitcode(status)
    if process.returncode != 0:
        raise RuntimeError(f"scan child exited {process.returncode}")
    receipt: dict[str, Any] = json.loads(Path(f"{output}.scan.json").read_text(encoding="utf-8"))
    divisor = 1024 * 1024 if platform.system() == "Darwin" else 1024
    receipt["process"] = {"cpu_seconds": round(usage.ru_utime + usage.ru_stime, 3), "max_rss_mib": round(usage.ru_maxrss / divisor, 1)}
    return receipt


class _Http:
    """Thin client wrapper that records bytes and latency per call."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self.client = client
        self.request_bytes = 0
        self.response_bytes = 0

    async def call(self, method: str, url: str, **kwargs: Any) -> tuple[httpx.Response, float]:
        began = time.perf_counter()
        response = await self.client.request(method, url, **kwargs)
        elapsed = time.perf_counter() - began
        self.request_bytes += len(response.request.content or b"") + len(str(response.request.url))
        self.response_bytes += len(response.content)
        return response, elapsed


PUSH_HEADERS = {"Content-Type": "application/json", "Prefer": "respond-async"}


async def _push(http: _Http, body: bytes, deadline_seconds: float, *, idempotency_key: str | None = None) -> dict[str, Any]:
    headers = {**PUSH_HEADERS, **({"Idempotency-Key": idempotency_key} if idempotency_key else {})}
    first, admit = await http.call("POST", "/v1/results/push", content=body, headers=headers)
    if first.status_code not in {201, 202}:
        raise RuntimeError(f"push rejected: {first.status_code} {first.text[:300]}")
    retry, _ = await http.call("POST", "/v1/results/push", content=body, headers=headers)
    receipt = first.json()
    deadline = time.monotonic() + deadline_seconds
    while receipt.get("status") not in {"stored", "failed"}:
        if time.monotonic() > deadline:
            raise RuntimeError(f"push not stored within {deadline_seconds}s: {receipt}")
        await asyncio.sleep(0.05)
        receipt = (await http.call("GET", first.json()["status_url"]))[0].json()
    return {
        "admission_ms": round(admit * 1000, 1),
        "status": receipt.get("status"),
        "job_id": first.json().get("job_id"),
        "retry_status": retry.status_code,
        "retry_same_job": retry.json().get("job_id") == first.json().get("job_id"),
        "graph_nodes": (receipt.get("graph_persistence") or {}).get("nodes"),
    }


async def stored_findings(http: _Http, job_id: str) -> set[tuple[str, str, str]]:
    """Every stored finding key for ``job_id``, read back through the paged result-section API."""
    return _finding_keys(await stored_rows(http, job_id))


async def _graph_reads(http: _Http, repeats: int) -> dict[str, Any]:
    latencies: dict[str, list[float]] = {name: [] for name in GRAPH_READS}
    sizes: dict[str, int] = {}
    statuses: dict[str, int] = {}
    for _ in range(repeats):
        for name, url in GRAPH_READS.items():
            response, elapsed = await http.call("GET", url)
            latencies[name].append(elapsed * 1000)
            sizes[name] = len(response.content)
            statuses[name] = response.status_code
    return {
        name: {
            "status": statuses[name],
            "p50_ms": round(percentile(values, 50), 2),
            "p95_ms": round(percentile(values, 95), 2),
            "response_bytes": sizes[name],
            "samples": len(values),
        }
        for name, values in latencies.items()
    }


async def _exports(http: _Http, job_id: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for fmt in ("json", "graphml"):
        response, elapsed = await http.call("GET", f"/v1/scan/{job_id}/graph-export?format={fmt}")
        out[f"graph_export_{fmt}"] = {"status": response.status_code, "ms": round(elapsed * 1000, 1), "bytes": len(response.content)}
    from agent_bom.api.report_worker import _run_report_job_sync

    created, elapsed = await http.call("POST", "/v1/reports", json={"format": "ndjson", "status": "all"})
    report_id = created.json()["job_id"]
    began = time.perf_counter()
    # ASGITransport does not run the app lifespan, so the report worker loop is not
    # started; the embedded runner claims and builds this one job the same way.
    await asyncio.to_thread(_run_report_job_sync, report_id, TENANT)
    lookup, lookup_s = await http.call("GET", f"/v1/reports/{report_id}")
    job = lookup.json()
    download_bytes = None
    if job.get("status") == "done" and job.get("download_url"):
        headers = {job["download_token_header"]: job["download_token"]}
        download, _ = await http.call("GET", job["download_url"], headers=headers)
        download_bytes = len(download.content) if download.status_code == 200 else None
    out["findings_report"] = {
        "status": job.get("status"),
        "create_status": created.status_code,
        "seconds_to_done": round(time.perf_counter() - began + elapsed, 3),
        "retained_lookup_ms": round(lookup_s * 1000, 1),
        "retained_lookup_status": lookup.status_code,
        "download_bytes": download_bytes,
    }
    return out


async def _jobs_listed(http: _Http) -> int:
    payload = (await http.call("GET", "/v1/jobs?limit=100"))[0].json()
    return len(payload.get("jobs", []) if isinstance(payload, dict) else payload)


async def _expire_retained_jobs(http: _Http) -> dict[str, Any]:
    """The API maintenance sweep with its TTL forced to zero: every completed job and its snapshot expire."""
    from agent_bom.api import stores
    from agent_bom.api.scan_snapshot_store import expire_jobs_and_snapshots

    before = await _jobs_listed(http)
    removed = await asyncio.to_thread(expire_jobs_and_snapshots, stores._get_store(), 0)
    return {"jobs_before": before, "jobs_removed": removed, "jobs_after": await _jobs_listed(http)}


async def run_workflow(
    profile: WorkflowProfile,
    workdir: Path,
    *,
    footprint: Callable[[], dict[str, int]],
    retention: bool = True,
    check_equivalence: bool = True,
    source_id: str = WORKFLOW_PUSH_SOURCE_ID,
    fail_first_batches: int = 1,
    ingest_deadline_seconds: float = 600.0,
) -> dict[str, Any]:
    """Run the whole workflow once and return per-stage measurements plus accuracy checks."""
    from agent_bom.api.server import app
    from agent_bom.inventory import build_agents_from_inventory, load_inventory

    workdir.mkdir(parents=True, exist_ok=True)
    started_cpu = time.process_time()
    with ResourceSampler() as sampler, network_guard() as guard:
        recorder = StageRecorder(sampler)
        with recorder.stage("collection") as info:
            report, _summary = generate_estate(
                agents=profile.agents, seed=profile.seed, vulnerable_package_rate=profile.vulnerable_package_rate
            )
            inventory = inventory_from_estate(report)
            inventory_path = workdir / "inventory.json"
            inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
            agents = build_agents_from_inventory(load_inventory(str(inventory_path)), str(inventory_path))
            info.update(
                agents=len(agents),
                packages=sum(len(s.packages) for a in agents for s in a.mcp_servers),
                inventory_bytes=inventory_path.stat().st_size,
            )
        expected = expected_findings(report, inventory)

        report_path = workdir / "report.json"
        with recorder.stage("scan_enrichment") as info:
            # The CLI runs on a collector host, not in the API process this run measures:
            # its CPU and peak RSS are the child's own (``scan_process``).
            child = await asyncio.to_thread(
                scan_in_child, inventory_path, report_path, vulnerable_versions(report), fail_first_batches=fail_first_batches
            )
            guard.blocked.extend(child["blocked_connections"])
            guard.callers.extend(child["blocked_callers"])
            # The harness is the client in this process: keep only the rows it compares, not
            # the whole parsed report (120 MiB at 200 agents), so RSS stays the API's.
            scanned_rows = json.loads(report_path.read_text(encoding="utf-8")).get("blast_radius") or []
            scanned = _finding_keys(scanned_rows)
            info.update(
                exit_code=child["exit_code"],
                report_bytes=report_path.stat().st_size,
                findings=len(scanned),
                upstream=child["upstream"],
                scan_process=child["process"],
                cpu_seconds=child["process"]["cpu_seconds"],
            )

        body = cli_push_body(report_path.read_bytes(), source_id=source_id)
        storage_before = footprint()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://workflow", timeout=ingest_deadline_seconds
        ) as client:
            http = _Http(client)
            assert (await client.post("/v1/results/push", json={})).status_code == 422  # warm routing, admit nothing
            with recorder.stage("ingest") as info:
                pushed = await _push(http, body, ingest_deadline_seconds)
                info.update(pushed, request_bytes=http.request_bytes, response_bytes=http.response_bytes)
            stored_ingest = await stored_rows(http, pushed["job_id"])
            stored = _finding_keys(stored_ingest)
            storage_after = footprint()

            with recorder.stage("graph_api") as info:
                http.request_bytes = http.response_bytes = 0
                info.update(
                    reads=await _graph_reads(http, profile.query_repeats),
                    request_bytes=http.request_bytes,
                    response_bytes=http.response_bytes,
                )
            with recorder.stage("report_export") as info:
                http.request_bytes = http.response_bytes = 0
                info.update(await _exports(http, pushed["job_id"]), request_bytes=http.request_bytes, response_bytes=http.response_bytes)

            equivalence: dict[str, Any] = {}
            view_ingest = await findings_view(http) if check_equivalence else {}
            if check_equivalence:
                equivalence["ingest"] = ingest_equivalence(scanned_rows, stored_ingest, view_ingest)

            rebuilt: set[tuple[str, str, str]] | None = None
            storage_retained = storage_rebuilt = None
            if retention:
                with recorder.stage("retention") as info:
                    info.update(await _expire_retained_jobs(http))
                storage_retained = footprint()
                with recorder.stage("rebuild") as info:
                    # Retention removed the job, so the identical push is admitted again under
                    # its content key rather than answered from the key's old receipt.
                    again = await _push(http, body, ingest_deadline_seconds)
                    info.update(
                        status=again["status"],
                        graph_nodes=again["graph_nodes"],
                        new_job=again["job_id"] != pushed["job_id"],
                    )
                rebuilt_rows = await stored_rows(http, again["job_id"])
                rebuilt = _finding_keys(rebuilt_rows)
                storage_rebuilt = footprint()
                if check_equivalence:
                    equivalence["rebuild"] = rebuild_equivalence(
                        stored_ingest, rebuilt_rows, view_ingest, await findings_view(http), expected
                    )
            if check_equivalence:
                # Last, so the rebuild above re-ingests current evidence rather than a report
                # older than this update (an older report cannot reopen a newer resolution).
                with recorder.stage("update_delete") as info:
                    equivalence["update_delete"] = await update_delete(
                        http, report=report, inventory=inventory, inventory_path=inventory_path, source_id=source_id, before=view_ingest
                    )
                    info.update(status=equivalence["update_delete"]["status"])

    steady = recorder.stages["graph_api"]["rss_median_mib"]
    return {
        "profile": profile.as_dict(),
        "stages": recorder.stages,
        "storage": {
            "before": storage_before,
            "after_ingest": storage_after,
            "after_retention": storage_retained,
            "after_rebuild": storage_rebuilt,
            "ingest_growth_bytes": storage_after["total_bytes"] - storage_before["total_bytes"],
        },
        "accuracy": {
            "expected_findings": len(expected),
            "stored_findings": len(stored),
            "stored_digest": findings_digest(stored),
            "job_id": pushed["job_id"],
            "scanned_matches_expected": scanned == expected,
            "stored_matches_scanned": stored == scanned,
            "rebuilt_matches_stored": None if rebuilt is None else rebuilt == stored,
            "missing_after_scan": sorted(expected - scanned)[:10],
            "unexpected_after_scan": sorted(scanned - expected)[:10],
            "stored_projection_digest": projection_digest(stored_ingest),
        },
        "equivalence": {**equivalence, "failures": equivalence_failures(equivalence), "known_gaps": known_gaps(equivalence)},
        "network": {"blocked_connections": guard.blocked, "blocked_callers": sorted(set(guard.callers))},
        "process": {
            "cpu_seconds": round(time.process_time() - started_cpu, 3),
            "rss_peak_mib": max(stage["rss_peak_mib"] for stage in recorder.stages.values()),
            "rss_steady_mib": steady,
        },
    }


def sqlite_footprint(*directories: Path) -> Callable[[], dict[str, int]]:
    """Footprint of the control-plane SQLite files (main, WAL, shared memory); the client scan cache is excluded."""

    def _measure() -> dict[str, int]:
        files = {
            str(path): path.stat().st_size
            for directory in directories
            for path in sorted(directory.glob("*.db*"))
            if path.is_file() and not path.name.startswith("scan-cache")
        }
        wal = sum(size for name, size in files.items() if name.endswith("-wal"))
        return {"total_bytes": sum(files.values()), "wal_bytes": wal, "files": len(files)}

    return _measure


def postgres_footprint(dsn: str) -> Callable[[], dict[str, int]]:
    """Database, index and WAL growth for a Postgres store; WAL is bytes written since this call."""
    import psycopg

    def _query() -> tuple[int, int, int]:
        with psycopg.connect(dsn) as connection:
            row = connection.execute(
                "SELECT pg_database_size(current_database()),"
                " (SELECT coalesce(sum(pg_indexes_size(relid)), 0) FROM pg_stat_user_tables),"
                " pg_wal_lsn_diff(pg_current_wal_lsn(), '0/0')"
            ).fetchone()
        assert row is not None
        return int(row[0]), int(row[1]), int(row[2])

    start_wal = _query()[2]

    def _measure() -> dict[str, int]:
        database, indexes, wal = _query()
        return {"total_bytes": database, "index_bytes": indexes, "wal_bytes": wal - start_wal}

    return _measure
