#!/usr/bin/env python3
"""Performance lane: real API process on SQLite or a real Postgres service.

Fixed estates from the existing generator are pushed through the public ingest
route, then the graph, findings and full-report reads are timed from a separate
client process. A scale step then bulk-ingests findings toward one million until
it reaches the target, exhausts its time budget, or the API refuses, and records
the largest size reached and why it stopped. Nothing is extrapolated.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from common import (  # noqa: E402
    REPO_ROOT,
    RESULTS_DIR,
    LaneResult,
    agent_bom_command,
    free_port,
    http_json,
    latency_summary,
    tail,
    wait_for_http,
)
from generate_graph_benchmark_estate import generate_estate  # noqa: E402

READ_REPEATS = 20
READ_TIMEOUT_SECONDS = 120
INGEST_TIMEOUT_SECONDS = 600
HEALTH_POLL_SECONDS = 1.0
HEALTH_TIMEOUT_SECONDS = 30
SCALE_STEPS = (10_000, 50_000, 100_000, 250_000, 500_000, 1_000_000)
SCALE_BATCH = 1000
SCALE_READ_REPEATS = 10
ALEMBIC_INI = REPO_ROOT / "deploy" / "supabase" / "postgres" / "alembic.ini"


@dataclass(frozen=True)
class Estate:
    name: str
    agents: int
    vulnerable_package_rate: float
    seed: int = 2145
    # Past the sizes promised to work: not finishing inside the bound records a limit, not a failure.
    capacity_probe: bool = False


ESTATES = (
    Estate("small-25-agents", 25, 0.08),
    # Closest the generator reaches to the size an audit found slow (1,169 findings, 5,274 nodes): 1,008 and 5,399.
    Estate("audited-1169-findings", 89, 1.0, seed=2147),
    Estate("medium-1000-agents", 1000, 0.08),
    Estate("large-5000-agents", 5000, 0.08, capacity_probe=True),
)


def generate(estate: Estate) -> tuple[dict[str, Any], dict[str, Any]]:
    return generate_estate(agents=estate.agents, seed=estate.seed, vulnerable_package_rate=estate.vulnerable_package_rate)


def scale_up(
    ingest: Callable[[int, int], tuple[bool, str]],
    probe: Callable[[int], dict[str, Any]],
    *,
    steps: tuple[int, ...] = SCALE_STEPS,
    batch: int = SCALE_BATCH,
    budget_seconds: float = 1500,
) -> dict[str, Any]:
    """Ingest toward ``steps[-1]``, probing at each step, and say honestly where it stopped."""
    started = time.monotonic()
    total = 0
    rows: list[dict[str, Any]] = []
    stop_reason = ""
    for step in steps:
        while total < step and not stop_reason:
            if time.monotonic() - started >= budget_seconds:
                stop_reason = f"time budget of {budget_seconds:.0f}s exhausted on a standard hosted runner"
                break
            size = min(batch, step - total)
            ok, reason = ingest(total, size)
            if not ok:
                stop_reason = f"ingest refused at {total} findings: {reason}"
                break
            total += size
        if stop_reason:
            break
        elapsed = time.monotonic() - started
        rows.append(
            {
                "findings": total,
                "elapsed_seconds": round(elapsed, 1),
                "findings_per_second": round(total / max(elapsed, 0.001), 1),
                **probe(total),
            }
        )
    return {
        "target": steps[-1],
        "largest_reached": total,
        "reached_target": total >= steps[-1] and not stop_reason,
        "stop_reason": stop_reason or "reached target",
        "elapsed_seconds": round(time.monotonic() - started, 1),
        "steps": rows,
    }


class ApiServer:
    """The API as its own process, as deployed, so client timings cross a real socket."""

    def __init__(self, env: dict[str, str], name: str) -> None:
        self.port = free_port()
        self.key = secrets.token_urlsafe(32)
        self.base = f"http://127.0.0.1:{self.port}"
        self.headers = {"Authorization": f"Bearer {self.key}"}
        log_dir = RESULTS_DIR / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        self.log_path = log_dir / f"api-{name}.log"
        self._log = self.log_path.open("wb")
        command = agent_bom_command("api", "--host", "127.0.0.1", "--port", str(self.port), "--api-key", self.key, "--log-level", "warning")
        self.process = subprocess.Popen(command, env=env, stdout=self._log, stderr=subprocess.STDOUT)  # noqa: S603

    def wait_ready(self, timeout: float = 180) -> bool:
        return wait_for_http(f"{self.base}/health", timeout=timeout)

    def peak_rss_mb(self) -> float | None:
        try:
            for line in Path(f"/proc/{self.process.pid}/status").read_text(encoding="utf-8").splitlines():
                if line.startswith("VmHWM:"):
                    return round(int(line.split()[1]) / 1024, 1)
        except OSError:
            pass
        return None

    def stop(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self._log.close()

    def log_tail(self) -> str:
        return tail(self.log_path.read_text(encoding="utf-8", errors="replace"), 15)


def timed_reads(server: ApiServer, path: str, repeats: int = READ_REPEATS) -> dict[str, Any]:
    latencies: list[float] = []
    statuses: dict[str, int] = {}
    size = 0
    first: Any = None
    for _ in range(repeats):
        began = time.perf_counter()
        status, body, size = http_json(f"{server.base}{path}", headers=server.headers, timeout=READ_TIMEOUT_SECONDS)
        elapsed = (time.perf_counter() - began) * 1000
        statuses[str(status)] = statuses.get(str(status), 0) + 1
        if status == 200:
            latencies.append(elapsed)
            first = first if first is not None else body
    summary: dict[str, Any] = {**latency_summary(latencies), "statuses": statuses, "response_bytes": size}
    summary["cold_ms"] = round(latencies[0], 3) if latencies else None
    return {"timing": summary, "body": first}


class HealthProbe:
    """Poll liveness from a thread while a slow ingest runs, as an orchestrator would."""

    def __init__(self, server: ApiServer) -> None:
        self.url = f"{server.base}/health"
        self.timings: list[float] = []
        self.failures = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.wait(HEALTH_POLL_SECONDS):
            began = time.perf_counter()
            status, _body, _size = http_json(self.url, timeout=HEALTH_TIMEOUT_SECONDS)
            if status == 200:
                self.timings.append((time.perf_counter() - began) * 1000)
            else:
                self.failures += 1

    def __enter__(self) -> HealthProbe:
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=HEALTH_TIMEOUT_SECONDS + 5)

    def summary(self) -> dict[str, Any]:
        return {**latency_summary(self.timings), "failures": self.failures}


def push_estate(server: ApiServer, report: dict[str, Any]) -> dict[str, Any]:
    body = json.dumps({**report, "source_id": "qualification", "idempotency_key": report["scan_id"]}).encode()
    began = time.perf_counter()
    status, receipt, _size = http_json(
        f"{server.base}/v1/results/push",
        method="POST",
        body=body,
        headers={**server.headers, "Content-Type": "application/json", "Prefer": "respond-async"},
        timeout=INGEST_TIMEOUT_SECONDS,
    )
    outcome: dict[str, Any] = {"push_status": status, "body_bytes": len(body), "response_seconds": round(time.perf_counter() - began, 3)}
    if status not in (201, 202):
        outcome["ingest_status"] = "refused"
        outcome["detail"] = str(receipt)[:500]
        return outcome
    deadline = time.monotonic() + INGEST_TIMEOUT_SECONDS
    while status == 202 or (isinstance(receipt, dict) and receipt.get("status") not in {"stored", "failed", None}):
        if time.monotonic() > deadline:
            receipt = {**receipt, "status": "timed_out"} if isinstance(receipt, dict) else {"status": "timed_out"}
            break
        time.sleep(0.25)
        status, receipt, _size = http_json(f"{server.base}/v1/results/push/{outcome_job(receipt)}", headers=server.headers, timeout=60)
    outcome["job_id"] = outcome_job(receipt)
    outcome["ingest_status"] = receipt.get("status") if isinstance(receipt, dict) else "unknown"
    outcome["ingest_seconds"] = round(time.perf_counter() - began, 3)
    return outcome


def outcome_job(receipt: Any) -> str:
    return str(receipt.get("job_id", "")) if isinstance(receipt, dict) else ""


def measure_estate(result: LaneResult, estate: Estate, env: dict[str, str]) -> dict[str, Any]:
    report, summary = generate(estate)
    server = ApiServer(env, f"{result.variant}-{estate.name}")
    row: dict[str, Any] = {"agents": estate.agents, "generated": summary["counts"]}
    try:
        if not result.check(
            f"{estate.name}_api_ready", server.wait_ready(), server.log_tail() if server.process.poll() is not None else "healthy"
        ):
            return row
        with HealthProbe(server) as health:
            row.update(push_estate(server, report))
        row["health_during_ingest"] = health.summary()
        result.check(f"{estate.name}_api_stays_live_during_ingest", health.failures == 0, row["health_during_ingest"])
        stored = row.get("ingest_status") == "stored"
        detail = {key: row.get(key) for key in ("push_status", "ingest_status", "ingest_seconds", "body_bytes", "detail")}
        if estate.capacity_probe and row.get("ingest_status") == "timed_out":
            result.skip(estate.name, f"ingest unfinished after {INGEST_TIMEOUT_SECONDS}s on a standard hosted runner: {detail}")
        else:
            result.check(f"{estate.name}_ingest_stored", stored, detail)
        if not stored:
            row["log_tail"] = server.log_tail()
            return row
        graph = timed_reads(server, f"/v1/graph?scan_id={report['scan_id']}")
        findings = timed_reads(server, "/v1/findings?limit=100")
        full_report = timed_reads(server, f"/v1/scan/{row['job_id']}?view=full", repeats=3)
        row.update(
            graph=graph["timing"],
            findings=findings["timing"],
            report=full_report["timing"],
            report_bytes=full_report["timing"]["response_bytes"],
        )
        row["api_peak_rss_mb"] = server.peak_rss_mb()
        _assert_reads(result, estate, row, report, graph["body"], findings["body"])
    finally:
        row.setdefault("api_peak_rss_mb", server.peak_rss_mb())
        server.stop()
    return row


def _assert_reads(result: LaneResult, estate: Estate, row: dict[str, Any], report: dict[str, Any], graph: Any, findings: Any) -> None:
    nodes = (graph or {}).get("pagination", {}).get("total") if isinstance(graph, dict) else None
    returned = len((graph or {}).get("nodes", [])) if isinstance(graph, dict) else 0
    row["graph_nodes"] = nodes if nodes is not None else returned
    row["graph_nodes_returned"] = returned
    row["findings_total"] = findings.get("total") if isinstance(findings, dict) else None
    expected_rows = len(report["blast_radius"])
    row["estate_blast_radius_rows"] = expected_rows
    result.check(f"{estate.name}_graph_read_ok", row["graph"]["samples"] == READ_REPEATS, row["graph"]["statuses"])
    result.check(f"{estate.name}_graph_has_nodes", returned > 0, f"{returned} returned, {nodes} total")
    result.check(f"{estate.name}_findings_read_ok", row["findings"]["samples"] == READ_REPEATS, row["findings"]["statuses"])
    result.check(
        f"{estate.name}_findings_reconcile_with_estate",
        row["findings_total"] == expected_rows,
        f"API total {row['findings_total']} vs {expected_rows} pushed advisories",
    )
    result.check(f"{estate.name}_report_read_ok", row["report"]["samples"] == 3 and row["report_bytes"] > 0, row["report"]["statuses"])


def scale_ingest(server: ApiServer) -> Callable[[int, int], tuple[bool, str]]:
    def ingest(start: int, size: int) -> tuple[bool, str]:
        findings = [
            {
                "id": f"qualification-scale:{index}",
                "title": f"Qualification scale finding {index}",
                "severity": "medium",
                "effective_reach_score": float(index % 100),
                "cvss_score": float((index % 10) + 1),
                "evidence": {"package_name": "qualification-pkg", "package_version": "1.0.0", "ecosystem": "pypi"},
            }
            for index in range(start, start + size)
        ]
        body = json.dumps({"source": "qualification-scale", "findings": findings}).encode()
        status, reply, _size = http_json(
            f"{server.base}/v1/findings/bulk",
            method="POST",
            body=body,
            headers={**server.headers, "Content-Type": "application/json"},
            timeout=READ_TIMEOUT_SECONDS,
        )
        return status == 201, f"HTTP {status}: {str(reply)[:300]}"

    return ingest


def measure_scale(result: LaneResult, env: dict[str, str], budget_seconds: float) -> dict[str, Any]:
    server = ApiServer(env, f"{result.variant}-scale")
    try:
        if not result.check("scale_api_ready", server.wait_ready(), "healthy"):
            return {}

        def probe(total: int) -> dict[str, Any]:
            reads = timed_reads(server, "/v1/findings?limit=100", repeats=SCALE_READ_REPEATS)
            body = reads["body"] if isinstance(reads["body"], dict) else {}
            return {"findings_read": reads["timing"], "api_total": body.get("total"), "api_peak_rss_mb": server.peak_rss_mb()}

        outcome = scale_up(scale_ingest(server), probe, budget_seconds=budget_seconds)
        result.check(
            "scale_recorded_largest_size", outcome["largest_reached"] > 0, f"{outcome['largest_reached']}: {outcome['stop_reason']}"
        )
        wrong = [row for row in outcome["steps"] if row["api_total"] != row["findings"]]
        result.check("scale_api_total_matches_ingested", not wrong, wrong[:3] or "totals match at every step")
        slow = [row for row in outcome["steps"] if row["findings_read"]["samples"] != SCALE_READ_REPEATS]
        result.check("scale_reads_stay_available", not slow, slow[:3] or "reads answered at every step")
        if not outcome["reached_target"]:
            result.skip("one million findings", f"largest reached {outcome['largest_reached']}: {outcome['stop_reason']}")
        return outcome
    finally:
        server.stop()


def _pg_admin(admin_url: str, statements: list[str], database: str = "postgres") -> None:
    import psycopg

    with psycopg.connect(admin_url.rsplit("/", 1)[0] + f"/{database}", autocommit=True) as connection:
        for statement in statements:
            connection.execute(statement)


def bootstrap_postgres(admin_url: str, workdir: Path) -> dict[str, str]:
    """Create the migrated template the same way the fresh Alembic-only path in the contract job does."""
    owner_pass, app_pass, maintenance_pass = (secrets.token_urlsafe(24) for _ in range(3))
    _pg_admin(
        admin_url,
        [
            f"CREATE ROLE agentbom_migration_owner LOGIN PASSWORD '{owner_pass}' SUPERUSER",
            "CREATE DATABASE agentbom_template OWNER agentbom_migration_owner",
            f"ALTER DATABASE agentbom_template SET init.app_password = '{app_pass}'",
            f"ALTER DATABASE agentbom_template SET init.maintenance_password = '{maintenance_pass}'",
        ],
    )
    host = admin_url.rsplit("@", 1)[1].rsplit("/", 1)[0]
    env = {
        **os.environ,
        "ALEMBIC_DATABASE_URL": f"postgresql+psycopg://agentbom_migration_owner:{owner_pass}@{host}/agentbom_template",
        "AGENT_BOM_POSTGRES_URL": f"postgresql://agent_bom_app@{host}/agentbom_template",
        "AGENT_BOM_POSTGRES_MAINTENANCE_URL": f"postgresql://agent_bom_maintenance@{host}/agentbom_template",
    }
    app_file, maintenance_file = workdir / "pg-app", workdir / "pg-maintenance"
    app_file.write_text(app_pass, encoding="utf-8")
    maintenance_file.write_text(maintenance_pass, encoding="utf-8")
    app_file.chmod(0o600)
    maintenance_file.chmod(0o600)
    env["AGENT_BOM_POSTGRES_PASSWORD_FILE"] = str(app_file)
    env["AGENT_BOM_POSTGRES_MAINTENANCE_PASSWORD_FILE"] = str(maintenance_file)
    subprocess.run([sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), "upgrade", "head"], env=env, check=True, cwd=REPO_ROOT)  # noqa: S603
    return {"host": host, "app_file": str(app_file), "maintenance_file": str(maintenance_file)}


def backend_env(backend: str, name: str, workdir: Path, postgres: dict[str, str] | None, admin_url: str) -> dict[str, str]:
    env = {
        **os.environ,
        "HOME": str(workdir / "home"),
        "AGENT_BOM_STATE_DIR": str(workdir / f"state-{name}"),
        "AGENT_BOM_SKIP_UPDATE_CHECK": "1",
        "AGENT_BOM_AUDIT_HMAC_KEY": "qualification-synthetic-audit-key",
    }
    if backend == "sqlite":
        env["AGENT_BOM_DB"] = str(workdir / f"{name}.db")
        return env
    assert postgres is not None
    database = "qual_" + "".join(ch if ch.isalnum() else "_" for ch in name)
    _pg_admin(admin_url, [f"CREATE DATABASE {database} TEMPLATE agentbom_template"])
    env.update(
        AGENT_BOM_POSTGRES_URL=f"postgresql://agent_bom_app@{postgres['host']}/{database}",
        AGENT_BOM_POSTGRES_PASSWORD_FILE=postgres["app_file"],
        AGENT_BOM_POSTGRES_MAINTENANCE_URL=f"postgresql://agent_bom_maintenance@{postgres['host']}/{database}",
        AGENT_BOM_POSTGRES_MAINTENANCE_PASSWORD_FILE=postgres["maintenance_file"],
    )
    return env


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--backend", required=True, choices=("sqlite", "postgres"))
    parser.add_argument("--postgres-admin-url", default=os.environ.get("QUALIFICATION_POSTGRES_ADMIN_URL", ""))
    parser.add_argument("--estates", default=",".join(estate.name for estate in ESTATES))
    parser.add_argument("--scale-budget-seconds", type=float, default=1500)
    args = parser.parse_args()
    result = LaneResult("performance", args.backend)
    selected = [estate for estate in ESTATES if estate.name in args.estates.split(",")]
    with tempfile.TemporaryDirectory(prefix="qualification-performance-") as tmp:
        workdir = Path(tmp)
        (workdir / "home").mkdir()
        postgres = bootstrap_postgres(args.postgres_admin_url, workdir) if args.backend == "postgres" else None
        estates: dict[str, Any] = {}
        for estate in selected:
            estates[estate.name] = measure_estate(
                result, estate, backend_env(args.backend, estate.name, workdir, postgres, args.postgres_admin_url)
            )
        result.measurements["estates"] = estates
        if args.scale_budget_seconds > 0:
            result.measurements["scale"] = measure_scale(
                result, backend_env(args.backend, "scale", workdir, postgres, args.postgres_admin_url), args.scale_budget_seconds
            )
    scale = result.measurements.get("scale") or {}
    result.measurements["headline"] = {
        **{f"{name}_graph_p95_ms": (row.get("graph") or {}).get("p95_ms") for name, row in result.measurements["estates"].items()},
        "scale_largest": scale.get("largest_reached"),
        "scale_stop": scale.get("stop_reason"),
    }
    return result.write()


if __name__ == "__main__":
    raise SystemExit(main())
