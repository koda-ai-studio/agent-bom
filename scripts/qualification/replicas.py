#!/usr/bin/env python3
"""Replica lane: several API replicas on one Postgres behind a load balancer.

Runs against an installed chart (``kind_replicas.py`` sets one up on kind, with
a NodePort Service as the load balancer). Every check goes through the load
balancer with a fresh connection per request, so requests spread over the
replicas, and reads back each replica directly through ``kubectl port-forward``:

* requests spread over more than one replica (attributed from pod logs)
* distinct estates pushed concurrently are each stored with exactly their findings
* one report pushed concurrently with one ``Idempotency-Key`` becomes one job
* every replica serves the same jobs, findings and current graph
* each pushed job is stored once (one job row, one graph snapshot)
* a replica killed mid-ingest: what the job does, and whether a retry converges
* a rolling restart under steady reads: how many requests fail

Estates and expected findings come from the workflow benchmark's offline
fixture (``scripts/perf/workflow_profiles.py``), so no advisory network is used.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import secrets
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from common import REPO_ROOT, LaneResult, free_port, latency_summary  # noqa: E402

PUSH_HEADERS = {"Content-Type": "application/json", "Prefer": "respond-async"}
# Idempotency keys are unique per run, so a rerun against the same database admits new jobs.
RUN = secrets.token_hex(4)
CHECKS = ("spread", "pushes", "kill", "restart")


@dataclasses.dataclass(frozen=True)
class Estate:
    body: bytes
    expected: frozenset[tuple[str, str, str]]
    agents: int


def _scan_estate_child(agents: int, seed: int, source_id: str, workdir: Path) -> None:
    """Child process: scan one estate offline and write the push body and expected findings."""
    from scripts.generate_graph_benchmark_estate import generate_estate
    from scripts.perf.workflow_budget import _run_cli_scan, mocked_upstream, network_guard
    from scripts.perf.workflow_profiles import MockUpstream, cli_push_body, expected_findings, inventory_from_estate, vulnerable_versions

    report, _summary = generate_estate(agents=agents, seed=seed, vulnerable_package_rate=0.08)
    inventory = inventory_from_estate(report)
    inventory_path, report_path = workdir / "inventory.json", workdir / "report.json"
    inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
    with network_guard() as guard, mocked_upstream(MockUpstream(vulnerable=vulnerable_versions(report))):
        _run_cli_scan(inventory_path, report_path)
    if guard.blocked:
        raise RuntimeError(f"estate scan attempted live network: {guard.blocked}")
    (workdir / "body.json").write_bytes(cli_push_body(report_path.read_bytes(), source_id=source_id))
    (workdir / "expected.json").write_text(json.dumps(sorted(expected_findings(report, inventory))), encoding="utf-8")


def estate_env(workdir: Path) -> dict[str, str]:
    """A private home, state directory and scan cache per estate.

    The offline fixture numbers its advisories per estate, so a scan cache shared
    between estates would hand one estate another's advisory ids.
    """
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_BOM_")}
    env.update(
        {
            "HOME": str(workdir / "home"),
            "AGENT_BOM_STATE_DIR": str(workdir / "state"),
            "AGENT_BOM_SCAN_CACHE": str(workdir / "state" / "scan-cache.db"),
            "AGENT_BOM_DB_PATH": str(workdir / "state" / "no-local-vulns.db"),
            "AGENT_BOM_SKIP_UPDATE_CHECK": "1",
            "PYTHONPATH": os.pathsep.join([str(REPO_ROOT / "src"), str(REPO_ROOT), os.environ.get("PYTHONPATH", "")]),
        }
    )
    return env


def build_estate(agents: int, seed: int, source_id: str, workdir: Path) -> Estate:
    """Scan a generated estate offline with the real CLI, in its own process, and return the body the CLI would push."""
    workdir.mkdir(parents=True, exist_ok=True)
    command = [sys.executable, str(Path(__file__).resolve()), "--child-estate", str(agents), str(seed), source_id, str(workdir)]
    child = subprocess.run(command, env=estate_env(workdir), capture_output=True, text=True, timeout=1800)  # noqa: S603
    if child.returncode != 0:
        raise RuntimeError(f"estate scan failed: {child.stderr[-1500:]}")
    expected = frozenset(tuple(item) for item in json.loads((workdir / "expected.json").read_text(encoding="utf-8")))
    return Estate((workdir / "body.json").read_bytes(), expected, agents)  # type: ignore[arg-type]


def spread(counts: dict[str, int]) -> int:
    """How many replicas served at least one of the counted requests."""
    return sum(1 for value in counts.values() if value > 0)


def same_everywhere(views: dict[str, Any]) -> bool:
    """True when every replica returned the same view (and there is more than one replica)."""
    values = [json.dumps(view, sort_keys=True, default=str) for view in views.values()]
    return len(values) > 1 and len(set(values)) == 1


class Cluster:
    def __init__(self, context: str, namespace: str, selector: str) -> None:
        self.context, self.namespace, self.selector = context, namespace, selector

    def kubectl(self, *args: str, timeout: float = 300) -> subprocess.CompletedProcess[str]:
        command = ["kubectl", "--context", self.context, "-n", self.namespace, *args]
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout)  # noqa: S603, S607

    def pods(self) -> list[str]:
        """Ready replicas that are not terminating."""
        listing = json.loads(self.kubectl("get", "pods", "-l", self.selector, "-o", "json").stdout or '{"items": []}')
        ready = []
        for pod in listing["items"]:
            conditions = {c["type"]: c["status"] for c in pod.get("status", {}).get("conditions", [])}
            if conditions.get("Ready") == "True" and not pod["metadata"].get("deletionTimestamp"):
                ready.append(pod["metadata"]["name"])
        return sorted(ready)

    def log_counts(self, needle: str, since: str) -> dict[str, int]:
        return {pod: self.kubectl("logs", pod, f"--since={since}").stdout.count(needle) for pod in self.pods()}

    def psql(self, sql: str) -> str:
        return self.kubectl("exec", "deploy/postgres", "--", "psql", "-U", "agent_bom", "-d", "agent_bom", "-tAc", sql).stdout.strip()

    def forward(self, pod: str) -> tuple[subprocess.Popen[bytes], str]:
        port = free_port()
        command = ["kubectl", "--context", self.context, "-n", self.namespace, "port-forward", f"pod/{pod}", f"{port}:8422"]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # noqa: S603, S607
        base = f"http://127.0.0.1:{port}"
        for _ in range(50):
            try:
                httpx.get(f"{base}/health", timeout=1)
                break
            except httpx.HTTPError:
                time.sleep(0.2)
        return process, base


def client(base: str, key: str, timeout: float = 120) -> httpx.Client:
    limits = httpx.Limits(max_keepalive_connections=0)
    return httpx.Client(base_url=base, headers={"Authorization": f"Bearer {key}"}, timeout=timeout, limits=limits)


def push(base: str, key: str, body: bytes, idempotency_key: str) -> dict[str, Any]:
    with client(base, key) as http:
        response = http.post("/v1/results/push", content=body, headers={**PUSH_HEADERS, "Idempotency-Key": idempotency_key})
    payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
    return {
        "status": response.status_code,
        "job_id": payload.get("job_id"),
        "status_url": payload.get("status_url"),
        "body": response.text[:300],
    }


def wait_stored(base: str, key: str, status_url: str, deadline_seconds: float) -> dict[str, Any]:
    began = time.monotonic()
    last: dict[str, Any] = {}
    with client(base, key) as http:
        while time.monotonic() - began < deadline_seconds:
            try:
                response = http.get(status_url)
                last = response.json() if response.status_code == 200 else {"http": response.status_code}
            except httpx.HTTPError as exc:
                last = {"error": type(exc).__name__}
            if last.get("status") in {"stored", "failed"}:
                break
            time.sleep(1)
    return {"status": last.get("status") or last, "seconds": round(time.monotonic() - began, 1)}


def stored_findings(base: str, key: str, job_id: str) -> set[tuple[str, str, str]]:
    rows: list[dict[str, Any]] = []
    offset: int | None = 0
    with client(base, key) as http:
        while offset is not None:
            response = http.get(f"/v1/scan/{job_id}/result/blast_radius?offset={offset}&limit=1000")
            response.raise_for_status()
            page = response.json()
            rows.extend(page.get("items") or [])
            offset = page.get("next_offset")
    from scripts.perf.workflow_budget import _finding_keys

    return set(_finding_keys(rows))


def replica_view(base: str, key: str) -> dict[str, Any]:
    with client(base, key) as http:
        jobs = http.get("/v1/jobs?limit=100").json()
        rows = jobs.get("jobs", jobs) if isinstance(jobs, dict) else jobs
        findings = http.get("/v1/findings?limit=1").json()
        graph = http.get("/v1/graph?limit=100")
        for _ in range(60):
            if graph.status_code != 503:
                break
            time.sleep(1)
            graph = http.get("/v1/graph?limit=100")
        payload = graph.json() if graph.status_code == 200 else {}
    return {
        "jobs": sorted(row["job_id"] for row in rows if row.get("status") == "done"),
        "findings_total": findings.get("total"),
        "graph_status": graph.status_code,
        "graph_nodes": sorted(node.get("id") for node in payload.get("nodes", [])),
        "graph_total": (payload.get("pagination") or {}).get("total") or payload.get("total_nodes"),
    }


def check_spread(result: LaneResult, cluster: Cluster, base: str, key: str) -> None:
    with client(base, key) as http:
        statuses = Counter(http.get("/v1/jobs?limit=1").status_code for _ in range(30))
    counts = cluster.log_counts("path=/v1/jobs ", "60s")
    result.measurements["lb_requests_per_replica"] = counts
    result.check("lb_spreads_requests", statuses == Counter({200: 30}) and spread(counts) >= 2, f"{dict(statuses)} {counts}")


def check_concurrent_pushes(result: LaneResult, base: str, key: str, estates: list[Estate]) -> list[str]:
    with ThreadPoolExecutor(len(estates)) as pool:
        receipts = list(pool.map(lambda pair: push(base, key, pair[1].body, f"{RUN}-estate-{pair[0]}"), enumerate(estates)))
    jobs: list[str] = []
    for index, (receipt, estate) in enumerate(zip(receipts, estates, strict=True)):
        done = wait_stored(base, key, receipt["status_url"], 600) if receipt.get("status_url") else {"status": receipt}
        stored = stored_findings(base, key, receipt["job_id"]) if done["status"] == "stored" else set()
        result.check(
            f"concurrent_push_{index}_exact_findings",
            receipt["status"] in (201, 202) and done["status"] == "stored" and stored == set(estate.expected),
            f"admit {receipt['status']} stored={done} findings {len(stored)}/{len(estate.expected)}",
        )
        jobs.append(receipt["job_id"])
    return jobs


def check_idempotency(result: LaneResult, cluster: Cluster, base: str, key: str, estate: Estate) -> str | None:
    with ThreadPoolExecutor(6) as pool:
        receipts = list(pool.map(lambda _i: push(base, key, estate.body, f"{RUN}-idempotent"), range(6)))
    ids = {receipt["job_id"] for receipt in receipts}
    counts = cluster.log_counts("path=/v1/results/push ", "120s")
    result.measurements["idempotent_push_statuses"] = sorted(receipt["status"] for receipt in receipts)
    result.measurements["idempotent_push_replicas"] = counts
    job = next(iter(ids)) if len(ids) == 1 else None
    rows = cluster.psql(f"select count(*) from scan_jobs where job_id = '{job}'") if job else "n/a"
    result.check("idempotent_push_one_job_across_replicas", job is not None and rows == "1", f"job ids {ids} rows {rows} replicas {counts}")
    status_url = next((receipt["status_url"] for receipt in receipts if receipt.get("status_url")), None)
    if job and status_url:
        done = wait_stored(base, key, status_url, 600)
        result.check("idempotent_push_stored", done["status"] == "stored", done)
    return job


def compact(views: dict[str, Any]) -> dict[str, Any]:
    """Per-replica counts small enough to read in a check detail."""
    return {
        pod: {
            "jobs": len(view["jobs"]),
            "findings": view["findings_total"],
            "graph": [view["graph_status"], view["graph_total"], len(view["graph_nodes"])],
        }
        for pod, view in views.items()
    }


def check_consistency(result: LaneResult, cluster: Cluster, key: str, jobs: list[str], label: str, timeout: float = 180) -> None:
    """Replicas read one database but each builds its own current graph, so record the first read and the time to agree."""
    began = time.monotonic()
    first: dict[str, Any] | None = None
    while True:
        views: dict[str, Any] = {}
        for pod in cluster.pods():
            process, base = cluster.forward(pod)
            try:
                views[pod] = replica_view(base, key)
            finally:
                process.terminate()
        first = first or compact(views)
        if same_everywhere(views) or time.monotonic() - began > timeout:
            break
        time.sleep(5)
    agreed = same_everywhere(views)
    result.measurements[f"{label}_first_read"] = first
    result.measurements[f"{label}_agreed_after_seconds"] = round(time.monotonic() - began, 1) if agreed else None
    result.check(f"{label}_replicas_agree", agreed, {"first": first, "last": compact(views)})
    missing = [job for job in jobs if any(job not in view["jobs"] for view in views.values())]
    result.check("every_pushed_job_visible_on_every_replica", not missing, missing)
    for job in jobs:
        committed = (
            "select count(*) from scan_jobs j, jsonb_array_elements_text(j.data::jsonb->'progress') step"
            f" where j.job_id = '{job}' and step = 'Ingest committed'"
        )
        rows = cluster.psql(f"select (select count(*) from scan_jobs where job_id = '{job}')||'/'||({committed})")
        result.check(f"job_{job[:8]}_stored_once", rows == "1/1", f"job rows / ingest commits {rows}")


def check_kill_mid_ingest(result: LaneResult, cluster: Cluster, base: str, key: str, estate: Estate) -> None:
    since = time.time()
    receipt = push(base, key, estate.body, f"{RUN}-kill")
    time.sleep(1)
    owners = {pod: n for pod, n in cluster.log_counts("path=/v1/results/push ", f"{int(time.time() - since) + 5}s").items() if n}
    victim = next(iter(owners), None)
    result.measurements["kill_admission"] = {"status": receipt["status"], "owner": owners}
    if victim is None or receipt["status"] not in (201, 202):
        result.check("kill_mid_ingest_admitted", False, receipt)
        return
    cluster.kubectl("delete", "pod", victim, "--grace-period=0", "--force")
    after_kill = wait_stored(base, key, receipt["status_url"], 300)
    result.measurements["kill_job_after_kill"] = {"killed": victim, **after_kill}
    result.measurements["kill_recovered_without_retry"] = after_kill["status"] == "stored"
    # An identical retry either replays the stored job (201) or re-offers the pending one (202).
    retry = push(base, key, estate.body, f"{RUN}-kill")
    retried = (
        wait_stored(base, key, retry["status_url"], 600)
        if retry.get("status_url")
        else {"status": "stored" if retry["status"] == 201 else retry}
    )
    job = retry.get("job_id") or receipt["job_id"]
    stored = stored_findings(base, key, job) if retried["status"] == "stored" else set()
    result.measurements["kill_retry"] = {"admit": retry["status"], "same_job": job == receipt["job_id"], **retried}
    result.check(
        "kill_mid_ingest_converges",
        job == receipt["job_id"] and retried["status"] == "stored" and stored == set(estate.expected),
        f"killed {victim}; after kill {after_kill}; retry {retry['status']} {retried}; findings {len(stored)}/{len(estate.expected)}",
    )


def check_rolling_restart(result: LaneResult, cluster: Cluster, base: str, key: str, deployment: str) -> None:
    stop = threading.Event()
    statuses: Counter[str] = Counter()
    latencies: list[float] = []

    def reader() -> None:
        with client(base, key, timeout=10) as http:
            while not stop.is_set():
                began = time.perf_counter()
                try:
                    statuses[str(http.get("/v1/jobs?limit=1").status_code)] += 1
                except httpx.HTTPError as exc:
                    statuses[type(exc).__name__] += 1
                latencies.append((time.perf_counter() - began) * 1000)
                time.sleep(0.1)

    thread = threading.Thread(target=reader, daemon=True)
    thread.start()
    began = time.monotonic()
    cluster.kubectl("rollout", "restart", f"deployment/{deployment}")
    rollout = cluster.kubectl("rollout", "status", f"deployment/{deployment}", "--timeout=600s", timeout=660)
    result.measurements["rolling_restart_seconds"] = round(time.monotonic() - began, 1)
    time.sleep(5)
    stop.set()
    thread.join(timeout=15)
    failed = sum(count for status, count in statuses.items() if status != "200")
    result.measurements["rolling_restart_requests"] = dict(statuses)
    result.measurements["rolling_restart_latency"] = latency_summary(latencies)
    result.check("rolling_restart_completes", rollout.returncode == 0, rollout.stdout[-300:] + rollout.stderr[-300:])
    result.check("rolling_restart_no_failed_requests", failed == 0, dict(statuses))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", help="load balancer URL in front of the API replicas")
    parser.add_argument("--api-key-file", type=Path, help="file holding an admin API key (kind_replicas.py writes one)")
    parser.add_argument("--context")
    parser.add_argument("--namespace", default="agent-bom")
    parser.add_argument("--deployment", default="agent-bom-api")
    parser.add_argument("--selector", default="app.kubernetes.io/component=api")
    parser.add_argument("--agents", type=int, default=12, help="agents per concurrently pushed estate")
    parser.add_argument("--kill-agents", type=int, default=100, help="agents in the push whose replica is killed")
    parser.add_argument("--checks", action="append", choices=CHECKS, help="run only these checks (repeatable); default all")
    parser.add_argument("--child-estate", nargs=4, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.child_estate:
        agents, seed, source_id, workdir = args.child_estate
        _scan_estate_child(int(agents), int(seed), source_id, Path(workdir))
        return 0
    if not (args.base_url and args.api_key_file and args.context):
        parser.error("--base-url, --api-key-file and --context are required")
    key = args.api_key_file.read_text(encoding="utf-8").strip() if args.api_key_file.exists() else ""
    result = LaneResult("replicas", "kind-helm")
    cluster = Cluster(args.context, args.namespace, args.selector)
    result.measurements["replicas"] = len(cluster.pods())
    try:
        if not key:
            raise RuntimeError(f"no API key in {args.api_key_file}")
        with tempfile.TemporaryDirectory(prefix="replica-lane-") as tmp:
            estates = [build_estate(args.agents, 2145 + index, f"replica-lane-{index}", Path(tmp) / f"e{index}") for index in range(3)]
            big = build_estate(args.kill_agents, 3145, "replica-lane-kill", Path(tmp) / "kill")
        result.measurements["estates"] = {"agents": args.agents, "findings": [len(e.expected) for e in estates], "kill_agents": big.agents}
        selected = set(args.checks or CHECKS)
        jobs: list[str] = []
        if "spread" in selected:
            check_spread(result, cluster, args.base_url, key)
        if "pushes" in selected:
            jobs = check_concurrent_pushes(result, args.base_url, key, estates)
            idempotent = check_idempotency(result, cluster, args.base_url, key, estates[0])
            check_consistency(result, cluster, key, [*jobs, *([idempotent] if idempotent else [])], "after_pushes")
        if "kill" in selected:
            check_kill_mid_ingest(result, cluster, args.base_url, key, big)
        if "restart" in selected:
            check_rolling_restart(result, cluster, args.base_url, key, args.deployment)
            check_consistency(result, cluster, key, jobs, "after_restart")
    except Exception as exc:  # noqa: BLE001 - a lane records its own failure before exiting
        result.check("lane_completed", False, f"{type(exc).__name__}: {exc}")
    return result.write()


if __name__ == "__main__":
    raise SystemExit(main())
