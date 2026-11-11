#!/usr/bin/env python3
"""Measure the end-to-end workflow's resource cost per pinned profile, with no live network.

Each phase runs in its own child process so CPU-seconds and peak RSS are the
child's own (``wait4`` rusage), and a restart is a real new process on the
same store:

* ``cold``     fresh store and scan cache: collect, scan, ingest, query, export, retain, rebuild
* ``warm``     same store and scan cache, a second identical workflow
* ``restart``  new process, reads only: stored findings and graph reads must match ``warm``
* ``cancel``   a push is killed with SIGKILL after admission; a new process
               retries the identical report and must converge to the same findings
* ``replicas`` (Postgres profiles with ``api_replicas > 1``) N processes push
               distinct estates concurrently into one database

    python scripts/run_workflow_resource_benchmark.py --profile small-self-hosted
    python scripts/run_workflow_resource_benchmark.py --profile multi-replica-local \\
        --postgres-url postgresql://user@127.0.0.1:PORT/db

Not a PR gate: ``tests/test_workflow_resource_budget.py`` carries the PR budget.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CHILD_TIMEOUT_SECONDS = 1800
_PASSTHROUGH = ("AGENT_BOM_DEFER_PRODUCT_PROOF", "AGENT_BOM_AUDIT_HMAC_KEY", "AGENT_BOM_POSTGRES_POOL_")


def _child_env(workdir: Path, store: str, postgres_url: str | None) -> dict[str, str]:
    # Operator settings pass through; every path the run writes is pinned below.
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_BOM_") or key.startswith(_PASSTHROUGH)}
    env.update(
        {
            "HOME": str(workdir / "home"),
            "AGENT_BOM_STATE_DIR": str(workdir / "state"),
            "AGENT_BOM_DB_PATH": str(workdir / "state" / "no-local-vulns.db"),
            "AGENT_BOM_SCAN_CACHE": str(workdir / "state" / "scan-cache.db"),
            "AGENT_BOM_ALLOW_UNAUTHENTICATED_API": "1",
            "AGENT_BOM_NO_AUTH_ROLE": "admin",
            "PYTHONPATH": os.pathsep.join([str(ROOT / "src"), str(ROOT)]),
        }
    )
    if store == "postgres":
        if not postgres_url:
            raise SystemExit("postgres profile requires --postgres-url")
        env["AGENT_BOM_POSTGRES_URL"] = postgres_url
    else:
        env["AGENT_BOM_DB"] = str(workdir / "db" / "control-plane.db")
    return env


def _spawn(phase: str, profile: str, workdir: Path, env: dict[str, str], extra: list[str] | None = None) -> subprocess.Popen[bytes]:
    for sub in ("home", "state", "db"):
        (workdir / sub).mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "--child",
        phase,
        "--profile",
        profile,
        "--workdir",
        str(workdir),
        *(extra or []),
    ]
    log = (workdir / f"{phase}.log").open("ab")
    return subprocess.Popen(command, env=env, stdout=log, stderr=subprocess.STDOUT, cwd=str(workdir))


def _wait(process: subprocess.Popen[bytes], timeout: float = CHILD_TIMEOUT_SECONDS) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while True:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            break
        if time.monotonic() > deadline:
            process.kill()
            pid, status, usage = os.wait4(process.pid, 0)
            break
        time.sleep(0.05)
    process.returncode = os.waitstatus_to_exitcode(status)
    divisor = 1024 * 1024 if platform.system() == "Darwin" else 1024
    return {
        "exit_code": process.returncode,
        "cpu_seconds": round(usage.ru_utime + usage.ru_stime, 3),
        "max_rss_mib": round(usage.ru_maxrss / divisor, 1),
    }


def _read(workdir: Path, name: str) -> dict[str, Any] | None:
    path = workdir / f"{name}.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def _run_phase(phase: str, profile: str, workdir: Path, env: dict[str, str], extra: list[str] | None = None) -> dict[str, Any]:
    began = time.perf_counter()
    usage = _wait(_spawn(phase, profile, workdir, env, extra))
    return {"process": {**usage, "wall_seconds": round(time.perf_counter() - began, 2)}, "result": _read(workdir, phase)}


def _cancel_then_recover(profile: str, workdir: Path, env: dict[str, str]) -> dict[str, Any]:
    marker = workdir / "cancel-admitted"
    victim = _spawn("cancel", profile, workdir, env)
    deadline = time.monotonic() + CHILD_TIMEOUT_SECONDS
    while not marker.exists() and victim.poll() is None and time.monotonic() < deadline:
        time.sleep(0.01)
    admitted = marker.exists()
    killed_while_running = victim.poll() is None
    if killed_while_running:
        os.kill(victim.pid, signal.SIGKILL)
    victim_usage = _wait(victim)
    recover = _run_phase("recover", profile, workdir, env)
    return {
        "admitted_before_kill": admitted,
        "killed_while_running": killed_while_running,
        "victim": victim_usage,
        "recover": recover,
    }


def _replicas(profile_name: str, replicas: int, base: Path, env_for: Any) -> dict[str, Any]:
    began = time.perf_counter()
    children = []
    for index in range(replicas):
        workdir = base / f"replica-{index}"
        children.append((workdir, _spawn("replica", profile_name, workdir, env_for(workdir), ["--replica-index", str(index)])))
    usages = [_wait(child) for _workdir, child in children]
    return {
        "wall_seconds": round(time.perf_counter() - began, 2),
        "processes": usages,
        "results": [_read(workdir, "replica") for workdir, _child in children],
    }


def measure(profile_name: str, postgres_url: str | None, *, cancel: bool) -> dict[str, Any]:
    from scripts.perf.workflow_profiles import PROFILES

    profile = PROFILES[profile_name]
    with tempfile.TemporaryDirectory(prefix=f"workflow-{profile_name}-") as tmp:
        base = Path(tmp)

        def env_for(workdir: Path) -> dict[str, str]:
            return _child_env(workdir, profile.store, postgres_url)

        main = base / "main"
        if profile.api_replicas > 1:
            return {"profile": profile.as_dict(), "replicas": _replicas(profile_name, profile.api_replicas, base, env_for)}
        out: dict[str, Any] = {"profile": profile.as_dict()}
        for phase in ("cold", "warm", "restart"):
            out[phase] = _run_phase(phase, profile_name, main, env_for(main))
        if cancel:
            fresh = base / "cancel"
            out["cancel"] = _cancel_then_recover(profile_name, fresh, env_for(fresh))
        return out


_ACCURACY_KEYS = ("scanned_matches_expected", "stored_matches_scanned", "rebuilt_matches_stored")


def _workflow_failures(label: str, phase: dict[str, Any]) -> list[str]:
    if phase["process"]["exit_code"] != 0:
        return [f"{label}: child exited {phase['process']['exit_code']}"]
    result = phase.get("result")
    if not result:
        return [f"{label}: no result"]
    failures = [f"{label}: {key} is false" for key in _ACCURACY_KEYS if result["accuracy"].get(key) is False]
    if result["network"]["blocked_connections"]:
        failures.append(f"{label}: live network attempted: {result['network']['blocked_connections']}")
    return failures


def evidence_failures(evidence: dict[str, Any]) -> list[str]:
    """Every crashed phase, inaccurate finding set or live-network attempt in a run; empty when clean."""
    failures: list[str] = []
    for entry in evidence["profiles"]:
        name = entry["profile"]["name"]
        for phase in ("cold", "warm"):
            if phase in entry:
                failures += _workflow_failures(f"{name}/{phase}", entry[phase])
        restart = entry.get("restart")
        if restart:
            if restart["process"]["exit_code"] != 0 or not restart.get("result"):
                failures.append(f"{name}/restart: child exited {restart['process']['exit_code']}")
            elif not restart["result"].get("findings_match_before_restart"):
                failures.append(f"{name}/restart: findings changed across restart")
        recover = (entry.get("cancel") or {}).get("recover")
        if recover:
            if recover["process"]["exit_code"] != 0 or not recover.get("result"):
                failures.append(f"{name}/cancel: recovery child exited {recover['process']['exit_code']}")
            elif not recover["result"].get("findings_match_expected"):
                failures.append(f"{name}/cancel: retried push did not converge to the expected findings")
        replicas = entry.get("replicas")
        if replicas:
            for index, (usage, result) in enumerate(zip(replicas["processes"], replicas["results"], strict=True)):
                failures += _workflow_failures(f"{name}/replica-{index}", {"process": usage, "result": result})
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--profile", action="append", help="profile name (repeatable); default small-self-hosted")
    parser.add_argument("--postgres-url", default=os.environ.get("WORKFLOW_BENCH_POSTGRES_URL"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--no-cancel", action="store_true", help="skip the SIGKILL cancellation phase")
    parser.add_argument("--child", help=argparse.SUPPRESS)
    parser.add_argument("--workdir", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--replica-index", type=int, default=0, help=argparse.SUPPRESS)
    args = parser.parse_args()
    sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
    if args.child:
        from scripts.perf.workflow_phases import run_child

        return run_child(args.child, (args.profile or ["small-self-hosted"])[0], args.workdir, replica_index=args.replica_index)
    evidence: dict[str, Any] = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
            "load_average": os.getloadavg(),
        },
        "profiles": [measure(name, args.postgres_url, cancel=not args.no_cancel) for name in (args.profile or ["small-self-hosted"])],
    }
    failures = evidence_failures(evidence)
    evidence["failures"] = failures
    text = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text)
    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
