#!/usr/bin/env python3
"""Cgroup lane: the workflow resource benchmark under CPU and memory limits the kernel enforces.

macOS has no cgroups, so the 2 CPU / 2 GiB envelope in docs/PERFORMANCE_BENCHMARKS.md
is otherwise only compared with measured numbers. This lane runs
``scripts/run_workflow_resource_benchmark.py`` inside the API image with
``docker run --cpus --memory --memory-swap`` (cgroup v2 on Linux and Docker
Desktop), samples the container's ``memory.stat`` every second, and records OOM
kills, peak anonymous and page-cache memory, CPU throttling and the harness's
own accuracy checks. A Postgres profile gets a private, migrated Postgres 16
container that the benchmark reaches over loopback, so the harness's
outbound-network guard stays strict.

    python scripts/qualification/cgroup_limits.py --image agent-bom:local --profile small-self-hosted
    python scripts/qualification/cgroup_limits.py --image agent-bom:local --profile small-self-hosted-postgres

Passwords and keys are generated per run, passed through a 0600 ``--env-file``
and never written to the result.
"""

from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import REPO_ROOT, LaneResult, run_measured, tail  # noqa: E402

MIB = 1024 * 1024
SAMPLER = """#!/bin/sh
name=$1; shift
( while :; do
    echo "$(date +%s) $(cat /sys/fs/cgroup/memory.current)" \\
      "$(awk '$1=="anon"{print $2}' /sys/fs/cgroup/memory.stat)" \\
      "$(awk '$1=="file"{print $2}' /sys/fs/cgroup/memory.stat)"
    sleep 1
  done ) > /out/$name.mem &
sampler=$!
python /src/scripts/run_workflow_resource_benchmark.py "$@" --output /out/$name.json >/dev/null 2>/out/$name.err
echo "harness_exit=$?" > /out/$name.cgroup
kill $sampler
{ echo "memory_max=$(cat /sys/fs/cgroup/memory.max)"
  echo "cpu_max=$(cat /sys/fs/cgroup/cpu.max | tr ' ' '/')"
  echo "memory_peak=$(cat /sys/fs/cgroup/memory.peak)"
  sed 's/^/memory_events_/; s/ /=/' /sys/fs/cgroup/memory.events
  sed 's/^/cpu_stat_/; s/ /=/' /sys/fs/cgroup/cpu.stat
} >> /out/$name.cgroup
"""


def parse_keyvalues(text: str) -> dict[str, str]:
    """``key=value`` lines from the sampler's cgroup dump."""
    pairs = (line.split("=", 1) for line in text.splitlines() if "=" in line)
    return {key.strip(): value.strip() for key, value in pairs}


def memory_summary(samples: str) -> dict[str, float | int]:
    """Peaks of ``memory.current`` and its anonymous and page-cache parts, in MiB."""
    rows = [line.split() for line in samples.splitlines() if len(line.split()) == 4]
    if not rows:
        return {"samples": 0}
    return {
        "samples": len(rows),
        "peak_current_mib": round(max(int(row[1]) for row in rows) / MIB, 1),
        "peak_anon_mib": round(max(int(row[2]) for row in rows) / MIB, 1),
        "peak_file_mib": round(max(int(row[3]) for row in rows) / MIB, 1),
    }


def evaluate(result: LaneResult, label: str, evidence: dict[str, Any] | None, cgroup: dict[str, str], *, oom_killed: bool) -> None:
    """Record whether the kernel enforced the limits and the workflow stayed correct inside them."""
    raw_limit = cgroup.get("memory_max", "max")
    limit = int(raw_limit) if raw_limit.isdigit() else 0
    result.check(f"{label}_memory_limit_enforced", limit > 0, f"memory.max={cgroup.get('memory_max')}")
    result.check(f"{label}_cpu_limit_enforced", cgroup.get("cpu_max", "max").split("/")[0] != "max", f"cpu.max={cgroup.get('cpu_max')}")
    oom_kills = int(cgroup.get("memory_events_oom_kill", "0") or 0)
    result.check(f"{label}_no_oom_kill", oom_kills == 0 and not oom_killed, f"oom_kill={oom_kills} OOMKilled={oom_killed}")
    result.check(f"{label}_harness_exit_zero", cgroup.get("harness_exit") == "0", f"harness_exit={cgroup.get('harness_exit')}")
    failures = (evidence or {}).get("failures")
    result.check(f"{label}_workflow_accurate", evidence is not None and failures == [], failures if evidence else "no evidence")
    result.measurements[label] = {
        "memory_max_mib": round(limit / MIB, 1) if limit else None,
        "memory_peak_mib": round(int(cgroup.get("memory_peak", "0") or 0) / MIB, 1),
        "memory_max_events": int(cgroup.get("memory_events_max", "0") or 0),
        "oom_kills": oom_kills,
        "cpu_max": cgroup.get("cpu_max"),
        "cpu_seconds": round(int(cgroup.get("cpu_stat_usage_usec", "0") or 0) / 1e6, 1),
        "cpu_throttled_periods": int(cgroup.get("cpu_stat_nr_throttled", "0") or 0),
        "cpu_throttled_seconds": round(int(cgroup.get("cpu_stat_throttled_usec", "0") or 0) / 1e6, 1),
    }


def phase_digest(evidence: dict[str, Any]) -> dict[str, Any]:
    """Per-phase wall time, CPU, peak RSS and read latency, small enough to keep in the result."""
    digest: dict[str, Any] = {}
    for profile in evidence.get("profiles", []):
        name = profile["profile"]["name"]
        for phase in ("cold", "warm", "restart"):
            if phase not in profile:
                continue
            stages = (profile[phase].get("result") or {}).get("stages") or {}
            reads = (stages.get("graph_api") or {}).get("reads") or (profile[phase].get("result") or {}).get("reads") or {}
            digest[f"{name}/{phase}"] = {
                **profile[phase]["process"],
                "reads_p50_p95_ms": {key: [value.get("p50_ms"), value.get("p95_ms")] for key, value in reads.items()},
                "stage_rss_peak_mib": {key: value.get("rss_peak_mib") for key, value in stages.items() if isinstance(value, dict)},
            }
        recover = (profile.get("cancel") or {}).get("recover") or {}
        if recover:
            digest[f"{name}/cancel"] = {
                "admitted_before_kill": profile["cancel"].get("admitted_before_kill"),
                "victim_exit": (profile["cancel"].get("victim") or {}).get("exit_code"),
                "recover_exit": (recover.get("process") or {}).get("exit_code"),
                "findings_match_expected": (recover.get("result") or {}).get("findings_match_expected"),
            }
    return digest


def docker(*args: str, timeout: float = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)  # noqa: S603, S607


def start_postgres(image: str, prefix: str, env_dir: Path) -> tuple[str, Path]:
    """A private Postgres 16 migrated to head with the app and maintenance roles; returns its name and the harness env file."""
    name = f"{prefix}-pg"
    admin, app, maintenance = (secrets.token_hex(16) for _ in range(3))
    admin_env = env_dir / "postgres.env"
    admin_env.write_text(f"POSTGRES_USER=agent_bom\nPOSTGRES_DB=agent_bom\nPOSTGRES_PASSWORD={admin}\n", encoding="utf-8")
    admin_env.chmod(0o600)
    started = docker("run", "-d", "--name", name, "--env-file", str(admin_env), "postgres:16-alpine", "-c", "max_connections=200")
    if started.returncode != 0:
        raise RuntimeError(f"postgres did not start: {started.stderr}")
    deadline = time.monotonic() + 120
    while docker("exec", name, "pg_isready", "-U", "agent_bom", "-d", "agent_bom").returncode != 0:
        if time.monotonic() > deadline:
            raise RuntimeError("postgres not ready in 120 s")
        time.sleep(1)
    time.sleep(2)
    settings = (
        f"ALTER DATABASE agent_bom SET init.app_password = '{app}';"
        f"ALTER DATABASE agent_bom SET init.maintenance_password = '{maintenance}';"
    )
    docker("exec", name, "psql", "-U", "agent_bom", "-d", "agent_bom", "-qc", settings)
    migrate_env = env_dir / "migrate.env"
    migrate_env.write_text(f"ALEMBIC_DATABASE_URL=postgresql+psycopg://agent_bom:{admin}@127.0.0.1:5432/agent_bom\n", encoding="utf-8")
    migrate_env.chmod(0o600)
    migrated = docker(
        "run", "--rm", "--network", f"container:{name}", "--env-file", str(migrate_env), "-w", "/opt/agent-bom",
        "--entrypoint", "alembic", image, "-c", "deploy/supabase/postgres/alembic.ini", "upgrade", "head",
    )  # fmt: skip
    if migrated.returncode != 0:
        raise RuntimeError(f"migration failed: {tail(migrated.stderr, 5)}")
    harness_env = env_dir / "harness.env"
    harness_env.write_text(
        f"WORKFLOW_BENCH_POSTGRES_URL=postgresql://agent_bom_app:{app}@127.0.0.1:5432/agent_bom\n"
        f"AGENT_BOM_POSTGRES_MAINTENANCE_URL=postgresql://agent_bom_maintenance:{maintenance}@127.0.0.1:5432/agent_bom\n"
        f"AGENT_BOM_AUDIT_HMAC_KEY={secrets.token_hex(32)}\nAGENT_BOM_POSTGRES_POOL_MIN_SIZE=1\nAGENT_BOM_POSTGRES_POOL_MAX_SIZE=4\n",
        encoding="utf-8",
    )
    harness_env.chmod(0o600)
    return name, harness_env


def run_profile(result: LaneResult, args: argparse.Namespace, out: Path, env_dir: Path) -> None:
    label = args.profile.replace("-", "_")
    container = f"{args.name_prefix}-{args.profile}"
    sampler = env_dir / "sampler.sh"
    sampler.write_text(SAMPLER, encoding="utf-8")
    sampler.chmod(0o755)
    command = [
        "docker", "run", "--name", container, "--cpus", args.cpus, "--memory", args.memory, "--memory-swap", args.memory,
        "-v", f"{REPO_ROOT}:/src:ro", "-v", f"{out}:/out", "-v", f"{sampler}:/sampler.sh:ro", "-w", "/tmp",
        "-e", "AGENT_BOM_DEFER_PRODUCT_PROOF=1", "-e", "AGENT_BOM_SKIP_UPDATE_CHECK=1",
    ]  # fmt: skip
    postgres = None
    if args.profile.endswith("postgres") or args.profile.startswith("multi-replica"):
        postgres, harness_env = start_postgres(args.image, args.name_prefix, env_dir)
        command += ["--network", f"container:{postgres}", "--env-file", str(harness_env)]
    command += ["--entrypoint", "sh", args.image, "/sampler.sh", label, "--profile", args.profile]
    if args.no_cancel:
        command.append("--no-cancel")
    try:
        run = run_measured(command, timeout=args.timeout)
        result.measurements[f"{label}_wall_seconds"] = run.seconds
        state = json.loads(docker("inspect", container, "--format", "{{json .State}}").stdout or "{}")
        cgroup = parse_keyvalues((out / f"{label}.cgroup").read_text(encoding="utf-8")) if (out / f"{label}.cgroup").exists() else {}
        evidence_path = out / f"{label}.json"
        evidence = json.loads(evidence_path.read_text(encoding="utf-8")) if evidence_path.exists() else None
        evaluate(result, label, evidence, cgroup, oom_killed=bool(state.get("OOMKilled")))
        samples = out / f"{label}.mem"
        result.measurements[label].update(memory_summary(samples.read_text(encoding="utf-8") if samples.exists() else ""))
        if evidence:
            result.measurements[f"{label}_phases"] = phase_digest(evidence)
    finally:
        docker("rm", "-f", container)
        if postgres:
            docker("rm", "-f", postgres)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--image", required=True, help="API image built from this checkout (docker build -t IMAGE .)")
    parser.add_argument("--profile", default="small-self-hosted", help="profile from scripts/perf/workflow_profiles.py")
    parser.add_argument("--cpus", default="2", help="docker --cpus; default is the documented 2 CPU envelope")
    parser.add_argument("--memory", default="2g", help="docker --memory and --memory-swap; default is the 2 GiB envelope")
    parser.add_argument("--name-prefix", default="agent-bom-cgroup", help="prefix for the containers this lane creates")
    parser.add_argument("--no-cancel", action="store_true", help="skip the SIGKILL cancellation phase")
    parser.add_argument("--timeout", type=float, default=7200)
    parser.add_argument("--output-dir", type=Path, help="keep the raw harness evidence here (default: a temporary directory)")
    args = parser.parse_args()
    result = LaneResult("cgroup", f"{args.profile}-{args.cpus}cpu-{args.memory}")
    result.measurements["image"] = args.image
    with tempfile.TemporaryDirectory(prefix="cgroup-lane-") as tmp:
        out = args.output_dir or Path(tmp) / "out"
        out.mkdir(parents=True, exist_ok=True)
        out.chmod(0o777)  # the image runs as a non-root user
        try:
            run_profile(result, args, out, Path(tmp))
        except Exception as exc:  # noqa: BLE001 - a lane records its own failure before exiting
            result.check("lane_completed", False, f"{type(exc).__name__}: {exc}")
    return result.write()


if __name__ == "__main__":
    raise SystemExit(main())
