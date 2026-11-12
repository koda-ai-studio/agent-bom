#!/usr/bin/env python3
"""Upgrade lane: a released API image to this checkout's image on one Postgres, and back.

    python scripts/qualification/upgrade.py --from-image agentbom/agent-bom:0.114.0 --to-image agent-bom:local

1. Postgres 16 migrated by the old image; the old API stores a pushed estate.
2. ``pg_dump`` of that database (the backup).
3. The new image migrates to its head; the new API serves the same jobs, findings
   and graph, and stores a second push.
4. Rollback: the new image's Alembic downgrades to the old head; the old API
   serves both pushes.
5. Restore: the backup restored into a fresh Postgres, migrated by the new
   image, serves the first push.
6. Removal: every container, network and volume the lane made is deleted and
   none remains.

Containers run on a private Docker network with loopback-only published ports.
Passwords and keys are generated per run and passed through 0600 env files.
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

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parent))

from common import LaneResult, secret_env, tail  # noqa: E402
from replicas import Estate, build_estate, replica_view, stored_findings, wait_stored  # noqa: E402

ALEMBIC_INI = "deploy/supabase/postgres/alembic.ini"


def docker(
    *args: str, timeout: float = 900, stdin: bytes | None = None, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["docker", *args], capture_output=True, input=stdin, timeout=timeout, env=env)  # noqa: S603, S607


def checked(*args: str, timeout: float = 900, env: dict[str, str] | None = None) -> str:
    completed = docker(*args, timeout=timeout, env=env)
    if completed.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args[:3])} failed: {tail(completed.stderr.decode(errors='replace'), 6)}")
    return completed.stdout.decode(errors="replace").strip()


class Stack:
    def __init__(self, prefix: str, workdir: Path) -> None:
        self.prefix, self.workdir = prefix, workdir
        self.network = f"{prefix}-net"
        self.passwords = {role: secrets.token_hex(16) for role in ("admin", "app", "maintenance")}
        self.api_key = secrets.token_hex(24)
        self.api_env: dict[str, str] = {
            "AGENT_BOM_API_KEYS": f"{self.api_key}:admin",
            "AGENT_BOM_AUDIT_HMAC_KEY": secrets.token_hex(32),
            "AGENT_BOM_SKIP_UPDATE_CHECK": "1",
            "AGENT_BOM_API_LOCAL_PATH_SCANS": "disabled",
        }

    def url(self, role: str, host: str, driver: str = "postgresql") -> str:
        user = {"admin": "agent_bom", "app": "agent_bom_app", "maintenance": "agent_bom_maintenance"}[role]
        return f"{driver}://{user}:{self.passwords[role]}@{host}:5432/agent_bom"

    def postgres(self, name: str) -> str:
        container = f"{self.prefix}-{name}"
        boot_args, boot_env = secret_env(
            {"POSTGRES_USER": "agent_bom", "POSTGRES_DB": "agent_bom", "POSTGRES_PASSWORD": self.passwords["admin"]}
        )
        checked(
            "run",
            "-d",
            "--name",
            container,
            "--network",
            self.network,
            "-v",
            f"{container}-data:/var/lib/postgresql/data",
            *boot_args,
            "postgres:16-alpine",
            env=boot_env,
        )
        deadline = time.monotonic() + 120
        while docker("exec", container, "pg_isready", "-U", "agent_bom", "-d", "agent_bom").returncode != 0:
            if time.monotonic() > deadline:
                raise RuntimeError(f"{container} not ready")
            time.sleep(1)
        time.sleep(2)
        settings = (
            f"ALTER DATABASE agent_bom SET init.app_password = '{self.passwords['app']}';"
            f"ALTER DATABASE agent_bom SET init.maintenance_password = '{self.passwords['maintenance']}';"
        )
        checked("exec", container, "psql", "-U", "agent_bom", "-d", "agent_bom", "-qc", settings)
        return container

    def alembic(self, image: str, database: str, *command: str) -> str:
        migrate_args, migrate_env = secret_env({"ALEMBIC_DATABASE_URL": self.url("admin", database, "postgresql+psycopg")})
        checked(
            "run",
            "--rm",
            "--network",
            self.network,
            *migrate_args,
            "-w",
            "/opt/agent-bom",
            "--entrypoint",
            "alembic",
            image,
            "-c",
            ALEMBIC_INI,
            *command,
            env=migrate_env,
        )
        return checked("exec", database, "psql", "-U", "agent_bom", "-d", "agent_bom", "-tAc", "select version_num from alembic_version")

    def api(self, image: str, database: str) -> tuple[str, str]:
        container = f"{self.prefix}-api"
        docker("rm", "-f", container)
        values = {
            **self.api_env,
            "AGENT_BOM_POSTGRES_URL": self.url("app", database),
            "AGENT_BOM_POSTGRES_MAINTENANCE_URL": self.url("maintenance", database),
        }
        api_args, api_env = secret_env(values)
        checked(
            "run",
            "-d",
            "--name",
            container,
            "--network",
            self.network,
            "-p",
            "127.0.0.1::8422",
            *api_args,
            image,
            "api",
            "--host",
            "0.0.0.0",
            "--port",
            "8422",
            env=api_env,
        )
        base = "http://" + checked("port", container, "8422").split()[0]
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            try:
                if httpx.get(base + "/health", timeout=2).status_code == 200:
                    return container, base
            except httpx.HTTPError:
                pass  # not listening yet; retried until the deadline
            if docker("inspect", container, "--format", "{{.State.Running}}").stdout.strip() == b"false":
                break
            time.sleep(1)
        raise RuntimeError(f"API {image} did not become healthy: {tail(docker('logs', container).stderr.decode(errors='replace'), 8)}")


def push_and_verify(result: LaneResult, name: str, base: str, key: str, estate: Estate, idempotency_key: str) -> str | None:
    from replicas import push

    receipt = push(base, key, estate.body, idempotency_key)
    done = wait_stored(base, key, receipt["status_url"], 600) if receipt.get("status_url") else {"status": receipt}
    stored = stored_findings(base, key, receipt["job_id"]) if done["status"] == "stored" else set()
    result.check(
        name,
        done["status"] == "stored" and stored == set(estate.expected),
        f"{receipt['status']} {done} {len(stored)}/{len(estate.expected)}",
    )
    return receipt.get("job_id")


def view(base: str, key: str, *, changed_from: int | None = None, timeout: float = 180) -> dict[str, Any]:
    """Jobs, findings and the current graph; with ``changed_from``, wait for the graph's asynchronous rebuild after a push."""
    deadline = time.monotonic() + timeout
    while True:
        snapshot = replica_view(base, key)
        snapshot["graph_nodes"] = len(snapshot["graph_nodes"])
        if changed_from is None or snapshot["graph_total"] != changed_from or time.monotonic() > deadline:
            return snapshot
        time.sleep(3)


def run(result: LaneResult, args: argparse.Namespace, workdir: Path) -> None:
    stack = Stack(args.name_prefix, workdir)
    key = stack.api_key
    estates = [build_estate(args.agents, 4145 + index, f"upgrade-lane-{index}", workdir / f"estate-{index}") for index in range(2)]
    checked("network", "create", stack.network)
    database = stack.postgres("pg")
    old_head = stack.alembic(args.from_image, database, "upgrade", "head")
    result.measurements["from_head"] = old_head
    _container, base = stack.api(args.from_image, database)
    first = push_and_verify(result, "old_api_stores_push", base, key, estates[0], "upgrade-first")
    before = view(base, key)
    result.measurements["view_on_old"] = before

    dump = workdir / "backup.dump"
    dumped = docker("exec", database, "pg_dump", "-U", "agent_bom", "-d", "agent_bom", "-Fc")
    dump.write_bytes(dumped.stdout)
    result.check("backup_pg_dump", dumped.returncode == 0 and dump.stat().st_size > 0, f"{dump.stat().st_size} bytes")
    result.measurements["backup_bytes"] = dump.stat().st_size

    began = time.monotonic()
    new_head = stack.alembic(args.to_image, database, "upgrade", "head")
    result.measurements["upgrade"] = {"to_head": new_head, "seconds": round(time.monotonic() - began, 1)}
    _container, base = stack.api(args.to_image, database)
    after = view(base, key)
    result.measurements["view_on_new"] = after
    result.check("upgrade_keeps_jobs_findings_graph", after == before, {"before": before, "after": after})
    second = push_and_verify(result, "new_api_stores_push", base, key, estates[1], "upgrade-second")
    on_new = view(base, key, changed_from=after["graph_total"])
    result.measurements["view_on_new_after_push"] = on_new

    began = time.monotonic()
    rolled = stack.alembic(args.to_image, database, "downgrade", old_head)
    result.measurements["rollback"] = {"to_head": rolled, "seconds": round(time.monotonic() - began, 1)}
    result.check("rollback_reaches_old_head", rolled == old_head, rolled)
    _container, base = stack.api(args.from_image, database)
    rolled_view = view(base, key)
    result.measurements["view_after_rollback"] = rolled_view
    result.check(
        "rollback_old_api_serves_both_pushes",
        rolled_view == on_new and {first, second} <= set(rolled_view["jobs"]),
        {"new": on_new, "rolled": rolled_view},
    )

    restored = stack.postgres("pg-restore")
    # Roles are cluster objects a dump does not carry: the old image's migration creates them first.
    stack.alembic(args.from_image, restored, "upgrade", "head")
    loaded = docker(
        "exec",
        "-i",
        restored,
        "pg_restore",
        "-U",
        "agent_bom",
        "-d",
        "agent_bom",
        "--no-owner",
        "--clean",
        "--if-exists",
        stdin=dump.read_bytes(),
    )
    result.measurements["restore_stderr"] = tail(loaded.stderr.decode(errors="replace"), 5)
    stack.alembic(args.to_image, restored, "upgrade", "head")
    _container, base = stack.api(args.to_image, restored)
    restored_view = view(base, key)
    result.measurements["view_after_restore"] = restored_view
    result.check("restore_serves_backed_up_push", restored_view == before, {"backup": before, "restored": restored_view})


def remove(result: LaneResult, prefix: str) -> None:
    containers = docker("ps", "-aq", "--filter", f"name=^{prefix}-").stdout.decode().split()
    if containers:
        docker("rm", "-f", "-v", *containers)
    volumes = docker("volume", "ls", "-q", "--filter", f"name=^{prefix}-").stdout.decode().split()
    if volumes:
        docker("volume", "rm", *volumes)
    docker("network", "rm", f"{prefix}-net")
    left = [
        *docker("ps", "-aq", "--filter", f"name=^{prefix}-").stdout.decode().split(),
        *docker("volume", "ls", "-q", "--filter", f"name=^{prefix}-").stdout.decode().split(),
        *docker("network", "ls", "-q", "--filter", f"name=^{prefix}-").stdout.decode().split(),
    ]
    result.check("removal_leaves_nothing", not left, left)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--from-image", required=True, help="released image, e.g. agentbom/agent-bom:0.114.0")
    parser.add_argument("--to-image", required=True, help="image built from this checkout")
    parser.add_argument("--agents", type=int, default=12)
    parser.add_argument("--name-prefix", default="agent-bom-upgrade")
    args = parser.parse_args()
    result = LaneResult("upgrade", "postgres")
    result.measurements["images"] = {"from": args.from_image, "to": args.to_image}
    with tempfile.TemporaryDirectory(prefix="upgrade-lane-") as tmp:
        try:
            run(result, args, Path(tmp))
        except Exception as exc:  # noqa: BLE001 - a lane records its own failure before exiting
            result.check("lane_completed", False, f"{type(exc).__name__}: {exc}")
        finally:
            remove(result, args.name_prefix)
    print(json.dumps(result.measurements, indent=1, default=str)[:3000])
    return result.write()


if __name__ == "__main__":
    raise SystemExit(main())
