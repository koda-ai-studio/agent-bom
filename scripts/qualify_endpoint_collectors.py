#!/usr/bin/env python3
"""Run native endpoint collectors and retain only privacy-safe qualification counts.

This measures this host and permission context, not universal OS coverage. It
does not upload inventory, enroll an endpoint, or preserve raw process rows.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from agent_bom import __version__
from agent_bom.endpoint.inventory import _default_runner, collect_endpoint_inventory

CORE = {"applications", "processes", "services", "listeners"}
ALL = CORE | {"containers", "images"}
STATUSES = {"complete", "partial", "unsupported", "unavailable", "permission_denied"}


def assess(inventory: dict, *, system: str, max_items: int) -> dict:
    rows = [{key: row.get(key) for key in ("name", "status", "item_count")} for row in inventory.get("collectors", [])]
    by_name = {row["name"]: row for row in rows}
    checks = {
        "native_platform": inventory.get("platform", {}).get("system") == system,
        "all_collectors_reported": len(rows) == len(ALL) and set(by_name) == ALL,
        "valid_statuses": all(row["status"] in STATUSES for row in rows),
        "bounded_rows": all(isinstance(inventory.get(name), list) and len(inventory[name]) <= max_items for name in ALL),
        "core_collectors_ran": all(by_name.get(name, {}).get("status") in {"complete", "partial"} for name in CORE),
        "privacy_flags": bool(inventory.get("privacy")) and all(value is False for value in inventory["privacy"].values()),
    }
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "collectors": rows,
        "all_collectors_complete": len(rows) == len(ALL) and all(row["status"] == "complete" for row in rows),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, choices=range(1, 61), default=5)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Reserve the receipt before collection; never replace a previous failed run.
    with args.output.open("x", encoding="utf-8") as stream:
        start = time.monotonic()
        receipt = {
            "schema_version": "endpoint.qualification.v1",
            "source_version": __version__,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "max_items": 64,
            "command_timeout_seconds": args.timeout_seconds,
            "evidence": "native-host-collector-execution",
            "universal_os_coverage": False,
        }
        receipt["harness_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        try:
            revision = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
            dirty = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, check=False)
            receipt["source_commit"] = revision.stdout.strip() if revision.returncode == 0 else "unknown"
            receipt["source_tree"] = ("dirty" if dirty.stdout.strip() else "clean") if dirty.returncode == 0 else "unknown"
        except OSError:
            receipt.update({"source_commit": "unknown", "source_tree": "unknown"})
        try:
            commands = []

            def runner(command, timeout):
                result = _default_runner(command, timeout)
                commands.append({"executable": command[0], "status": result.status, "returncode": result.returncode})
                return result

            # Give the listener collector a known, owned resource even on an
            # otherwise idle CI host. The socket accepts no external traffic.
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                port = listener.getsockname()[1]
                inventory = collect_endpoint_inventory(max_items=64, timeout_seconds=args.timeout_seconds, runner=runner)
                receipt.update(assess(inventory, system=platform.system(), max_items=64))
                receipt["fixture_listener_observed"] = any(row.get("port") == port for row in inventory.get("listeners", []))
                receipt["passed"] = receipt["passed"] and receipt["fixture_listener_observed"]
            receipt["commands"] = commands
        except Exception as exc:
            receipt.update({"passed": False, "error_type": type(exc).__name__})
        receipt["elapsed_seconds"] = round(time.monotonic() - start, 3)
        stream.write(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
