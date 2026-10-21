"""Isolated native inventory export: ``python -m agent_bom.cloud.native_inventory_cli``.

Install the selected provider's official SDK in the same Python environment.
No API push or graph persistence is offered until that integration is qualified.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any

from agent_bom.cli._cloud_inventory_io import _write_report
from agent_bom.cloud.native_inventory import collect_modal, collect_ngc


def _run_json(args: list[str], *, timeout: int = 30, max_bytes: int = 2 * 1024 * 1024) -> Any:
    """Bound subprocess output and runtime; never return provider stderr."""
    with subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=os.name != "nt") as proc:
        output = bytearray()
        exceeded = threading.Event()

        def stop() -> None:
            try:
                if os.name == "nt":
                    proc.kill()
                else:
                    os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        def drain(stream: Any, retain: bool) -> None:
            total = 0
            while chunk := stream.read(8192):
                total += len(chunk)
                if total > max_bytes:
                    exceeded.set()
                    stop()
                    break
                if retain:
                    output.extend(chunk)

        threads = [
            threading.Thread(target=drain, args=(stream, retain), daemon=True)
            for stream, retain in ((proc.stdout, True), (proc.stderr, False))
        ]
        for thread in threads:
            thread.start()
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            stop()
            proc.wait()
            raise ValueError("Native metadata read timed out") from None
        finally:
            for thread in threads:
                thread.join(timeout=2)
        if exceeded.is_set() or code:
            raise ValueError("Native metadata read failed or exceeded the output limit")
        return json.loads(output)


def _credential(path: Path, output: Path) -> dict[str, Any]:
    if path.resolve() == output.resolve() or path.stat().st_size > 65536:
        raise ValueError("Invalid credential/output paths")
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise ValueError("Credential file must have mode 0600")
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError("Credential file must contain an object")
    return data


def _worker(args: argparse.Namespace) -> dict[str, Any]:
    credential = _credential(args.credential_file, args.output)
    if args.provider == "modal":
        if credential.get("workspace") != args.account:
            raise ValueError("Credential scope does not match requested workspace")
        for key in list(os.environ):
            if key.startswith("MODAL_"):
                os.environ.pop(key)
        with tempfile.TemporaryDirectory(prefix="agent-bom-modal-") as directory:
            for key in ("token_id", "token_secret"):
                if not isinstance(credential.get(key), str) or not credential[key]:
                    raise ValueError("Missing Modal credential")
            os.environ.update(
                MODAL_TOKEN_ID=credential["token_id"],
                MODAL_TOKEN_SECRET=credential["token_secret"],
                MODAL_CONFIG_PATH=str(Path(directory) / "config.toml"),
                MODAL_ENVIRONMENT=args.environment,
            )
            from modal import Workspace

            return collect_modal(
                workspace=args.account,
                environment=args.environment,
                workspace_client=Workspace.from_context(),
                read=lambda argv: _run_json([sys.executable, "-m", "modal", *argv]),
                limit=args.limit,
            )
    from ngcsdk import Client

    if credential.get("organization") != args.account or not isinstance(credential.get("token"), str) or not credential["token"]:
        raise ValueError("Credential scope does not match requested organization")
    client = Client()
    client.configure(api_key=credential["token"], org_name=args.account, team_name="no-team")
    return collect_ngc(organization=args.account, client=client, limit=args.limit)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only Modal/NGC native metadata export; no resource writes or inference.")
    parser.add_argument("provider", choices=("modal", "ngc"))
    parser.add_argument("--account", required=True, help="Exact Modal workspace or NGC organization.")
    parser.add_argument("--environment", default="main", help="Explicit Modal environment.")
    parser.add_argument("--credential-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        _credential(args.credential_file, args.output)
        if args.worker:
            with contextlib.redirect_stdout(sys.stderr):
                report = _worker(args)
            sys.stdout.write(json.dumps(report) + "\n")
            return 0
        child_args = list(sys.argv[1:] if argv is None else argv)
        report = _run_json([sys.executable, "-m", "agent_bom.cloud.native_inventory_cli", *child_args, "--worker"], timeout=180)
        _write_report(args.output, report)
        sys.stdout.write(f"{args.provider}: {report['status']}; native metadata written to {args.output}\n")
        return 0 if report["status"] == "ok" else 2
    except Exception:  # broad-except: isolated CLI boundary suppresses all credential and provider diagnostics
        sys.stderr.write("Native inventory failed; check the SDK installation, private credential file and explicit scope.\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
