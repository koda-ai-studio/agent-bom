#!/usr/bin/env python3
"""Qualify an installed release from offline demo to a rendered sample graph.

Run with the clean environment's Python, never ``uv run`` from a source tree.
Requires agent-bom[ui] and the Playwright test driver with Chromium installed.
Only a fresh output directory and a disposable loopback server are used.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import urlopen


def validate_report(report: dict) -> str:
    if report.get("scan_run", {}).get("outcome") != "complete":
        raise ValueError("Sample report must be complete")
    if not report.get("agents") or not report.get("scan_id"):
        raise ValueError("Sample report needs inventory and a snapshot identity")
    return str(report["scan_id"])


def validate_graph(graph: dict, scan_id: str) -> dict:
    if graph.get("scan_id") != scan_id:
        raise ValueError("API returned a different snapshot")
    nodes, edges = graph.get("nodes", []), graph.get("edges", [])
    ids = {node["id"] for node in nodes}
    if not nodes or not edges or any(edge["source"] not in ids or edge["target"] not in ids for edge in edges):
        raise ValueError("Sample graph must contain connected nodes and edges")
    return {"nodes": len(nodes), "edges": len(edges)}


def _get_json(url: str) -> dict:
    with urlopen(url, timeout=5) as response:  # noqa: S310 - caller constructs loopback URLs only
        return json.load(response)


def _wait_for_server(base: str, process: subprocess.Popen, timeout: float = 90) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Local server exited; inspect server.log")
        try:
            _get_json(base + "/health")
            return
        except (URLError, TimeoutError):
            time.sleep(0.2)
    raise TimeoutError("Local server did not become healthy")


def _browser(base: str, scan_id: str, graph: dict, output: Path, started: float) -> list[dict]:
    from playwright.sync_api import sync_playwright

    views = []
    with sync_playwright() as playwright:
        with playwright.chromium.launch() as browser:
            for theme, width in (("light", 1440), ("dark", 1440), ("light", 390), ("dark", 390)):
                page = browser.new_page(viewport={"width": width, "height": 1000}, color_scheme=theme)
                page.add_init_script(f"localStorage.setItem('agent-bom-theme', {json.dumps(theme)})")
                errors = []
                page.on("pageerror", lambda error: errors.append(type(error).__name__))
                response = page.goto(base + "/security-graph?" + urlencode({"lens": "lineage", "scan": scan_id}))
                if response is None or response.status != 200:
                    raise RuntimeError("Graph page did not load")
                page.locator(".react-flow__node").first.wait_for(timeout=60000)
                page.locator(".react-flow__edge").first.wait_for(timeout=30000)
                rendered = page.locator(".react-flow__node").evaluate_all("nodes => nodes.map(node => node.dataset.id)")
                if not set(rendered).intersection(node["id"] for node in graph["nodes"]):
                    raise RuntimeError("Rendered graph does not contain the persisted sample nodes")
                if errors:
                    raise RuntimeError("Browser raised a page error")
                if page.locator("html").get_attribute("data-theme") != theme:
                    raise RuntimeError("Browser did not apply the requested theme")
                if not page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1"):
                    raise RuntimeError("Graph page overflows the viewport")
                screenshot = f"graph-{theme}-{width}.png"
                page.screenshot(path=str(output / screenshot), full_page=True)
                views.append(
                    {
                        "theme": theme,
                        "width": width,
                        "rendered_nodes": len(rendered),
                        "screenshot": screenshot,
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                    }
                )
                page.close()
    return views


def run(output: Path, expected_version: str, install_seconds: float | None = None) -> dict:
    output.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    receipt = {
        "schema_version": "first-run.v1",
        "status": "failed",
        "claim": "automated_sample_journey_not_external_user_or_production_evidence",
        "python": platform.python_version(),
        "platform": platform.system(),
        "expected_version": expected_version,
        "install_seconds": install_seconds,
        "timings_seconds": {},
        "steps": [],
    }
    process = None
    try:
        distribution = importlib.metadata.distribution("agent-bom")
        receipt["installed_version"] = distribution.version
        if distribution.version != expected_version:
            raise ValueError("Installed version does not match the selected release")
        direct_url = json.loads(distribution.read_text("direct_url.json") or "{}")
        if direct_url.get("dir_info", {}).get("editable"):
            raise ValueError("Use a clean installed wheel, not an editable source checkout")
        executable = Path(sys.executable).with_name("agent-bom")
        if not executable.is_file():
            raise ValueError("Installed console script is missing")
        env = {k: v for k, v in os.environ.items() if not k.startswith("AGENT_BOM_") and k not in {"PYTHONPATH", "PYTHONHOME"}}
        env.update(
            AGENT_BOM_STATE_DIR=str(output / "state"),
            AGENT_BOM_DB=str(output / "control-plane.db"),
            AGENT_BOM_GRAPH_DB=str(output / "control-plane.db"),
            AGENT_BOM_SKIP_UPDATE_CHECK="1",
            AGENT_BOM_NO_AUTH_ROLE="analyst",
            NO_COLOR="1",
        )

        def command(name: str, args: list[str], expected_exit: int) -> None:
            before = time.monotonic()
            with (output / f"{name}.log").open("w") as log:
                result = subprocess.run([str(executable), *args], cwd=output, env=env, stdout=log, stderr=log, timeout=300)
            receipt["steps"].append({"name": name, "args": args, "exit_code": result.returncode, "expected_exit": expected_exit})
            receipt["timings_seconds"][name] = round(time.monotonic() - before, 3)
            if result.returncode != expected_exit:
                raise RuntimeError(f"{name} returned an unexpected exit code; inspect its log")

        command("demo", ["scan", "--demo", "--offline", "-f", "json", "-o", str(output / "demo.json")], 1)
        demo = json.loads((output / "demo.json").read_text())
        validate_report(demo)
        receipt["timings_seconds"]["first_report"] = round(time.monotonic() - started, 3)
        command("quickstart", ["quickstart", "--run", "--offline", "--sample-dir", str(output / "sample")], 0)
        report = json.loads((output / "sample/agent-bom-report.json").read_text())
        scan_id = validate_report(report)
        receipt["scan_id"] = scan_id
        receipt["package_cve_lookup"] = "bundled_demo_only; quickstart_inventory_skips_lookup"
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        with (output / "server.log").open("w") as log:
            process = subprocess.Popen(
                [
                    str(executable),
                    "serve",
                    "--persist",
                    env["AGENT_BOM_DB"],
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--allow-insecure-no-auth",
                ],
                cwd=output,
                env=env,
                stdout=log,
                stderr=log,
            )
            _wait_for_server(base, process)
            graph = _get_json(base + "/v1/graph?" + urlencode({"scan_id": scan_id, "limit": 500}))
            receipt["graph"] = validate_graph(graph, scan_id)
            receipt["views"] = _browser(base, scan_id, graph, output, started)
            receipt["timings_seconds"]["first_rendered_graph"] = receipt["views"][0]["elapsed_seconds"]
        receipt["timings_seconds"]["all_graph_views"] = round(time.monotonic() - started, 3)
        receipt["status"] = "passed"
        return receipt
    except Exception as exc:
        # Keep diagnostics in local logs; never serialize arbitrary exception text.
        receipt["error_type"] = type(exc).__name__
        raise
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New directory outside any source checkout")
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--install-seconds", type=float)
    args = parser.parse_args()
    try:
        run(args.output.resolve(), args.expected_version, args.install_seconds)
    except Exception as exc:
        print(f"First-run verification failed ({type(exc).__name__}); inspect local logs and receipt.json", file=sys.stderr)
        return 1
    print(f"First-run verification passed: {args.output / 'receipt.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
