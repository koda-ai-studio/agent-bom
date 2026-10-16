#!/usr/bin/env python3
"""Run three bounded MCP investigations against a fictional agent configuration.

Uses the real dependency parser, pinned offline advisory lookup, SQLite store
and MCP stdio transport. No agent tools execute and no deployment is changed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from prove_connected_bom import ADVISORY, scan_version

from agent_bom.api.graph_store import SQLiteGraphStore
from agent_bom.graph.builder import build_unified_graph_from_report

TENANT = "first-workflows-example"


def save(output: Path, filename: str, body: Any) -> None:
    with (output / filename).open("x") as stream:
        stream.write(json.dumps(body, indent=2, default=str) + "\n")


async def prepare(output: Path) -> list[dict[str, Any]]:
    store = SQLiteGraphStore(output / "graph.db")
    receipts = []
    for label, version in (("before", "9.0.0"), ("after", "10.0.1")):
        packages, digest = await scan_version(version)
        manifest_file = f"{label}-requirements.txt"
        with (output / manifest_file).open("x") as stream:
            stream.write(f"Pillow=={version}\n")
        report = {
            "scan_sources": ["fictional-mcp-configuration"],
            "agents": [
                {
                    "name": "example-image-assistant",
                    "agent_type": "custom",
                    "source": "fictional-mcp-configuration",
                    "config_path": "fictional/image-assistant.json",
                    "mcp_servers": [
                        {
                            "name": "example-image-tools",
                            "command": "python",
                            "args": ["-m", "fictional_image_tools"],
                            "credential_env_vars": ["EXAMPLE_API_TOKEN"],
                            "tools": [{"name": "resize_example_image"}],
                            "packages": [json.loads(json.dumps(asdict(package), default=str)) for package in packages],
                        }
                    ],
                }
            ],
        }
        save(output, f"{label}-input.json", report)
        graph = build_unified_graph_from_report(report, scan_id=f"first-{label}", tenant_id=TENANT)
        store.save_graph(graph)
        save(output, f"{label}-graph.json", graph.to_dict())
        receipts.append({"scan_id": graph.scan_id, "package_version": version, "manifest_file": manifest_file, "manifest_sha256": digest})
    return receipts


def payload(response: Any) -> dict[str, Any]:
    if response.is_error:
        raise RuntimeError("MCP rejected a documented workflow call")
    body = json.loads("".join(block.text for block in response.content if hasattr(block, "text")))
    if not isinstance(body, dict) or "error" in body:
        raise RuntimeError("MCP returned a domain error instead of investigation evidence")
    return body


async def investigate(output: Path, server_python: str) -> dict[str, Any]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    if output.exists() and any(output.iterdir()):
        raise ValueError("Choose a new or empty output directory; existing evidence is preserved")
    output.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    inputs = await prepare(output)
    # Keep the fixture isolated from operator state, credentials and tool plugins.
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_BOM_") and key != "PYTHONPATH"}
    env.update(
        AGENT_BOM_GRAPH_DB=str(output / "graph.db"),
        AGENT_BOM_MCP_TENANT_ID=TENANT,
        AGENT_BOM_STATE_DIR=str(output / "state"),
        AGENT_BOM_OFFLINE="1",
    )
    calls = []
    params = StdioServerParameters(command=server_python, args=["-m", "agent_bom", "mcp", "server", "--profile", "graph"], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            initialized = await session.initialize()

            async def call(name: str, arguments: dict[str, Any], filename: str) -> dict[str, Any]:
                call_started = time.perf_counter()
                body = payload(await session.call_tool(name, arguments))
                save(output, filename, body)
                calls.append(
                    {
                        "tool": name,
                        "arguments": arguments,
                        "artifact": filename,
                        "elapsed_seconds": round(time.perf_counter() - call_started, 4),
                    }
                )
                return body

            reach_args = {
                "node_id": f"vuln:{ADVISORY}",
                "scan_id": "first-before",
                "direction": "in",
                "entity_types": ["agent"],
                "max_depth": 4,
                "limit": 10,
            }
            affected = await call("graph_reach", reach_args, "affected-agents.json")
            if affected["total"] != 1 or len(affected["items"]) != 1 or affected["items"][0]["entityType"] != "agent":
                raise RuntimeError("The fictional configuration did not produce exactly one affected agent")
            if not affected["completeness"]["complete"] or affected["pagination"]["has_more"]:
                raise RuntimeError("The fixture's affected-agent walk is incomplete")
            first_result = time.perf_counter() - started
            filters = {"scan_id": "first-before", "finding_id": ADVISORY, "limit": 1}
            await call("exposure_paths", {**filters, "view": "summary"}, "exposure-summary.json")
            exposure = await call("exposure_paths", {**filters, "view": "full"}, "exposure-evidence.json")
            if not exposure["paths"] or not exposure["edges"]:
                raise RuntimeError("Exposure evidence is missing from the fixture")
            await call(
                "inventory_asset", {"asset_id": "pkg:pypi:pillow@9.0.0", "scan_id": "first-before", "limit": 10}, "before-component.json"
            )
            comparison = await call(
                "graph_diff", {"from_scan_id": "first-before", "to_scan_id": "first-after", "view": "summary"}, "comparison.json"
            )
            await call(
                "graph_diff",
                {
                    "from_scan_id": "first-before",
                    "to_scan_id": "first-after",
                    "view": "detail",
                    "kind": "node",
                    "entity_type": "vulnerability",
                    "change": "removed",
                    "limit": 10,
                },
                "removed-findings.json",
            )
            await call(
                "inventory_asset", {"asset_id": "pkg:pypi:pillow@10.0.1", "scan_id": "first-after", "limit": 10}, "after-component.json"
            )
            if comparison["summary"]["nodes_by_entity_type"].get("vulnerability", {}).get("removed") != 1:
                raise RuntimeError("The changed-input comparison did not retain the expected advisory removal")
            rejected = await session.call_tool("graph_reach", {**reach_args, "unexpected_argument": True})
            rejection = "".join(block.text for block in rejected.content if hasattr(block, "text"))
            if not rejected.is_error or "Unknown argument" not in rejection or "unexpected_argument" not in rejection:
                raise RuntimeError("The MCP server accepted an unknown workflow argument")
    result = {
        "schema_version": "agent-bom.first-workflows.v1",
        "evidence_origin": "fictional_agent_configuration",
        "transport": "mcp_stdio",
        "server_version": initialized.server_info.version,
        "tenant_id": TENANT,
        "inputs": inputs,
        "calls": calls,
        "first_useful_result_seconds": round(first_result, 4),
        "elapsed_seconds": round(time.perf_counter() - started, 4),
        "measurement_scope": (
            "Local fixture creation, MCP startup and first affected-agent response; excludes installation and human review."
        ),
        "deployment_verified": False,
        "strict_argument_rejection": True,
        "limits": [
            "Fictional configuration; no agent tool, cloud provider or credential was invoked.",
            "Recorded relationships do not establish execution, effective access or exploitability.",
            "One pinned advisory comparison; unknown collection coverage is not a clean estate verdict.",
            "Changed dependency input only; neither package version is installed and no deployment is remediated.",
            "Local timing is a reproducibility receipt, not a product performance benchmark. No telemetry is sent.",
        ],
    }
    save(output, "workflow-proof.json", result)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--server-python", default=sys.executable, help="Python containing agent-bom; defaults to this environment.")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    result = asyncio.run(asyncio.wait_for(investigate(output, args.server_python), timeout=90))
    print(
        json.dumps(
            {"artifact": str(output / "workflow-proof.json"), "first_useful_result_seconds": result["first_useful_result_seconds"]},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
