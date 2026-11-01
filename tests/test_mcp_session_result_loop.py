"""The agent loop over stdio: ``scan`` → ``blast_radius`` → ``should_i_deploy``.

A fresh stdio session that has just scanned a project must answer follow-up
analysis questions from that scan, not from a persisted snapshot made on
another day and not with "run a fresh scan first".
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from agent_bom.db.schema import init_db

REPO_ROOT = Path(__file__).parents[1]
FIXTURE_PROJECT = REPO_ROOT / "tests" / "fixtures" / "mcp_session_loop" / "project"
CVE = "CVE-2025-6514"


def _seed_local_db(path: Path) -> Path:
    conn = init_db(path)
    try:
        conn.execute(
            "INSERT INTO vulns(id,summary,severity,cvss_score,source) VALUES (?,?,?,?,'osv')",
            (CVE, "mcp-remote command injection", "critical", 9.6),
        )
        conn.execute(
            "INSERT INTO affected(vuln_id,ecosystem,package_name,introduced,fixed,last_affected) VALUES (?,?,?,?,?,'')",
            (CVE, "npm", "mcp-remote", "0", "0.1.16"),
        )
        conn.execute(
            "INSERT INTO sync_meta(source,last_synced,record_count) VALUES ('osv',?,1)",
            (datetime.now(timezone.utc).isoformat(),),
        )
        conn.commit()
    finally:
        conn.close()
    return path


def _text(result) -> str:
    return "".join(getattr(block, "text", "") for block in result.content)


def test_stdio_scan_then_blast_radius_and_deploy_gate_use_the_session_scan(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(home),
            "AGENT_BOM_STATE_DIR": str(tmp_path / "state"),
            "AGENT_BOM_DB_PATH": str(_seed_local_db(tmp_path / "vulns.db")),
            "AGENT_BOM_MCP_WORKSPACE_ROOTS": str(FIXTURE_PROJECT),
            "AGENT_BOM_OFFLINE": "1",
            "PYTHONPATH": str(REPO_ROOT / "src"),
        }
    )
    for key in ("AGENT_BOM_TENANT_ID", "AGENT_BOM_MCP_TENANT_ID", "AGENT_BOM_CONFIG"):
        env.pop(key, None)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-c", "from agent_bom.cli import cli_main; cli_main()", "mcp", "server", "--profile", "full", "--log-level", "error"],
        env=env,
    )

    async def loop() -> tuple[dict, dict, dict]:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                scan = json.loads(
                    _text(await session.call_tool("scan", {"project_path": str(FIXTURE_PROJECT), "no_discover": True, "offline": True}))
                )
                blast = json.loads(_text(await session.call_tool("blast_radius", {"cve_id": CVE})))
                gate = json.loads(_text(await session.call_tool("should_i_deploy", {"candidate": "mcp-remote@0.1.15"})))
                return scan, blast, gate

    scan, blast, gate = asyncio.run(asyncio.wait_for(loop(), timeout=220))

    assert scan.get("result_id"), scan
    assert CVE in json.dumps(scan), "the seeded advisory must come back from the session scan"

    assert blast.get("found") is True, blast
    assert blast["source"] == "session_scan_result"
    assert blast["result_id"] == scan["result_id"]
    assert blast["blast_radii"][0]["package"] == "mcp-remote@0.1.15"
    assert blast["blast_radii"][0]["affected_servers"] == ["remote-bridge"]
    assert blast["blast_radii"][0]["affected_agents"]

    assert gate["decision"] != "not_found", gate
    assert gate["decision"] in {"warn", "block"}
    assert gate["provenance"]["source"] == "mcp_should_i_deploy"
    assert gate["provenance"]["basis"] == "session_scan_result"
    assert gate["result_id"] == scan["result_id"]
    assert gate["matchedPathCount"] >= 1
