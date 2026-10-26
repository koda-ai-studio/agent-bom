"""Answer surfaces name repository dependency and filesystem surfaces readably.

The MCP ``scan`` summary and the ``--agent-mode`` envelope showed internal
identities such as ``repo-deps:root`` and ``fs:path-7bfc9b…`` as agent and server
names. The identity stays in ids; the answer shows a readable label.
"""

from __future__ import annotations

from agent_bom.evidence.asset_display import readable_asset_name


def test_readable_asset_name_maps_internal_surfaces() -> None:
    assert readable_asset_name("repo-deps:root") == "project dependencies"
    assert readable_asset_name("repo-deps:services/api") == "project dependencies (services/api)"
    assert readable_asset_name("fs:path-7bfc9b6415c2acec2e56c19f") == "filesystem packages"
    assert readable_asset_name("github") == "github"
    assert readable_asset_name(None) is None


def _report() -> dict:
    return {
        "summary": {"total_agents": 1},
        "agents": [
            {
                "name": "repo-deps:root",
                "agent_type": "custom",
                "status": "configured",
                "mcp_servers": [{"name": "repo-deps:root", "packages": []}],
            },
            {
                "name": "filesystem:proj",
                "agent_type": "custom",
                "status": "configured",
                "mcp_servers": [{"name": "fs:path-7bfc9b64", "packages": []}],
            },
        ],
        "findings": [
            {
                "id": "f1",
                "severity": "high",
                "title": "CVE-1: requests@2.19.1",
                "finding_type": "CVE",
                "affected_agents": ["repo-deps:root"],
                "affected_servers": ["repo-deps:root"],
            }
        ],
        "exposure_paths": {"paths": [{"id": "p1", "affectedAgents": ["repo-deps:root"], "affectedServers": ["repo-deps:root"]}]},
    }


def test_mcp_scan_summary_uses_readable_names() -> None:
    import json

    from agent_bom.mcp_tools.scan_response import build_scan_summary

    text = json.dumps(build_scan_summary(_report(), result_id="r1", ttl_seconds=60, offline=True))
    assert "repo-deps:" not in text and "fs:path-" not in text
    assert "project dependencies" in text


def test_agent_mode_envelope_uses_readable_names() -> None:
    import json

    from agent_bom.cli._agent_mode import summarize_scan_data

    text = json.dumps(summarize_scan_data(_report()))
    assert "repo-deps:" not in text and "fs:path-" not in text
    assert "filesystem packages" in text
