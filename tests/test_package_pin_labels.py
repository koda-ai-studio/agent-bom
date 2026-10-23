"""A floating launcher's observed version must never read as a pin."""

import json

from agent_bom.asset_provenance import package_version_provenance
from agent_bom.models import Package


def test_floating_reference_has_no_pinned_version():
    pkg = Package(
        name="@modelcontextprotocol/server-filesystem",
        version="2.0.0",
        ecosystem="npm",
        version_source="tool_cache",
        floating_reference=True,
        floating_reference_reason="npx command omitted an explicit package version",
    )
    prov = package_version_provenance(pkg)
    assert prov["pinned"] is False
    assert "pinned_version" not in prov
    assert prov["resolved_version"] == "2.0.0"
    assert prov["floating_reference"] is True


def test_exact_version_is_pinned():
    pkg = Package(name="requests", version="2.32.4", ecosystem="pypi", version_source="manifest", declared_version="2.32.4")
    prov = package_version_provenance(pkg)
    assert prov["pinned"] is True
    assert prov["pinned_version"] == "2.32.4"


def test_unresolved_latest_is_neither_pinned_nor_observed():
    pkg = Package(name="mcp-server-postgres", version="latest", ecosystem="pypi", floating_reference=True)
    prov = package_version_provenance(pkg)
    assert prov["pinned"] is False
    assert "pinned_version" not in prov and "resolved_version" not in prov


def test_mcp_inventory_rows_label_floating_versions(tmp_path, monkeypatch):
    from agent_bom.mcp_tools.runtime import inventory_impl

    monkeypatch.setenv("AGENT_BOM_MCP_WORKSPACE_ROOTS", str(tmp_path))
    (tmp_path / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "floating": {"command": "uvx", "args": ["mcp-server-floating-example"]},
                    "pinned": {"command": "uvx", "args": ["mcp-server-pinned-example==1.4.0"]},
                }
            }
        )
    )
    payload = json.loads(inventory_impl(config_path=str(tmp_path), _truncate_response=lambda s: s))
    rows = {p["name"]: p for a in payload["agents"] for s in a["servers"] for p in s["packages"]}
    floating, pinned = rows["mcp-server-floating-example"], rows["mcp-server-pinned-example"]
    assert floating["pinned"] is False and floating["pinned_version"] is None
    assert pinned["pinned"] is True and pinned["pinned_version"] == "1.4.0" and pinned["observed_version"] == "1.4.0"
    assert "version" in floating  # existing field kept for compatibility
    entities = {p["name"]: p for p in payload["ai_bom_entities"]["packages"]}
    assert entities["mcp-server-floating-example"]["version_provenance"]["pinned"] is False
    assert entities["mcp-server-pinned-example"]["version_provenance"]["pinned_version"] == "1.4.0"
