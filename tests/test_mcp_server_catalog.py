"""The public MCP server risk catalog is generated from the bundled registry and stays current."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.render_mcp_server_catalog import OUTPUT, REGISTRY, RISK_ORDER, main, render

ROOT = Path(__file__).resolve().parents[1]


def test_committed_catalog_matches_the_registry() -> None:
    assert main(["--check"]) == 0, "run python scripts/render_mcp_server_catalog.py"


def test_catalog_lists_every_reviewed_server_once_and_counts_the_rest() -> None:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    reviewed = [
        server
        for server in registry["servers"].values()
        if server.get("risk_level") in RISK_ORDER and str(server.get("risk_justification") or "").strip()
    ]
    page = render(registry)
    assert page.count("\n### ") == len(reviewed)
    assert f"**{len(reviewed)} MCP servers**" in page
    assert f"**{len(registry['servers']) - len(reviewed)} servers**" in page
    for risk in RISK_ORDER:
        count = sum(1 for server in reviewed if server["risk_level"] == risk)
        assert f"({count})" in page


def test_catalog_is_published_in_the_docs_navigation() -> None:
    assert OUTPUT == ROOT / "site-docs" / "mcp-servers" / "index.md"
    assert "mcp-servers/index.md" in (ROOT / "mkdocs.yml").read_text(encoding="utf-8")
