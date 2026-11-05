#!/usr/bin/env python3
"""Regenerate plugin evaluation tool schemas from their startup profiles."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
    from agent_bom.mcp_server import create_mcp_server

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for server, profile in (("agent-bom", "scan"), ("agent-bom-audit", "audit")):
        tools = asyncio.run(create_mcp_server(profile=profile).list_tools())
        text = json.dumps({"tools": [tool.model_dump(by_alias=True, exclude_none=True) for tool in tools]}, indent=2) + "\n"
        path = ROOT / "integrations/claude-code/evals/mocks" / server / "_tools.json"
        if args.check:
            if path.read_text(encoding="utf-8") != text:
                print(f"Stale plugin tool catalog: {path.relative_to(ROOT)}")
                return 1
        else:
            path.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
