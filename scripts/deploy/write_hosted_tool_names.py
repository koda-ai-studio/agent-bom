#!/usr/bin/env python3
"""Write the default-profile MCP tool names a hosted server registers, per auth mode.

Run from a trusted release checkout with ``PYTHONPATH=src``. The names come from
``registered_tool_names``, the function the server's own registration filter uses,
so an OAuth deployment's read-only subset is never a separately maintained list.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent_bom.mcp_tools.profiles import DEFAULT_PROFILE, registered_tool_names


def hosted_tool_names(*, read_only: bool) -> list[str]:
    names = registered_tool_names(DEFAULT_PROFILE, read_only=read_only)
    if not names:
        raise SystemExit(f"default MCP profile {DEFAULT_PROFILE!r} does not register a bounded, non-empty tool set")
    return sorted(names)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--full", type=Path, required=True, help="Output: names registered with static bearer authentication.")
    parser.add_argument("--read-only", type=Path, required=True, help="Output: names registered with OAuth (read-only catalog).")
    args = parser.parse_args(argv)
    full, read_only = hosted_tool_names(read_only=False), hosted_tool_names(read_only=True)
    if not set(read_only) <= set(full):
        raise SystemExit("read-only hosted tools must be a subset of the default profile")
    args.full.write_text(json.dumps(full, indent=2) + "\n", encoding="utf-8")
    args.read_only.write_text(json.dumps(read_only, indent=2) + "\n", encoding="utf-8")
    print(f"Default profile {DEFAULT_PROFILE!r}: {len(full)} tools; OAuth read-only: {len(read_only)} tools")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
