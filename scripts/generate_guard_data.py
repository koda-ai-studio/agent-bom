#!/usr/bin/env python3
"""Regenerate the offline reference data bundled with the agent-bom-guard plugin.

The guard hook runs on the user's system ``python3`` without agent-bom installed,
so it reads a JSON snapshot of agent-bom's own typosquat reference
(``agent_bom.malicious``) and confirmed-malicious entries from the bundled MCP
blocklist. ``--check`` fails when the snapshot has drifted from those sources.

Usage::

    python scripts/generate_guard_data.py          # rewrite the snapshot
    python scripts/generate_guard_data.py --check  # exit 1 on drift
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_bom import malicious  # noqa: E402

TARGET = ROOT / "integrations" / "agent-bom-guard" / "hooks" / "guard_data.json"
BLOCKLIST = Path(malicious.__file__).parent / "data" / "mcp-blocklist.json"


def _known_malicious() -> list[list[str]]:
    entries = json.loads(BLOCKLIST.read_text(encoding="utf-8"))["entries"]
    return sorted(
        [entry["ecosystem"], entry["package"], entry.get("affected_versions") or "*", entry["id"]]
        for entry in entries
        if entry.get("package") and entry.get("confidence") == "confirmed_malicious"
    )


def build() -> dict[str, object]:
    return {
        "source": "agent_bom.malicious and agent_bom/data/mcp-blocklist.json; regenerate with scripts/generate_guard_data.py",
        "popular": {eco: sorted(names) for eco, names in sorted(malicious._POPULAR_PACKAGES.items())},
        "known_legitimate": {eco: sorted(names) for eco, names in sorted(malicious._KNOWN_LEGITIMATE.items())},
        "safe_npm_scopes": sorted(malicious._SAFE_NPM_SCOPES),
        "known_malicious": _known_malicious(),
    }


def render() -> str:
    return json.dumps(build(), indent=1, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail when the bundled snapshot is stale")
    args = parser.parse_args(argv)
    expected = render()
    if args.check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != expected:
            print(f"{TARGET.relative_to(ROOT)} is stale; run python scripts/generate_guard_data.py")
            return 1
        print("guard data matches agent-bom sources")
        return 0
    TARGET.write_text(expected, encoding="utf-8")
    print(f"wrote {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
