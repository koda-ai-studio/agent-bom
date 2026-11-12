#!/usr/bin/env python3
"""Export MCP schemas from an isolated, exact published release installation.

The hosted origin may run newer code while retaining a release version string.
It must not define the expected marketplace contract. Child processes receive
no publishing credentials, user pip configuration, or checkout import path.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

EXTRACT = """
import asyncio, inspect, json, sys
from importlib.metadata import version
from agent_bom import __version__
expected, mode = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else 'default'
if version('agent-bom') != expected or __version__ != expected:
    raise SystemExit('Installed release version mismatch')
if mode == 'oauth':
    # An OAuth deployment registers through the release's own read-only filter.
    # Force that filter here instead of configuring a real identity provider.
    from agent_bom.mcp_tools import profiles
    original = profiles.configure_registration
    if 'read_only' not in inspect.signature(original).parameters:
        raise SystemExit('Release has no OAuth read-only registration filter')
    profiles.configure_registration = lambda mcp, name, *, read_only=False: original(mcp, name, read_only=True)
elif mode != 'default':
    raise SystemExit('Unknown extraction mode')
from agent_bom.mcp_server import create_mcp_server
tools = asyncio.run(create_mcp_server(profile='scan').list_tools())
# The wire alias is stable across MCP SDK 1.x and 2.x Python field names.
dumped = [t.model_dump(by_alias=True) for t in tools]
if mode == 'oauth':
    writable = sorted(t['name'] for t in dumped if (t.get('annotations') or {}).get('readOnlyHint') is not True)
    if writable:
        raise SystemExit('OAuth catalog registers non-read-only tools: ' + ', '.join(writable))
contract = [{'name': t['name'], 'inputSchema': t['inputSchema']} for t in dumped]
print(json.dumps(sorted(contract, key=lambda t: t['name'])))
"""


def _validated_contract(stdout: str) -> list[dict]:
    contract = json.loads(stdout)
    if not isinstance(contract, list) or any(
        not isinstance(tool, dict) or not isinstance(tool.get("inputSchema"), dict) for tool in contract
    ):
        raise ValueError("Published release returned malformed tool schemas")
    return contract


def _export(expected: str, names: list[str], modes: tuple[str, ...]) -> dict[str, list[dict]]:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected):
        raise ValueError("Expected release must be a stable version")
    if not names or any(not isinstance(name, str) or not name for name in names) or len(names) != len(set(names)):
        raise ValueError("Expected release tool names must be unique non-empty strings")
    with tempfile.TemporaryDirectory(prefix="agent-bom-release-contract-") as directory:
        root = Path(directory)
        env = {"PATH": os.defpath, "HOME": str(root), "LANG": "C.UTF-8"}
        if "SYSTEMROOT" in os.environ:
            env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]

        def run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
            return subprocess.run(command, cwd=root, env=env, text=True, capture_output=True, check=True, timeout=timeout)

        run([sys.executable, "-I", "-m", "venv", str(root / "venv")], 60)
        python = str(root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
        run(
            [
                python,
                "-I",
                "-m",
                "pip",
                "--isolated",
                "--disable-pip-version-check",
                "install",
                "--index-url",
                "https://pypi.org/simple",
                "--only-binary=:all:",
                f"agent-bom=={expected}",
            ],
            300,
        )
        contracts = {mode: _validated_contract(run([python, "-I", "-c", EXTRACT, expected, mode], 60).stdout) for mode in modes}
    if [tool.get("name") for tool in contracts["default"]] != sorted(names):
        raise ValueError("Published release tools differ from immutable release metadata")
    read_only = contracts.get("oauth")
    if read_only is not None:
        read_only_names = [tool.get("name") for tool in read_only]
        if not read_only_names or not set(read_only_names) <= set(names):
            raise ValueError("Published release OAuth tools are not a non-empty subset of immutable release metadata")
    return contracts


def export_contract(expected: str, names: list[str]) -> list[dict]:
    return _export(expected, names, ("default",))["default"]


def export_contracts(expected: str, names: list[str]) -> tuple[list[dict], list[dict]]:
    """Default-profile schemas and the read-only subset an OAuth deployment registers."""
    contracts = _export(expected, names, ("default", "oauth"))
    return contracts["default"], contracts["oauth"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--expected-tool-names-file", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--read-only-out", type=Path, default=None, help="Also write the OAuth read-only contract here.")
    parser.add_argument("--read-only-names-out", type=Path, default=None, help="Also write the OAuth read-only tool names here.")
    args = parser.parse_args()
    if (args.read_only_out is None) != (args.read_only_names_out is None):
        parser.error("--read-only-out and --read-only-names-out must be supplied together")
    try:
        names = json.loads(args.expected_tool_names_file.read_text())
        if not isinstance(names, list):
            raise ValueError("Expected tool names must be a list")
        if args.read_only_out is None:
            contract, read_only = export_contract(args.expected, names), None
        else:
            contract, read_only = export_contracts(args.expected, names)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit("Could not export exact published release schemas; no hosted-origin fallback is permitted") from None
    args.out.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n")
    print(f"Exported {len(contract)} MCP tool schemas from published agent-bom=={args.expected}")
    if read_only is not None:
        args.read_only_out.write_text(json.dumps(read_only, indent=2, sort_keys=True) + "\n")
        args.read_only_names_out.write_text(json.dumps([tool["name"] for tool in read_only], indent=2) + "\n")
        print(f"Exported {len(read_only)} OAuth read-only MCP tool schemas")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
