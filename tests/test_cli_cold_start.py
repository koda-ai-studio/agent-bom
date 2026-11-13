"""CLI cold-start guards: `--version` and the command tree stay light to import."""

from __future__ import annotations

import json
import os
import subprocess
import sys

from click.testing import CliRunner


def _run(code: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", code, *args],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "AGENT_BOM_SKIP_UPDATE_CHECK": "1"},
    )


def test_version_fast_path_skips_command_tree_and_matches_full_cli_output():
    fast = _run(
        "import sys; sys.argv[0] = 'agent-bom'\n"
        "from agent_bom.__main__ import cli_main\n"
        "try:\n    cli_main()\n"
        "finally:\n    sys.stderr.write('LOADED=' + str('agent_bom.cli' in sys.modules))\n",
        "--version",
    )
    from agent_bom.cli import main

    full = CliRunner().invoke(main, ["--version"])

    assert fast.returncode == 0, fast.stderr
    assert fast.stderr.endswith("LOADED=False")
    assert full.exit_code == 0
    assert fast.stdout == full.output
    assert fast.stdout.startswith("agent-bom ")


def test_entrypoint_delegates_everything_else_to_full_cli():
    result = _run(
        "import sys; sys.argv[0] = 'agent-bom'\nfrom agent_bom.__main__ import cli_main\ncli_main()\n",
        "--help",
    )

    assert result.returncode == 0, result.stderr
    assert "Usage:" in result.stdout


def test_console_script_targets_fast_entrypoint():
    import tomllib
    from pathlib import Path

    pyproject = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())

    assert pyproject["project"]["scripts"]["agent-bom"] == "agent_bom.__main__:cli_main"


def test_importing_cli_does_not_load_network_api_or_graph_stacks():
    heavy = ["agent_bom.api.fleet_store", "agent_bom.api.mcp_observation_store", "agent_bom.graph", "agent_bom.proxy_audit"]
    result = _run(
        f"import json, sys\nimport agent_bom.cli\nprint(json.dumps([m for m in {heavy!r} if m in sys.modules]))\n",
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == []


_MATCHING_STACK = [
    "agent_bom.scanners.package_scan",
    "agent_bom.scanners.distro_cpe_scan",
    "agent_bom.scanners.local_advisories",
    "agent_bom.scanners.nodejs_advisory",
    "agent_bom.scanners.cpython_advisory",
]


def test_importing_cli_does_not_load_the_vulnerability_matching_stack():
    result = _run(
        f"import json, sys\nimport agent_bom.cli\nprint(json.dumps([m for m in {_MATCHING_STACK!r} if m in sys.modules]))\n",
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == []


def test_help_does_not_load_the_vulnerability_matching_stack():
    result = _run(
        "import json, sys; sys.argv[0] = 'agent-bom'\n"
        "from agent_bom.__main__ import cli_main\n"
        "try:\n    cli_main()\nexcept SystemExit:\n    pass\n"
        f"sys.stderr.write('LOADED=' + json.dumps([m for m in {_MATCHING_STACK!r} if m in sys.modules]))\n",
        "--help",
    )

    assert result.returncode == 0, result.stderr
    assert "Usage:" in result.stdout
    assert result.stderr.endswith("LOADED=[]")


def test_scanners_package_resolves_reexports_lazily_and_keeps_patch_sync():
    result = _run(
        "import json, sys\n"
        "import agent_bom.scanners as scanners\n"
        "before = 'agent_bom.scanners.package_scan' in sys.modules\n"
        "fn = scanners.scan_agents_sync\n"
        "from agent_bom.scanners import package_scan\n"
        "same = fn is package_scan.scan_agents_sync\n"
        "sentinel = object()\n"
        "scanners.query_osv_batch = sentinel\n"
        "synced = package_scan.query_osv_batch is sentinel\n"
        "print(json.dumps([before, same, synced, sorted(set(scanners.__all__) - set(dir(scanners)))]))\n",
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [False, True, True, []]


def test_patching_a_lazy_scanners_reexport_restores_the_implementation_module():
    result = _run(
        "import json\n"
        "from unittest.mock import patch\n"
        "import agent_bom.scanners as scanners\n"
        "from agent_bom.scanners import package_scan\n"
        "original = package_scan.query_osv_batch\n"
        "with patch('agent_bom.scanners.query_osv_batch') as fake:\n"
        "    during = package_scan.query_osv_batch is fake\n"
        "after = [package_scan.query_osv_batch is original, scanners.query_osv_batch is original]\n"
        "print(json.dumps([during, *after]))\n",
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [True, True, True]


def test_bundled_mitre_catalog_does_not_import_httpx():
    result = _run(
        "import sys\nfrom agent_bom.mitre_fetch import get_bundled_techniques\nget_bundled_techniques()\nprint('httpx' in sys.modules)\n"
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "False"
