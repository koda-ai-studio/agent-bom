"""The plugin READMEs disclose every outbound host the code can reach."""

from __future__ import annotations

import json
import re
import socket
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_bom.core.egress_hosts import CONDITIONAL_HOSTS, DECLARED_HOSTS, LOOKUP_HOSTS, USER_NAMED_TARGETS

ROOT = Path(__file__).resolve().parents[1]
READMES = (
    ROOT / "integrations" / "claude-code" / "README.md",
    ROOT / "integrations" / "codex" / "README.md",
)
# Modules on the scan, check, remediate and SBOM paths the plugin skills run.
SCAN_PATH_MODULES = (
    "enrichment.py",
    "scorecard.py",
    "deps_dev.py",
    "resolver.py",
    "transitive.py",
    "parsers/go_resolution.py",
    "mcp_tools/check_lookup.py",
    "scanners/ghsa_advisory.py",
    "scanners/osv_details.py",
    "cli/_common.py",
)
# Literals in those modules that are documentation links, never requested.
DOC_LINK_HOSTS = {"scorecard.dev", "docs.deps.dev"}
_HOST_LITERAL = re.compile(r"https://([a-zA-Z0-9.-]+\.[a-z]{2,})")


@pytest.mark.parametrize("readme", READMES, ids=lambda p: p.parent.name)
def test_readme_discloses_every_declared_host(readme: Path) -> None:
    text = readme.read_text(encoding="utf-8")
    missing = sorted(host for host in DECLARED_HOSTS if f"`{host}`" not in text)
    assert not missing, f"{readme.relative_to(ROOT)} omits outbound hosts {missing}"
    assert USER_NAMED_TARGETS in text


@pytest.mark.parametrize("readme", READMES, ids=lambda p: p.parent.name)
def test_readme_lists_no_undeclared_host(readme: Path) -> None:
    text = readme.read_text(encoding="utf-8")
    section = text.split("**Sends**", 1)[1].split("\n- **", 1)[0]
    listed = set(re.findall(r"`([a-z0-9-]+(?:\.[a-z0-9-]+)+)`", section))
    listed = {host for host in listed if not host.endswith((".json", ".toml", ".md", ".lock"))}
    assert listed <= DECLARED_HOSTS, sorted(listed - DECLARED_HOSTS)


def test_lookup_and_conditional_hosts_do_not_overlap() -> None:
    assert not set(LOOKUP_HOSTS) & set(CONDITIONAL_HOSTS)


@pytest.mark.parametrize("module", SCAN_PATH_MODULES)
def test_scan_path_module_calls_only_declared_hosts(module: str) -> None:
    source = (ROOT / "src" / "agent_bom" / module).read_text(encoding="utf-8")
    hosts = set(_HOST_LITERAL.findall(source)) - DOC_LINK_HOSTS
    assert hosts <= DECLARED_HOSTS, f"{module} reaches undeclared hosts {sorted(hosts - DECLARED_HOSTS)}"


def test_mcp_inventory_makes_no_network_call(tmp_path, monkeypatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".claude.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fetch": {"command": "uvx", "args": ["mcp-server-fetch"]},
                    "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("UV_CACHE_DIR", str(tmp_path / "uv-cache"))
    lookups: list[str] = []

    def _no_network(host, *args, **kwargs):
        lookups.append(str(host))
        raise socket.gaierror("network disabled in test")

    monkeypatch.setattr(socket, "getaddrinfo", _no_network)

    from agent_bom.cli import main

    result = CliRunner().invoke(main, ["mcp", "inventory", "-q", "-f", "json"])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    names = {pkg["name"] for agent in data["agents"] for server in agent["mcp_servers"] for pkg in server["packages"]}
    assert {"mcp-server-fetch", "@modelcontextprotocol/server-github"} <= names
    assert lookups == []
