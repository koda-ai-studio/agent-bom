"""The banner and integration tables name only what the code implements."""

from __future__ import annotations

import html
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from agent_bom.discovery import CONFIG_LOCATIONS, discover_global_configs
from agent_bom.models import AgentType
from scripts import integrations_manifest as manifest_mod
from scripts.render_social_preview_svg import render as render_social_preview

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = manifest_mod.load()
BANNER = ROOT / "docs" / "images" / "social-preview.svg"
BANNER_SOURCE = ROOT / "docs" / "images" / "social-preview.source.svg"
PROVENANCE = ROOT / "docs" / "images" / "vendor" / "provenance.json"
TEST_TEXTS = [path.read_text(encoding="utf-8", errors="ignore") for path in (ROOT / "tests").rglob("test_*.py")]

# Clients whose config is not the shared JSON ``mcpServers`` shape have their own
# parser tests in tests/test_discovery_new_clients.py.
_CUSTOM_FORMAT_CLIENTS = {AgentType.CODEX_CLI, AgentType.GOOSE, AgentType.SNOWFLAKE_CLI, AgentType.CORTEX_CODE}


def test_every_banner_entry_resolves_to_implementing_code() -> None:
    assert manifest_mod.unresolved_refs(MANIFEST) == []


def test_every_registered_source_is_listed_or_explicitly_hidden() -> None:
    assert manifest_mod.uncovered_sources(MANIFEST) == []


def test_hidden_allowlist_names_only_real_sources() -> None:
    known = {f"{kind}:{value}" for kind, values in manifest_mod.registered_sources().items() for value in values}
    assert sorted(set(MANIFEST.hidden) - known) == []


def test_a_client_without_a_discovery_path_stays_off_the_banner() -> None:
    listed = {ref for item in MANIFEST.integrations() for ref in item.implements}
    assert not manifest_mod.ref_resolves("agent_type:replit-agent")
    assert "agent_type:replit-agent" not in listed


def test_a_newly_registered_provider_must_be_added_to_the_manifest(monkeypatch) -> None:
    from agent_bom import cloud

    monkeypatch.setitem(cloud._BUILTIN_PROVIDERS, "newcloud", "agent_bom.cloud.newcloud")
    manifest_mod.registered_sources.cache_clear()
    try:
        assert manifest_mod.uncovered_sources(MANIFEST) == ["cloud_provider:newcloud"]
    finally:
        monkeypatch.undo()
        manifest_mod.registered_sources.cache_clear()


def test_resolver_rejects_aspirational_entries() -> None:
    for ref in (
        "cloud_provider:oracle",
        "agent_type:not-a-client",
        "connector:salesforce",
        "symbol:agent_bom.cloud.vector_db:discover_everything",
        "symbol:agent_bom.no_such_module:anything",
        "export_kind:splunk",
    ):
        assert not manifest_mod.ref_resolves(ref), ref


def _exercises(test_text: str, ref: str) -> bool:
    module = manifest_mod.implementing_module(ref)
    symbol = ref.rpartition(":")[2] if ref.startswith("symbol:") else None
    if module and module in test_text:
        return True
    return bool(symbol and re.search(rf"\b{re.escape(symbol)}\b", test_text))


def test_every_implementing_module_is_exercised_by_a_test() -> None:
    untested = [
        f"{item.name} ({ref})"
        for item in MANIFEST.integrations()
        for ref in item.implements
        if not any(_exercises(text, ref) for text in TEST_TEXTS)
    ]
    assert untested == []


def _fixture_path(agent_type: AgentType, home: Path) -> Path:
    raw = CONFIG_LOCATIONS[agent_type]["Linux"][0]
    return home / raw.removeprefix("~/").replace("*", "IntelliJIdea2025.1")


@pytest.mark.parametrize(
    "agent_type",
    [agent for agent in CONFIG_LOCATIONS if agent not in _CUSTOM_FORMAT_CLIENTS and CONFIG_LOCATIONS[agent].get("Linux")],
    ids=lambda agent: agent.value,
)
def test_each_listed_mcp_client_is_discovered_from_its_config(agent_type: AgentType, tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr("agent_bom.discovery.get_platform", lambda: "Linux")
    config = _fixture_path(agent_type, tmp_path)
    config.parent.mkdir(parents=True, exist_ok=True)
    server = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", str(tmp_path)]}
    config.write_text(json.dumps({"mcpServers": {"fixture-fs": server}}), encoding="utf-8")

    agents = discover_global_configs([agent_type], quiet=True)

    assert [agent.agent_type for agent in agents] == [agent_type]
    assert [server.name for server in agents[0].mcp_servers] == ["fixture-fs"]


def test_logos_are_provenance_pinned_and_present() -> None:
    pinned = {asset["path"] for asset in json.loads(PROVENANCE.read_text(encoding="utf-8"))["assets"]}
    for item in MANIFEST.integrations():
        if item.logo:
            assert (BANNER.parent / item.logo).is_file(), item.logo
            assert f"docs/images/{item.logo}" in pinned, item.logo


def _banner_text() -> str:
    root = ET.parse(BANNER).getroot()
    return " ".join(" ".join(element.itertext()) for element in root.iter("{http://www.w3.org/2000/svg}text"))


def test_banner_is_rendered_from_the_manifest() -> None:
    assert render_social_preview(BANNER_SOURCE) == BANNER.read_text(encoding="utf-8")


def test_banner_names_every_group_and_logo_and_counts_the_rest() -> None:
    text = _banner_text()
    for group in MANIFEST.groups:
        assert group.title.upper() in text, group.title
        if not group.logos:
            for item in group.integrations:
                assert item.name in text, item.name
            continue
        shown = group.logos[:5]
        for item in shown:
            assert item.name in text, item.name
        rest = len(group.integrations) - len(shown)
        if rest:
            assert f"+{rest} more" in text, group.title
    for item in MANIFEST.evidence_out.integrations:
        assert item.name in text, item.name
    assert "trademarks of their owners" in text


def test_banner_never_names_an_unlisted_integration() -> None:
    listed = {item.name for item in MANIFEST.integrations()}
    tiles = [html.unescape(name) for name in re.findall(r'data-integration="([^"]+)"', BANNER.read_text(encoding="utf-8"))]
    assert tiles and set(tiles) <= listed


def test_doc_surfaces_carry_the_generated_integration_table() -> None:
    assert manifest_mod.stale_doc_surfaces(MANIFEST) == []
    for path in manifest_mod.DOC_SURFACES:
        text = path.read_text(encoding="utf-8")
        for item in MANIFEST.integrations():
            assert item.name in text, (path.name, item.name)
