"""Operator-declared advisories matched against stored inventory."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer
from agent_bom.oci_parser import scan_oci
from agent_bom.output.json_fmt import to_json
from agent_bom.scanners.operator_advisory import (
    OPERATOR_ADVISORY_PROVENANCE,
    OperatorAdvisory,
    match_advisories_against_reports,
)

FIXTURES = Path(__file__).parent / "fixtures" / "php2shell"


def _advisory(**overrides) -> OperatorAdvisory:
    data = json.loads((FIXTURES / "operator-advisory.json").read_text())
    data.update(overrides)
    return OperatorAdvisory.model_validate(data)


def _image_tar(tmp_path: Path, php_version: str) -> Path:
    config = json.loads((FIXTURES / "image-config.json").read_text())
    config["config"]["Env"] = [
        env if not env.startswith("PHP_VERSION=") else f"PHP_VERSION={php_version}" for env in config["config"]["Env"]
    ]
    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w:") as tf:
        info = tarfile.TarInfo("usr/local/bin/php")
        info.size = 4
        tf.addfile(info, io.BytesIO(b"\x7fELF"))
    out = tmp_path / f"php-{php_version}.tar"
    with tarfile.open(out, mode="w:") as outer:
        for name, payload in (
            ("layer0/layer.tar", layer.getvalue()),
            ("config.json", json.dumps(config).encode()),
            ("manifest.json", json.dumps([{"Config": "config.json", "RepoTags": ["php:8.3"], "Layers": ["layer0/layer.tar"]}]).encode()),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            outer.addfile(info, io.BytesIO(payload))
    return out


def _stored_report(tmp_path: Path, php_version: str) -> dict:
    packages, _strategy = scan_oci(_image_tar(tmp_path, php_version))
    server = MCPServer(name="php:8.3", command="docker", packages=packages)
    report = AIBOMReport(agents=[Agent(name="image:php:8.3", agent_type=AgentType.CUSTOM, config_path="php:8.3", mcp_servers=[server])])
    return to_json(report)


def test_php2shell_end_to_end_vulnerable_runtime_is_flagged(tmp_path: Path) -> None:
    result = match_advisories_against_reports([_advisory()], [_stored_report(tmp_path, "8.3.30")])
    (finding,) = result.findings
    assert finding["advisory_id"] == "CVE-2026-109618"
    assert finding["aliases"] == ["CVE-2026-109619"]
    assert finding["provenance"] == OPERATOR_ADVISORY_PROVENANCE
    assert finding["severity"] == "critical"
    assert finding["fixed_version"] == "8.3.36"
    assert finding["package"]["name"] == "php"
    assert finding["package"]["version"] == "8.3.30"
    assert finding["package"]["cpe"] == "cpe:2.3:a:php:php:8.3.30:*:*:*:*:*:*:*"
    assert finding["asset"] == {"agent": "image:php:8.3", "server": "php:8.3"}
    assert result.complete is True


def test_php2shell_end_to_end_fixed_runtime_is_clean(tmp_path: Path) -> None:
    result = match_advisories_against_reports([_advisory()], [_stored_report(tmp_path, "8.3.36")])
    assert result.findings == []
    assert result.indeterminate == []
    assert result.complete is True


@pytest.mark.parametrize(
    ("version", "fixed"),
    [("8.5.11", "8.5.12"), ("8.4.0", "8.4.27"), ("8.2.34", "8.2.35"), ("8.5.12", None), ("8.1.30", None), ("8.4.27", None)],
)
def test_each_release_branch_has_its_own_fixed_version(version: str, fixed: str | None) -> None:
    report = {
        "agents": [{"name": "a", "mcp_servers": [{"name": "s", "packages": [{"name": "php", "version": version, "ecosystem": "generic"}]}]}]
    }
    findings = match_advisories_against_reports([_advisory()], [report]).findings
    assert [f["fixed_version"] for f in findings] == ([fixed] if fixed else [])


def test_cpe_product_matches_even_when_name_differs() -> None:
    package = {"name": "php-runtime", "version": "8.3.1", "ecosystem": "generic", "cpe": "cpe:2.3:a:php:php:8.3.1:*:*:*:*:*:*:*"}
    report = {"agents": [{"name": "a", "mcp_servers": [{"name": "s", "packages": [package]}]}]}
    assert len(match_advisories_against_reports([_advisory()], [report]).findings) == 1


def test_same_name_in_other_ecosystem_does_not_match() -> None:
    package = {"name": "php", "version": "8.3.1", "ecosystem": "npm"}
    report = {"agents": [{"name": "a", "mcp_servers": [{"name": "s", "packages": [package]}]}]}
    assert match_advisories_against_reports([_advisory()], [report]).findings == []


def test_feed_record_wins_and_operator_record_becomes_alias() -> None:
    package = {
        "name": "php",
        "version": "8.3.30",
        "ecosystem": "generic",
        "vulnerabilities": [{"id": "CVE-2026-109619", "aliases": [], "advisory_sources": ["nvd"]}],
    }
    report = {"agents": [{"name": "a", "mcp_servers": [{"name": "s", "packages": [package]}]}]}
    result = match_advisories_against_reports([_advisory()], [report])
    assert result.findings == []
    assert result.superseded == [{"advisory_id": "CVE-2026-109618", "feed_id": "CVE-2026-109619", "package": "php@8.3.30"}]


def test_incomparable_version_is_indeterminate_not_clean() -> None:
    package = {"name": "php", "version": "8.3.x-dev", "ecosystem": "generic"}
    report = {"agents": [{"name": "a", "mcp_servers": [{"name": "s", "packages": [package]}]}]}
    result = match_advisories_against_reports([_advisory()], [report])
    assert result.findings == []
    assert result.indeterminate == [{"advisory_id": "CVE-2026-109618", "package": "php@8.3.x-dev", "reason": "version_incomparable"}]
    assert result.complete is False


def test_no_stored_inventory_is_incomplete_not_clean() -> None:
    result = match_advisories_against_reports([_advisory()], [])
    assert result.findings == []
    assert result.complete is False


@pytest.mark.parametrize(
    "overrides",
    [
        {"id": "not an id"},
        {"severity": "apocalyptic"},
        {"affected": []},
        {"affected": [{"name": "php", "ranges": [{"fixed": "8.3.36"}]}]},
        {"affected": [{"ecosystem": "generic", "name": "php", "ranges": []}]},
        {"affected": [{"cpe_product": "php", "ranges": [{"fixed": "1"}]}]},
        {"affected": [{"ecosystem": "generic", "name": "php", "ranges": [{"introduced": "8.4", "fixed": "8.3"}]}]},
        {"unexpected": True},
    ],
)
def test_invalid_advisories_are_rejected(overrides: dict) -> None:
    with pytest.raises(ValidationError):
        _advisory(**overrides)
