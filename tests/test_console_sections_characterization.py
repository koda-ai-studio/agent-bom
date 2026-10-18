"""Pin console sections before decomposing the renderer.

Regenerate deliberately, in a single process, with::

    AGENT_BOM_UPDATE_CONSOLE_GOLDENS=1 pytest tests/test_console_sections_characterization.py

Hashes cover exact terminal bytes, including wrapping and ANSI styles. Fixed
inputs keep timestamps, risk scores, and release versions out of the comparison.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console

import agent_bom.output as output
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output import console_render

GOLDEN = Path(__file__).parent / "fixtures" / "output" / "console-sections.json"
SECTIONS = ("print_summary", "print_posture_summary", "print_scan_performance_summary", "print_threat_frameworks", "print_remediation_plan")


def _report(populated: bool) -> AIBOMReport:
    report = AIBOMReport(generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc), tool_version="0.0.0-test")
    if not populated:
        return report
    server = MCPServer(
        name="tools", command="npx", env={"API_TOKEN": "${API_TOKEN}"}, packages=[Package(name="demo", version="1.0.0", ecosystem="npm")]
    )
    report.agents = [Agent(name="assistant", agent_type=AgentType.CUSTOM, config_path="/tmp/console-test.json", mcp_servers=[server])]
    for index, (name, severity, fixed, malicious) in enumerate(
        [
            ("demo", "critical", "2.0.0", False),
            ("demo", "high", "3.0.0", False),
            ("unfixed", "medium", None, False),
            ("preview", "low", "2.0.0rc1", False),
            ("bad-package", "critical", "2.0.0", True),
        ]
    ):
        report.findings.append(
            Finding(
                id=f"finding-{index}",
                finding_type=FindingType.CVE,
                source=FindingSource.SBOM,
                asset=Asset(name=name, asset_type="package"),
                severity=severity,
                title=f"CVE-2026-{index:04} in {name}",
                cve_id=f"CVE-2026-{index:04}",
                fixed_version=fixed,
                is_kev=index == 0,
                risk_score=8.0 - index,
                ai_risk_context="tool access" if index == 0 else None,
                affected_agents=["assistant"],
                affected_servers=["tools"],
                exposed_credentials=["API_TOKEN"],
                exposed_tools=["read_file"],
                evidence={
                    "package_name": name,
                    "package_version": "1.0.0",
                    "ecosystem": "pypi",
                    "package_is_malicious": malicious,
                    "references": ["https://example.org/advisory"],
                },
                owasp_tags=["LLM01"],
                atlas_tags=["AML.T0051"],
                attack_tags=["T1190", "unknown-technique"],
                nist_ai_rmf_tags=["GOVERN-1.1"],
                owasp_mcp_tags=["MCP01"],
                owasp_agentic_tags=["ASI01"],
                eu_ai_act_tags=["ART-9"],
                nist_csf_tags=["ID.AM"],
                iso_27001_tags=["A.5.1"],
                soc2_tags=["CC1.1"],
                cis_tags=["1.1"],
            )
        )
    report.ai_inventory_data = {
        "total_components": 3,
        "shadow_ai_count": 1,
        "deprecated_models_count": 1,
        "api_keys_count": 1,
        "unique_sdks": ["openai"],
        "unique_models": ["model"],
        "files_scanned": 2,
    }
    report.project_inventory_data = {
        "manifest_files": 2,
        "lockfiles": 1,
        "package_count": 3,
        "direct_packages": 1,
        "transitive_packages": 2,
        "lockfile_backed_packages": 2,
        "declaration_only_packages": 1,
        "advisory_depth_pct": 67,
    }
    report.repo_trust_data = {
        "status": "ok",
        "full_name": "example/repo",
        "stars": 5,
        "contributors": 2,
        "license": "MIT",
        "language": "Python",
        "pushed_at": "2026-01-01",
    }
    report.model_supply_chain_data = {
        "model_files": 1,
        "manifest_files": 1,
        "provenance_checks": 1,
        "signed_files": 1,
        "hash_verification": {"verified": 1, "tampered": 0},
        "manifests_with_repo_id": 1,
        "files_with_security_flags": 1,
    }
    report.scan_performance_data = {
        "osv": {"cache_hits": 3, "cache_misses": 1, "cache_hit_rate_pct": 75, "packages_queried": 4, "lookup_errors": 1},
        "registry": {
            "cache_hits": 1,
            "cache_misses": 1,
            "cache_hit_rate_pct": 50,
            "network_requests": 1,
            "npm_rate_limit_short_circuits": 1,
        },
        "advisory_coverage": {
            "primary_sources": {"osv": 4},
            "enrichment_sources": {"kev": 1},
            "records_with_enrichment": 1,
            "records_with_multiple_sources": 1,
        },
    }
    report.coverage_warnings = [
        {"reason": "manifest_parse_error", "release": "fixture", "detail": "invalid manifest"},
        {"release": "old-release", "package_count": 2, "advisory_rows": 0},
    ]
    return report


def _assert_golden(key: str, value: str) -> None:
    digest = hashlib.sha256(value.encode()).hexdigest()
    expected = json.loads(GOLDEN.read_text()) if GOLDEN.exists() else {}
    if os.environ.get("AGENT_BOM_UPDATE_CONSOLE_GOLDENS") == "1":
        expected[key] = digest
        GOLDEN.write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n")
    assert expected.get(key) == digest, f"Console bytes changed: {key}\n{value}"


@pytest.mark.parametrize("populated", [False, True], ids=["empty", "populated"])
@pytest.mark.parametrize("color", [False, True], ids=["plain", "ansi"])
@pytest.mark.parametrize("no_color_env", [False, True], ids=["color-env", "no-color-env"])
@pytest.mark.parametrize("terminal", ["dumb", "xterm-256color"])
@pytest.mark.parametrize("section", SECTIONS)
def test_console_section_bytes(monkeypatch, populated, color, no_color_env, terminal, section):
    monkeypatch.setenv("TERM", terminal)
    if no_color_env:
        monkeypatch.setenv("NO_COLOR", "1")
    else:
        monkeypatch.delenv("NO_COLOR", raising=False)
    stream = StringIO()
    monkeypatch.setattr(
        output,
        "console",
        Console(
            file=stream,
            width=100,
            height=25,
            force_terminal=color,
            force_jupyter=False,
            force_interactive=False,
            legacy_windows=False,
            no_color=not color,
            color_system="standard" if color else None,
        ),
    )
    getattr(console_render, section)(_report(populated))
    _assert_golden(f"{section}:{populated}:{color}", stream.getvalue())


def test_remediation_plan_bytes():
    plan = console_render.build_remediation_plan(_report(True).findings)
    _assert_golden("remediation-plan", json.dumps(plan, sort_keys=True))
