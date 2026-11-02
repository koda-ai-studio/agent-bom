"""The generated vendor-coverage matrix stays in sync with code and cites a source per cell."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC_JSON = ROOT / "docs" / "VENDOR_COVERAGE.json"


def test_committed_vendor_coverage_matches_generator() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/generate_vendor_coverage.py", "--check"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr


def test_every_cloud_matrix_cell_cites_a_source() -> None:
    data = json.loads(DOC_JSON.read_text(encoding="utf-8"))
    matrix = data["cloud_matrix"]
    lane_ids = {lane["id"] for lane in matrix["lanes"]}

    assert matrix["rows"], "matrix must list providers"
    for row in matrix["rows"]:
        assert set(row["cells"]) == lane_ids, row["provider"]
        for lane_id, cell in row["cells"].items():
            assert cell["source"]["path"], (row["provider"], lane_id)
            assert cell["source"]["symbol"], (row["provider"], lane_id)
            assert cell["display"], (row["provider"], lane_id)

    gaps = sum(1 for row in matrix["rows"] for cell in row["cells"].values() if cell["display"] == "—")
    assert gaps == matrix["gap_count"]


def test_every_integration_category_cites_a_source() -> None:
    data = json.loads(DOC_JSON.read_text(encoding="utf-8"))

    assert data["integrations"]
    for category in data["integrations"]:
        assert category["sources"], category["id"]
        for source in category["sources"]:
            assert source["path"] and source["symbol"], category["id"]
    for group in data["disagreements"]:
        assert group["providers_not_in_every_list"], group["id"]
        assert all(entry["source"]["path"] for entry in group["lists"]), group["id"]


def _generator():
    import importlib.util

    spec = importlib.util.spec_from_file_location("vendor_coverage_generator", ROOT / "scripts/generate_vendor_coverage.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_platform_collectors_are_visible_without_claiming_hosted_connections() -> None:
    generator = _generator()
    rows = {row["provider"]: row["cells"] for row in generator.build_cloud_matrix()["rows"]}
    for provider in ("supabase", "vercel"):
        assert provider in rows
        cell = rows[provider]["platform_inventory_cli"]
        assert cell["value"] is True
        assert f"cli/_{provider}_inventory.py" in cell["source"]["path"]
        for lane in ("connect", "api_connection", "scheduled", "ai_discovery", "deep_inventory"):
            assert rows[provider][lane]["value"] is False, (provider, lane)


def test_unregistered_platform_collector_is_not_declared(monkeypatch) -> None:
    import ast

    generator = _generator()
    original = generator._module
    path = "src/agent_bom/cli/_cloud_group.py"
    tree = ast.parse((ROOT / path).read_text().replace('cloud_group.add_command(vercel_cmd, "vercel")', ""))
    monkeypatch.setattr(generator, "_module", lambda source: tree if source == path else original(source))
    providers = {row["provider"] for row in generator.build_cloud_matrix()["rows"]}
    assert "supabase" in providers
    assert "vercel" not in providers


def test_capability_matrix_rows_cite_sources_and_name_the_dast_gap() -> None:
    data = json.loads(DOC_JSON.read_text(encoding="utf-8"))
    rows = {row["id"]: row for row in data["capabilities"]}

    assert {
        "sca",
        "secrets",
        "sast_native",
        "sast_import",
        "iac",
        "mcp_audit",
        "image_cve",
        "cloud_posture_live",
        "cloud_posture_static",
        "dast_http",
    } <= set(rows)
    for row in rows.values():
        assert row["sources"] and all(s["path"] and s["symbol"] for s in row["sources"]), row["id"]
        assert row["status"] in {"provided", "not provided"}, row["id"]
        assert row["detail"], row["id"]
    assert rows["dast_http"]["status"] == "not provided"
    assert rows["dast_http"]["values"] == []


def test_terraform_provider_counts_match_the_rule_registry() -> None:
    import re

    from agent_bom.iac import terraform_security as tf

    counts = {"aws": set(), "azure": set(), "gcp": set()}
    for scope, check in tf._RULES:
        rule_ids = {f"TF-SEC-{n}" for n in re.findall(r"\d{3}", check.__name__)}  # tf_sec_001_002 -> two ids
        assert rule_ids, check.__name__
        for rtype in scope or ("aws_", "azurerm_", "google_"):
            provider = "azure" if rtype.startswith("azurerm_") else "gcp" if rtype.startswith("google_") else "aws"
            counts[provider] |= rule_ids
    data = json.loads(DOC_JSON.read_text(encoding="utf-8"))
    iac = next(row for row in data["capabilities"] if row["id"] == "iac")

    generated = iac["values"]["terraform"]
    assert generated["azure"] == len(counts["azure"] - counts["aws"])
    assert generated["gcp"] == len(counts["gcp"] - counts["aws"])
    assert generated["aws"] == len(counts["aws"])
    assert generated["aws"] + generated["azure"] + generated["gcp"] == len(
        {rid for ids in iac["values"]["terraform_rule_ids"].values() for rid in ids}
    )
