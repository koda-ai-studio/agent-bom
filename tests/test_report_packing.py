"""Scan report schema 2.0: shared records serialized once, referenced by ID, expanded losslessly."""

from __future__ import annotations

import copy
import json
from datetime import datetime
from pathlib import Path

import pytest

from agent_bom.compliance_utils import apply_effective_blast_radius_tags
from agent_bom.models import (
    Agent,
    AgentStatus,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)
from agent_bom.output.json_fmt import redact_json_payload, to_json
from agent_bom.output.report_packing import (
    REPORT_SCHEMA_V1,
    REPORT_SCHEMA_V2,
    TRANSFORMS,
    ReportPackingError,
    expand_report,
    is_packed,
    pack_report,
)
from agent_bom.scanners.package_scan import apply_framework_tags


def _vuln(vuln_id: str, cwe: str, severity: Severity = Severity.HIGH) -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        severity=severity,
        summary=f"{vuln_id} summary",
        cvss_score=8.1,
        fixed_version="9.9.9",
        cwe_ids=[cwe],
        references=[f"https://example.invalid/{vuln_id}", "https://example.invalid/advisory"],
    )


def _report(shared_vulns: int = 6, other_vulns: int = 4) -> AIBOMReport:
    """Two agents share one vulnerable package through two servers, as a real estate does."""
    shared = Package(name="lodash", version="4.17.20", ecosystem="npm")
    shared.vulnerabilities = [_vuln(f"CVE-2024-{i:04d}", "CWE-79") for i in range(1, shared_vulns + 1)]
    other = Package(name="requests", version="2.19.0", ecosystem="pypi")
    other.vulnerabilities = [_vuln(f"CVE-2023-{i:04d}", "CWE-94", Severity.CRITICAL) for i in range(1, other_vulns + 1)]
    clean = Package(name="six", version="1.16.0", ecosystem="pypi")
    server_a = MCPServer(name="fs", command="npx", args=["fs"], transport=TransportType.STDIO, packages=[shared, other, clean])
    server_b = MCPServer(name="web", command="npx", args=["web"], transport=TransportType.STDIO, packages=[shared])
    agent_a = Agent(name="desk", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/a.json", mcp_servers=[server_a])
    agent_b = Agent(name="code", agent_type=AgentType.CURSOR, config_path="/tmp/b.json", mcp_servers=[server_b])
    agent_a.status = agent_b.status = AgentStatus.CONFIGURED
    blast_radii: list[BlastRadius] = []
    for pkg, servers, agents in ((shared, [server_a, server_b], [agent_a, agent_b]), (other, [server_a], [agent_a])):
        for vuln in pkg.vulnerabilities:
            br = BlastRadius(
                vulnerability=vuln,
                package=pkg,
                affected_servers=servers,
                affected_agents=agents,
                exposed_credentials=[],
                exposed_tools=[],
            )
            br.calculate_risk_score()
            apply_framework_tags(br)
            apply_effective_blast_radius_tags(br)
            blast_radii.append(br)
    return AIBOMReport(
        agents=[agent_a, agent_b],
        blast_radii=blast_radii,
        generated_at=datetime(2026, 1, 1, 12, 0, 0),
        tool_version="0.115.0",
        scan_id="scan-packing-test",
    )


@pytest.fixture(scope="module")
def legacy() -> dict:
    return json.loads(json.dumps(to_json(_report())))


def _size(doc: dict) -> int:
    return len(json.dumps(doc, indent=2))


def test_pack_marks_schema_two_and_expand_restores_the_legacy_document(legacy: dict) -> None:
    packed = pack_report(legacy)

    assert legacy["schema_version"] == REPORT_SCHEMA_V1
    assert packed["schema_version"] == REPORT_SCHEMA_V2
    assert packed["spec_version"] == REPORT_SCHEMA_V2
    assert is_packed(packed) and not is_packed(legacy)
    assert expand_report(packed) == legacy


def test_findings_controls_and_entities_reconstructed_from_v2_equal_v1(legacy: dict) -> None:
    restored = expand_report(json.loads(json.dumps(pack_report(legacy))))

    def finding_set(doc: dict) -> dict[str, dict]:
        return {row["canonical_id"]: row for row in doc["findings"]}

    assert finding_set(restored) == finding_set(legacy)
    for canonical_id, row in finding_set(legacy).items():
        assert finding_set(restored)[canonical_id]["controls"] == row["controls"]
    for section in ("agents", "packages", "ai_bom_entities", "inventory_snapshot", "assets", "blast_radius", "exposure_paths"):
        assert restored[section] == legacy[section], section


def test_each_compliance_control_is_serialized_once_and_referenced_by_id(legacy: dict) -> None:
    packed = pack_report(legacy)
    controls = packed["compliance_controls"]
    distinct = {json.dumps(control, sort_keys=True) for row in legacy["findings"] for control in row.get("controls") or []}

    assert len(controls) == len(distinct) > 0
    assert all("controls" not in row for row in packed["findings"])
    for packed_row, legacy_row in zip(packed["findings"], legacy["findings"], strict=True):
        assert [controls[ref] for ref in packed_row["control_refs"]] == legacy_row["controls"]
        # IDs read as the control they name.
        assert all(ref.startswith(f"{controls[ref]['framework']}:{controls[ref]['control']}:") for ref in packed_row["control_refs"])


def test_entities_are_serialized_once_and_referenced_by_canonical_id(legacy: dict) -> None:
    packed = pack_report(legacy)
    entity_ids = {row["id"] for row in packed["ai_bom_entities"]["packages"]}

    assert "packages" not in packed, "root packages is an exact alias of ai_bom_entities.packages"
    assert "packages" not in packed["inventory_snapshot"]
    occurrences = [pkg for agent in packed["agents"] for server in agent["mcp_servers"] for pkg in server["packages"]]
    assert occurrences and all(pkg["package_ref"] in entity_ids for pkg in occurrences)
    assert all("discovery_provenance" not in pkg and "name" not in pkg for pkg in occurrences)
    asset_ids = {row["stable_id"] for row in packed["assets"]}
    assert all(row["asset"]["asset_ref"] in asset_ids and "name" not in row["asset"] for row in packed["findings"])
    finding_ids = {row["canonical_id"] for row in packed["findings"]}
    assert all(row["finding_ref"] in finding_ids and "owasp_tags" not in row for row in packed["blast_radius"])
    provenance = packed["provenance"]
    text = json.dumps(packed)
    for value in provenance.values():
        assert text.count(json.dumps(value)) == 1, "each provenance record is written once"


def test_packing_manifest_names_the_fields_each_reference_covers(legacy: dict) -> None:
    fields = pack_report(legacy)["packing"]["fields"]

    assert set(fields) == {"finding_ref", "asset_ref", "package_ref"}
    assert "stable_id=id" in fields["package_ref"] and "owasp_tags" in fields["finding_ref"] and "name" in fields["asset_ref"]


def test_packed_report_is_smaller_than_legacy(legacy: dict) -> None:
    # Real reports measured 1.51x (10 packages, 176 CVEs) and 1.68x (this repository, --quick).
    assert _size(pack_report(legacy)) * 1.4 <= _size(legacy)
    assert len(json.dumps(pack_report(legacy)["findings"])) * 1.4 <= len(json.dumps(legacy["findings"]))


def test_pack_is_idempotent_and_leaves_input_untouched(legacy: dict) -> None:
    before = copy.deepcopy(legacy)
    packed = pack_report(legacy)

    assert legacy == before
    assert pack_report(packed) == packed
    expand_report(packed)
    assert packed == pack_report(before)


def test_round_trip_is_exact_for_a_document_without_a_schema_version() -> None:
    # Scanner-style estate documents (the graph benchmark input) carry no schema_version;
    # packing must mark them 2.0 without the expansion inventing a 1.0 version.
    doc = {"agents": [{"name": "a", "mcp_servers": []}], "blast_radius": [], "scan_id": "s"}
    packed = pack_report(doc)

    assert packed["schema_version"] == REPORT_SCHEMA_V2
    assert "legacy_schema_version" not in packed["packing"]
    assert expand_report(packed) == doc
    assert "schema_version" not in doc


def test_round_trip_is_exact_for_the_committed_benchmark_estate() -> None:
    path = Path(__file__).resolve().parents[1] / "docs" / "perf" / "results" / "graph-benchmark-estate-sample-report.json"
    doc = json.loads(path.read_text(encoding="utf-8"))

    assert expand_report(pack_report(doc)) == doc


def test_expand_passes_legacy_documents_through(legacy: dict) -> None:
    assert expand_report(legacy) == legacy
    assert expand_report({"document_type": "AI-BOM", "agents": []}) == {"document_type": "AI-BOM", "agents": []}


def test_values_that_differ_from_the_referenced_record_stay_inline(legacy: dict) -> None:
    varied = copy.deepcopy(legacy)
    varied["blast_radius"][0]["kev_due_date"] = "2099-01-01"
    varied["agents"][0]["mcp_servers"][0]["packages"][0]["version"] = "0.0.0-occurrence"
    varied["findings"][0]["asset"]["name"] = "renamed-at-this-occurrence"
    packed = pack_report(varied)

    assert packed["blast_radius"][0]["kev_due_date"] == "2099-01-01"
    assert packed["agents"][0]["mcp_servers"][0]["packages"][0]["version"] == "0.0.0-occurrence"
    assert expand_report(packed) == varied


def test_a_record_missing_a_key_its_reference_has_is_not_packed(legacy: dict) -> None:
    varied = copy.deepcopy(legacy)
    del varied["blast_radius"][0]["owasp_tags"]
    packed = pack_report(varied)

    assert "finding_ref" not in packed["blast_radius"][0]
    assert expand_report(packed) == varied


# ── trust boundary: v2 documents arrive from pushes and files ─────────────────


def _packed(legacy: dict) -> dict:
    return json.loads(json.dumps(pack_report(legacy)))


@pytest.mark.parametrize(
    "mutate",
    [
        pytest.param(lambda doc: doc["findings"][0]["control_refs"].append("nist:missing:00000000"), id="unknown-control-ref"),
        pytest.param(lambda doc: doc["findings"][0].__setitem__("control_refs", "not-a-list"), id="control-refs-type"),
        pytest.param(lambda doc: doc.__setitem__("compliance_controls", ["not", "a", "map"]), id="controls-table-type"),
        pytest.param(lambda doc: doc["packing"]["transforms"].append("unknown_transform"), id="unknown-transform"),
        pytest.param(lambda doc: doc.__setitem__("packing", {"schema_version": "9"}), id="unknown-packing-version"),
        pytest.param(lambda doc: doc.pop("packing"), id="missing-manifest"),
        pytest.param(lambda doc: doc["blast_radius"][0].__setitem__("finding_ref", "no-such-finding"), id="unknown-finding-ref"),
        pytest.param(
            lambda doc: doc["agents"][0]["mcp_servers"][0]["packages"][0].__setitem__("package_ref", "no-such-package"),
            id="unknown-package-ref",
        ),
        pytest.param(lambda doc: doc["findings"][0]["asset"].__setitem__("asset_ref", 7), id="asset-ref-type"),
        pytest.param(lambda doc: doc.__setitem__("provenance", {"p": "not-an-object"}), id="provenance-entry-type"),
        pytest.param(lambda doc: doc["packing"].pop("fields"), id="missing-ref-fields"),
        pytest.param(lambda doc: doc["packing"]["fields"].__setitem__("finding_ref", "owasp_tags"), id="ref-fields-type"),
        pytest.param(lambda doc: doc["packing"].__setitem__("fields", ["finding_ref"]), id="fields-table-type"),
    ],
)
def test_expand_rejects_malformed_references(legacy: dict, mutate) -> None:
    doc = _packed(legacy)
    mutate(doc)

    with pytest.raises(ReportPackingError):
        expand_report(doc)


def test_expand_bounds_reference_amplification(legacy: dict) -> None:
    doc = _packed(legacy)
    ref = doc["findings"][0]["control_refs"][0]
    doc["findings"][0]["control_refs"] = [ref] * 50_000

    with pytest.raises(ReportPackingError, match="expands beyond"):
        expand_report(doc, max_expanded_bytes=1_000_000)
    assert expand_report(_packed(legacy), max_expanded_bytes=_size(legacy) * 2) == legacy


_SECTIONS = ("agents", "findings", "blast_radius", "assets", "ai_bom_entities", "inventory_snapshot", "provenance", "compliance_controls")


@pytest.mark.parametrize("section", _SECTIONS)
@pytest.mark.parametrize("value", [5, "text", None, {"k": 1}, [1, "x", None], [{"mcp_servers": 3}]])
def test_expand_fails_closed_on_wrong_section_types(legacy: dict, section: str, value: object) -> None:
    """Any shape a pushed document can take either expands or raises ReportPackingError (422), never a 500."""
    doc = _packed(legacy)
    doc[section] = value
    try:
        outcome: dict | ReportPackingError = expand_report(doc)
    except ReportPackingError as exc:
        outcome = exc
    if not isinstance(outcome, ReportPackingError):
        # A shape the transforms never read expands to a 1.0 document carrying the value as given.
        assert outcome["schema_version"] == REPORT_SCHEMA_V1
        assert "packing" not in outcome and "compliance_controls" not in outcome and "provenance" not in outcome
        assert all("control_refs" not in row for row in outcome.get("findings") or [] if isinstance(row, dict))


# ── cross-language golden: ui/lib/report-packing.ts expands the same documents ─

GOLDEN = Path(__file__).resolve().parents[1] / "ui" / "tests" / "fixtures" / "report-schema-v2"


def write_golden() -> None:
    """Regenerate the UI golden pair: ``python -c 'from tests.test_report_packing import write_golden; write_golden()'``."""
    legacy = json.loads(json.dumps(redact_json_payload(to_json(_report(shared_vulns=1, other_vulns=1)))))
    GOLDEN.mkdir(parents=True, exist_ok=True)
    (GOLDEN / "legacy.json").write_text(json.dumps(legacy, indent=2) + "\n", encoding="utf-8")
    (GOLDEN / "packed.json").write_text(json.dumps(pack_report(legacy), indent=2) + "\n", encoding="utf-8")


def test_ui_golden_pair_matches_the_python_packer() -> None:
    legacy = json.loads((GOLDEN / "legacy.json").read_text(encoding="utf-8"))
    packed = json.loads((GOLDEN / "packed.json").read_text(encoding="utf-8"))

    assert set(packed["packing"]["transforms"]) == set(TRANSFORMS)
    assert pack_report(legacy) == packed
    assert expand_report(packed) == legacy
