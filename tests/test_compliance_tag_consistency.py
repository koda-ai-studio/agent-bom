"""Control tags stay framework-correct across findings, graph and exports."""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

from agent_bom.compliance_coverage import COMPLIANCE_TAG_FIELDS
from agent_bom.compliance_utils import framework_qualified_finding_tags
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.models import BlastRadius, Package, Severity, Vulnerability
from agent_bom.vuln_compliance import tag_vulnerability


def _finding(**tags: list[str]) -> Finding:
    return Finding(
        finding_type=FindingType.COMBINATION,
        source=FindingSource.GRAPH_ANALYSIS,
        asset=Asset(name="res", asset_type="cloud_resource"),
        severity="high",
        title="t",
        **tags,  # type: ignore[arg-type]
    )


def test_qualified_tags_never_pass_a_framework_less_colon_id_through() -> None:
    tags = framework_qualified_finding_tags(_finding(owasp_tags=["A06:2021"], compliance_tags=["LLM06:2025"]))
    frameworks = {tag.partition(":")[0] for tag in tags}
    assert "A06" not in frameworks
    assert "LLM06" not in frameworks


def test_qualified_tags_keep_already_qualified_compliance_tags() -> None:
    tags = framework_qualified_finding_tags(_finding(compliance_tags=["nist_800_53:AC-6"], owasp_tags=["LLM06"]))
    assert "nist_800_53:AC-6" in tags
    assert "owasp_llm:LLM06" in tags


def test_every_compliance_tag_field_round_trips_into_graph_vuln_node() -> None:
    br: dict[str, object] = {"vulnerability_id": "CVE-2099-0001", "severity": "high", "package": "pkg@1.0"}
    expected: dict[str, str] = {}
    for index, field in enumerate(COMPLIANCE_TAG_FIELDS):
        expected[field] = f"CTRL-{index}-{field}"
        br[field] = [expected[field]]
    graph = build_unified_graph_from_report({"blast_radius": [br]})
    node_tags = set(graph.nodes["vuln:CVE-2099-0001"].compliance_tags)
    missing = {field for field, tag in expected.items() if tag not in node_tags}
    assert not missing


def test_rehydrated_graph_findings_keep_every_tag_field() -> None:
    from agent_bom.domain.finding_rehydrate import finding_from_dict
    from agent_bom.finding import LEGACY_CONTROL_FIELDS

    framework_fields = [field for field, _ in LEGACY_CONTROL_FIELDS if field != "compliance_tags"]
    original = _finding(**{field: [f"X-{field}"] for field in framework_fields})
    rehydrated = finding_from_dict(original.to_dict())
    assert rehydrated is not None
    assert rehydrated.compliance_tags == []
    for field in framework_fields:
        assert getattr(rehydrated, field) == [f"X-{field}"], field


def _tags_for(cwe: str) -> dict[str, list[str]]:
    vuln = Vulnerability(id="CVE-2099-0002", summary="s", severity=Severity.HIGH, cwe_ids=[cwe])
    return tag_vulnerability(vuln, Package(name="left-pad", version="1.0.0", ecosystem="npm"))


def test_cwe_tagging_is_case_and_whitespace_insensitive() -> None:
    canonical = _tags_for("CWE-89")
    assert canonical.get("nist_800_53")
    assert _tags_for("cwe-89") == canonical
    assert _tags_for(" CWE-89 ") == canonical


def _swallowed_first_party_imports(path: Path) -> list[tuple[str, str]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        guarded = {h.type.id for h in node.handlers if isinstance(h.type, ast.Name)}
        if not guarded & {"ImportError", "ModuleNotFoundError"}:
            continue
        for stmt in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(stmt, ast.ImportFrom) and stmt.module and stmt.module.startswith("agent_bom") and stmt.level == 0:
                out.extend((stmt.module, alias.name) for alias in stmt.names)
    return out


def test_cmmc_has_no_swallowed_import_of_a_missing_symbol() -> None:
    import agent_bom.cmmc as cmmc

    for module_name, name in _swallowed_first_party_imports(Path(cmmc.__file__)):
        module = importlib.import_module(module_name)
        assert hasattr(module, name), f"{module_name}.{name} does not exist"


def test_sast_blast_radius_cmmc_tags_are_catalog_practices() -> None:
    from agent_bom.cmmc import CMMC_PRACTICES, tag_blast_radius

    vuln = Vulnerability(id="SAST-1", summary="sqli", severity=Severity.HIGH, cwe_ids=["CWE-89"])
    pkg = Package(name="app", version="0", ecosystem="sast")
    br = BlastRadius(vulnerability=vuln, package=pkg, affected_servers=[], affected_agents=[], exposed_credentials=[], exposed_tools=[])
    tags = tag_blast_radius(br)
    assert tags
    assert set(tags) <= set(CMMC_PRACTICES)
