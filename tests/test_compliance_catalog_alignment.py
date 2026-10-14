"""Every surface reads one catalog per framework, and every emitted tag resolves in it.

Three drifts this pins shut:

1. A tagger emitted an ID its framework's scoring catalog did not contain, so
   the finding silently dropped off that framework's line in ``/v1/compliance``
   and the evidence export (ISO 27001 crosswalk IDs such as ``A.5.17``).
2. The API and export scored MITRE ATT&CK against the bundled catalog while
   the taggers and CLI narrative read the active (synced) one.
3. A finding's ``applicable_frameworks`` (hub posture count) disagreed with
   the frameworks its control tags evidence (``/v1/compliance`` count).
"""

from __future__ import annotations

import itertools
import json
from collections import defaultdict
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from agent_bom.compliance_coverage import (
    TAG_MAPPED_FRAMEWORKS,
    ComplianceFrameworkMetadata,
    control_key_for_tag,
    rows_by_control_key,
    scoring_catalog,
)
from agent_bom.constants import CWE_COMPLIANCE_MAP, TRAINING_DATA_PACKAGES, VECTOR_STORE_PACKAGES
from agent_bom.finding import FindingSource, FindingType, ast_flow_dict_to_finding, secret_dict_to_finding
from agent_bom.framework_mapping import controls_for_finding_shape
from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, MCPTool, Package, Severity, Vulnerability
from agent_bom.scanners.package_scan import apply_framework_tags
from agent_bom.vuln_compliance import tag_vulnerability
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_META_BY_FIELD: dict[str, ComplianceFrameworkMetadata] = {m.tag_field: m for m in TAG_MAPPED_FRAMEWORKS}
_META_BY_SLUG: dict[str, ComplianceFrameworkMetadata] = {m.slug: m for m in TAG_MAPPED_FRAMEWORKS}
# Short framework keys used by CWE_COMPLIANCE_MAP and vuln_compliance whose tag
# field is not simply ``<key>_tags``.
_KEY_ALIASES = {"owasp_llm": "owasp_tags"}


def _field_for_key(key: str) -> str:
    field = _KEY_ALIASES.get(key, f"{key}_tags")
    assert field in _META_BY_FIELD, f"framework key {key!r} has no scoring framework"
    return field


def _secret(**overrides):
    payload = {
        "file": "project/app/settings.py",
        "line": 7,
        "type": "GitHub Token",
        "category": "credential",
        "severity": "critical",
        "preview": "ghp_****",
    }
    payload.update(overrides)
    return secret_dict_to_finding(payload)


def _sast(**overrides):
    payload = {"category": "command_execution", "file": "app.py", "line": 12, "sink": "subprocess.call"}
    payload.update(overrides)
    return ast_flow_dict_to_finding(payload)


# ─── 1. Every emittable ID resolves in its scoring catalog ──────────────────


def _blast_radius(*, severity, kev, fixed, pkg, creds, exec_tool, agents, malicious, cwe_ids) -> BlastRadius:
    return BlastRadius(
        vulnerability=Vulnerability(
            id="CVE-2026-0001",
            summary="t",
            severity=severity,
            is_kev=kev,
            fixed_version=fixed,
            cwe_ids=list(cwe_ids),
        ),
        package=Package(name=pkg, version="1.0.0", ecosystem="pypi", is_malicious=malicious),
        affected_servers=[MCPServer(name="srv")],
        affected_agents=[Agent(name=f"a{i}", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp") for i in range(agents)],
        exposed_credentials=["OPENAI_API_KEY"] if creds else [],
        exposed_tools=[MCPTool(name="exec", description="execute shell command")] if exec_tool else [],
    )


def _emittable_tags() -> dict[str, set[str]]:
    emitted: dict[str, set[str]] = defaultdict(set)
    all_cwes = sorted(CWE_COMPLIANCE_MAP)
    pkgs = ("flask", "langchain", sorted(TRAINING_DATA_PACKAGES)[0], sorted(VECTOR_STORE_PACKAGES)[0])

    # Curated CWE rows are data any CWE-driven tagger can return verbatim.
    for row in CWE_COMPLIANCE_MAP.values():
        for key, ids in row.items():
            emitted[_field_for_key(key)].update(ids)

    # Blast-radius taggers, through the one stamping function the scan uses.
    flag_space = itertools.product(
        (Severity.CRITICAL, Severity.LOW),
        (True, False),
        (None, "2.0.0"),
        pkgs,
        (True, False),
        (True, False),
        (1, 2),
        (True, False),
    )
    variants = [(*flags, cwes) for flags in flag_space for cwes in ((), tuple(all_cwes))]
    for cwe in all_cwes:
        variants.append((Severity.CRITICAL, True, "2.0.0", "langchain", True, True, 2, True, (cwe,)))
        variants.append((Severity.LOW, False, None, "flask", False, False, 1, False, (cwe,)))
    for severity, kev, fixed, pkg, creds, exec_tool, agents, malicious, cwes in variants:
        br = _blast_radius(
            severity=severity,
            kev=kev,
            fixed=fixed,
            pkg=pkg,
            creds=creds,
            exec_tool=exec_tool,
            agents=agents,
            malicious=malicious,
            cwe_ids=cwes,
        )
        apply_framework_tags(br)
        for field in _META_BY_FIELD:
            emitted[field].update(getattr(br, field))
        for key, ids in tag_vulnerability(br.vulnerability, br.package).items():
            emitted[_field_for_key(key)].update(ids)

    # Non-advisory finding shapes.
    cwe_variants = [(), tuple(all_cwes), *((cwe,) for cwe in all_cwes)]
    for finding_type, source, cwes, location in itertools.product(FindingType, FindingSource, cwe_variants, (None, "project/.mcp.json")):
        for field, ids in controls_for_finding_shape(finding_type, source=source, cwe_ids=cwes, location=location).items():
            emitted[field].update(ids)
    return emitted


def test_every_tagger_emitted_id_resolves_in_its_scoring_catalog() -> None:
    emitted = _emittable_tags()
    unresolved = {
        field: sorted(tag for tag in tags if control_key_for_tag(tag, scoring_catalog(_META_BY_FIELD[field])) is None)
        for field, tags in emitted.items()
    }
    assert {field: tags for field, tags in unresolved.items() if tags} == {}
    # The enumeration must actually reach the crosswalk-derived ISO IDs.
    assert {"A.5.17", "A.5.16", "A.8.7"} <= emitted["iso_27001_tags"]


def test_credential_exposure_reaches_the_iso_line() -> None:
    from agent_bom.api.routes.compliance_routes.scoring import _build_controls

    finding = _secret()
    assert "A.5.17" in finding.iso_27001_tags
    iso = _META_BY_SLUG["iso-27001"]
    catalog = scoring_catalog(iso)
    rows = [finding.to_dict()]
    controls = {
        c["control_id"]: c
        for c in _build_controls(
            rows_by_control_key(rows, catalog, iso.tag_field),
            catalog,
            iso.tag_field,
            "code",
            scan_count=1,
            latest_scan=None,
        )
    }
    for control_id in finding.iso_27001_tags:
        assert controls[control_id]["findings"] == 1, control_id
        assert controls[control_id]["status"] == "fail", control_id


def test_credential_exposure_reaches_the_iso_export(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.models import AIBOMReport
    from agent_bom.output import compliance_export

    finding = _secret()
    monkeypatch.setattr(compliance_export, "unified_export_findings", lambda _report: [finding])
    evidence = compliance_export._merged_evidence(AIBOMReport(), _META_BY_SLUG["iso-27001"])
    assert set(finding.iso_27001_tags) <= set(evidence)
    assert "A.5.17" in evidence


# ─── 2. One ATT&CK catalog resolver for API, export and CLI ─────────────────

_SYNCED_ONLY_TECHNIQUE = "T9999"


@pytest.fixture
def synced_attack_catalog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    from agent_bom import mitre_fetch

    bundled = json.loads(mitre_fetch._BUNDLED_CATALOG_PATH.read_text())
    bundled["techniques"][_SYNCED_ONLY_TECHNIQUE] = {"name": "Synced Only Technique", "tactics": ["execution"]}
    bundled["cwe_to_attack"].setdefault("CWE-78", []).append(_SYNCED_ONLY_TECHNIQUE)
    bundled["source"] = "synced"
    synced = tmp_path / "mitre_attack_catalog.json"
    synced.write_text(json.dumps(bundled))
    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_PATH", str(synced))
    monkeypatch.setenv("AGENT_BOM_MITRE_CATALOG_MODE", "auto")
    return _SYNCED_ONLY_TECHNIQUE


def test_synced_attack_technique_is_in_every_surface_catalog(synced_attack_catalog: str) -> None:
    from agent_bom.mitre_attack import tag_blast_radius
    from agent_bom.output.compliance_narrative import _get_catalog

    attack = _META_BY_SLUG["attack"]
    br = _blast_radius(
        severity=Severity.HIGH,
        kev=False,
        fixed=None,
        pkg="flask",
        creds=False,
        exec_tool=False,
        agents=1,
        malicious=False,
        cwe_ids=("CWE-78",),
    )
    assert synced_attack_catalog in tag_blast_radius(br)
    assert synced_attack_catalog in scoring_catalog(attack)
    assert synced_attack_catalog in _get_catalog("attack")[0]
    # The bundled disclosure count stays deterministic for docs.
    assert synced_attack_catalog not in attack.catalog


def test_synced_attack_technique_reaches_export(synced_attack_catalog: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.models import AIBOMReport
    from agent_bom.output import compliance_export

    finding = _sast()
    finding.attack_tags = [synced_attack_catalog]
    monkeypatch.setattr(compliance_export, "unified_export_findings", lambda _report: [finding])
    evidence = compliance_export._merged_evidence(AIBOMReport(), _META_BY_SLUG["attack"])
    assert synced_attack_catalog in evidence


class TestApiCatalogs:
    @classmethod
    def setup_class(cls) -> None:
        enable_trusted_proxy_env()

    @classmethod
    def teardown_class(cls) -> None:
        disable_trusted_proxy_env()

    def _seed(self, findings: list[dict]) -> None:
        from datetime import datetime, timezone

        from agent_bom.api.server import JobStatus, ScanJob, ScanRequest, _get_store, set_job_store
        from agent_bom.api.store import InMemoryJobStore

        set_job_store(InMemoryJobStore())
        now = datetime.now(timezone.utc).isoformat()
        job = ScanJob(job_id="job-alignment", tenant_id="default", created_at=now, request=ScanRequest())
        job.status = JobStatus.DONE
        job.completed_at = now
        job.result = {"agents": [], "blast_radius": [], "findings": findings, "threat_framework_summary": {}}
        _get_store().put(job)

    def _compliance(self) -> dict:
        from agent_bom.api.server import app

        with TestClient(app) as client:
            response = client.get("/v1/compliance", headers=proxy_headers(tenant="default"))
        assert response.status_code == 200, response.text
        return response.json()

    def test_api_scores_credential_exposure_on_iso_line(self) -> None:
        finding = _secret()
        self._seed([finding.to_dict()])
        iso = {c["control_id"]: c for c in self._compliance()["iso_27001"]}
        assert iso["A.5.17"]["findings"] == 1
        assert iso["A.5.17"]["status"] == "fail"

    def test_api_attack_overlay_uses_synced_catalog(self, synced_attack_catalog: str) -> None:
        finding = _sast()
        finding.attack_tags = [synced_attack_catalog]
        self._seed([finding.to_dict()])
        attack = {c["control_id"]: c for c in self._compliance()["mitre_attack"]}
        assert attack[synced_attack_catalog]["status"] == "applicable"
        assert attack[synced_attack_catalog]["findings"] == 1


# ─── 3. Applicability and control tags agree ────────────────────────────────


def _tagged_slugs(finding) -> set[str]:
    return {meta.slug for meta in TAG_MAPPED_FRAMEWORKS if getattr(finding, meta.tag_field)}


@pytest.mark.parametrize(
    "build",
    [
        _sast,
        lambda: _sast(category="dynamic_code_execution_eval", sink="eval"),
        _secret,
        lambda: _secret(file="project/.mcp.json", line=3),
        lambda: _secret(type="US SSN", category="pii", severity="medium"),
    ],
    ids=["sast", "sast-no-cwe", "credential", "credential-mcp", "pii"],
)
def test_every_tagged_framework_is_applicable(build) -> None:
    from agent_bom.compliance_hub import apply_hub_classification

    finding = build()
    assert _tagged_slugs(finding)
    assert _tagged_slugs(finding) <= set(finding.applicable_frameworks)
    before = list(finding.applicable_frameworks)
    apply_hub_classification(finding)
    assert finding.applicable_frameworks == before


def test_hub_posture_counts_cover_compliance_tag_counts() -> None:
    findings = [_sast(), _secret(), _secret(type="US SSN", category="pii", severity="medium")]
    by_applicability: dict[str, int] = defaultdict(int)
    by_tags: dict[str, int] = defaultdict(int)
    for finding in findings:
        for slug in finding.applicable_frameworks:
            by_applicability[slug] += 1
        for slug in _tagged_slugs(finding):
            by_tags[slug] += 1
    # A finding /v1/compliance counts under a framework is always counted by hub
    # posture too; hub posture may also list frameworks the selection table
    # applies but no control tag maps yet.
    assert all(by_applicability[slug] >= count for slug, count in by_tags.items())


def test_untagged_finding_keeps_selection_baseline() -> None:
    from agent_bom.compliance_hub import apply_hub_classification, select_frameworks
    from agent_bom.finding import Asset, Finding

    finding = Finding(
        finding_type=FindingType.LICENSE,
        source=FindingSource.SBOM,
        asset=Asset(name="pkg", asset_type="package"),
        severity="low",
        title="copyleft license",
    )
    apply_hub_classification(finding)
    assert not _tagged_slugs(finding)
    assert finding.applicable_frameworks == select_frameworks(FindingSource.SBOM, asset_type="package", finding_type=FindingType.LICENSE)
