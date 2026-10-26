"""CycloneDX XML and SPDX tag-value ingest match their JSON twins exactly."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest
from cyclonedx.model import ExternalReference, ExternalReferenceType, HashAlgorithm, HashType, Property, XsUri
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentScope, ComponentType
from cyclonedx.model.contact import OrganizationalEntity
from cyclonedx.model.license import DisjunctiveLicense, LicenseExpression
from cyclonedx.model.vulnerability import (
    BomTarget,
    Vulnerability,
    VulnerabilityRating,
    VulnerabilityScoreSource,
    VulnerabilitySeverity,
    VulnerabilitySource,
)
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from packageurl import PackageURL

from agent_bom.parsers.sbom_context import load_sbom_agents
from agent_bom.sbom import load_sbom
from agent_bom.sbom_formats.decode import decode_sbom_document

FIXTURES = Path(__file__).parent / "fixtures" / "sbom_ingest"


def _packages(path: Path) -> list[dict]:
    packages, _fmt, _name = load_sbom(str(path))
    return [dataclasses.asdict(pkg) for pkg in packages]


def _agent_packages(path: Path) -> list[dict]:
    agents, _fmt = load_sbom_agents(str(path))
    return [dataclasses.asdict(pkg) for agent in agents for server in agent.mcp_servers for pkg in server.packages]


def _rich_bom() -> Bom:
    bom = Bom()
    bom.metadata.timestamp = datetime(2026, 1, 2, tzinfo=timezone.utc)
    bom.metadata.component = Component(name="payments-api", version="4.2.0", type=ComponentType.APPLICATION, bom_ref="root")
    flask = Component(
        name="flask",
        version="2.0.0",
        type=ComponentType.LIBRARY,
        bom_ref="pkg:pypi/flask@2.0.0",
        purl=PackageURL.from_string("pkg:pypi/flask@2.0.0"),
        supplier=OrganizationalEntity(name="Pallets"),
        author="Armin Ronacher",
        description="A simple framework for building complex web applications.",
        scope=ComponentScope.REQUIRED,
        copyright="2010 Pallets",
        licenses=[DisjunctiveLicense(id="BSD-3-Clause")],
        hashes=[HashType(alg=HashAlgorithm.SHA_256, content="a" * 64)],
        external_references=[
            ExternalReference(type=ExternalReferenceType.WEBSITE, url=XsUri("https://example.test/flask")),
            ExternalReference(type=ExternalReferenceType.VCS, url=XsUri("https://example.test/flask.git")),
            ExternalReference(type=ExternalReferenceType.DISTRIBUTION, url=XsUri("https://example.test/flask.tar.gz")),
        ],
        properties=[Property(name="agent-bom:dependency-scope", value="runtime")],
    )
    werkzeug = Component(
        name="werkzeug",
        version="2.0.1",
        type=ComponentType.LIBRARY,
        bom_ref="pkg:pypi/werkzeug@2.0.1",
        purl=PackageURL.from_string("pkg:pypi/werkzeug@2.0.1"),
        licenses=[LicenseExpression("BSD-3-Clause OR MIT")],
        scope=ComponentScope.OPTIONAL,
    )
    nested = Component(
        name="left-pad",
        version="1.3.0",
        type=ComponentType.LIBRARY,
        bom_ref="pkg:npm/left-pad@1.3.0",
        purl=PackageURL.from_string("pkg:npm/left-pad@1.3.0"),
        licenses=[DisjunctiveLicense(name="WTFPL")],
    )
    flask.components.add(nested)
    bom.components.add(flask)
    bom.components.add(werkzeug)
    bom.register_dependency(bom.metadata.component, [flask])
    bom.register_dependency(flask, [werkzeug, nested])
    bom.vulnerabilities.add(
        Vulnerability(
            bom_ref="vuln-1",
            id="CVE-2023-30861",
            source=VulnerabilitySource(name="NVD", url=XsUri("https://nvd.nist.gov/vuln/detail/CVE-2023-30861")),
            description="Session cookie disclosure",
            recommendation="Upgrade to 2.3.2",
            ratings=[
                VulnerabilityRating(
                    score=Decimal("7.5"),
                    severity=VulnerabilitySeverity.HIGH,
                    method=VulnerabilityScoreSource.CVSS_V3_1,
                    vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                )
            ],
            cwes=[539],
            affects=[BomTarget(ref="pkg:pypi/flask@2.0.0")],
            properties=[
                Property(name="agent-bom:kev", value="true"),
                Property(name="agent-bom:epss_score", value="0.42"),
                Property(name="agent-bom:epss_percentile", value="0.9"),
            ],
        )
    )
    return bom


@pytest.mark.parametrize("version", [SchemaVersion.V1_4, SchemaVersion.V1_5, SchemaVersion.V1_6, SchemaVersion.V1_7])
def test_cyclonedx_xml_matches_json_for_library_generated_boms(tmp_path: Path, version: SchemaVersion) -> None:
    bom = _rich_bom()
    json_path = tmp_path / "bom.cdx.json"
    xml_path = tmp_path / "bom.cdx.xml"
    json_path.write_text(make_outputter(bom, OutputFormat.JSON, version).output_as_string(indent=2))
    xml_path.write_text(make_outputter(bom, OutputFormat.XML, version).output_as_string(indent=2))

    from_json = _packages(json_path)
    from_xml = _packages(xml_path)

    assert from_xml == from_json
    by_name = {pkg["name"]: pkg for pkg in from_xml}
    assert set(by_name) == {"flask", "werkzeug", "left-pad"}
    flask = by_name["flask"]
    assert flask["license"] == "BSD-3-Clause" and flask["supplier"] == "Pallets"
    assert flask["homepage"] and flask["repository_url"] and flask["download_url"]
    assert flask["is_direct"] is True and by_name["werkzeug"]["is_direct"] is False
    assert by_name["werkzeug"]["license_expression"] == "BSD-3-Clause OR MIT"
    [vuln] = flask["vulnerabilities"]
    assert (vuln["id"], vuln["severity"].value, vuln["cvss_score"], vuln["is_kev"]) == ("CVE-2023-30861", "high", 7.5, True)
    assert vuln["fixed_version"] == "2.3.2"


@pytest.mark.parametrize(
    ("xml_name", "json_name"),
    [("syft-like.cdx.xml", "syft-like.cdx.json"), ("agent-context.cdx.xml", "agent-context.cdx.json")],
)
def test_cyclonedx_xml_fixture_pairs_match_through_every_intake(xml_name: str, json_name: str) -> None:
    assert _packages(FIXTURES / xml_name) == _packages(FIXTURES / json_name)
    assert _agent_packages(FIXTURES / xml_name) == _agent_packages(FIXTURES / json_name)
    assert _packages(FIXTURES / xml_name)


def test_cyclonedx_xml_agent_context_restores_the_same_topology() -> None:
    xml_agents, xml_fmt = load_sbom_agents(str(FIXTURES / "agent-context.cdx.xml"))
    json_agents, json_fmt = load_sbom_agents(str(FIXTURES / "agent-context.cdx.json"))
    assert xml_fmt == json_fmt == "cyclonedx"
    shape = lambda agents: [(a.name, [(s.name, [p.name for p in s.packages]) for s in a.mcp_servers]) for a in agents]  # noqa: E731
    assert shape(xml_agents) == shape(json_agents)
    assert len(xml_agents) >= 1 and any(s.packages for a in xml_agents for s in a.mcp_servers)


def test_spdx_tagvalue_fixture_pair_matches_json() -> None:
    tag_value = _packages(FIXTURES / "syft-like.spdx")
    assert tag_value == _packages(FIXTURES / "syft-like.spdx.json")
    assert _agent_packages(FIXTURES / "syft-like.spdx") == _agent_packages(FIXTURES / "syft-like.spdx.json")
    by_name = {pkg["name"]: pkg for pkg in tag_value}
    assert by_name["requests"]["purl"] == "pkg:pypi/requests@2.31.0"
    assert by_name["requests"]["license"] == "Apache-2.0"
    assert by_name["urllib3"]["parent_package"] == "requests"
    assert by_name["requests"]["description"].startswith("Python HTTP")


def test_spdx_tagvalue_export_round_trips_like_spdx_json(tmp_path: Path) -> None:
    from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package, Severity
    from agent_bom.models import Vulnerability as Vuln
    from agent_bom.output.spdx2_fmt import to_spdx2, to_spdx2_tagvalue

    pkg = Package(name="requests", version="2.31.0", ecosystem="pypi", purl="pkg:pypi/requests@2.31.0", license="Apache-2.0")
    pkg.vulnerabilities = [Vuln(id="CVE-2024-35195", summary="cert verify", severity=Severity.MEDIUM)]
    server = MCPServer(name="fetch-server", command="uvx", args=["mcp-server-fetch"], packages=[pkg])
    agent = Agent(name="desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/x.json", mcp_servers=[server])
    report = AIBOMReport(agents=[agent])
    (tmp_path / "out.spdx.json").write_text(json.dumps(to_spdx2(report)))
    (tmp_path / "out.spdx").write_text(to_spdx2_tagvalue(report))

    assert _packages(tmp_path / "out.spdx") == _packages(tmp_path / "out.spdx.json")
    shape = lambda agents: sorted((a.name, sorted((s.name, sorted(p.name for p in s.packages)) for s in a.mcp_servers)) for a in agents)  # noqa: E731
    assert shape(load_sbom_agents(str(tmp_path / "out.spdx"))[0]) == shape(load_sbom_agents(str(tmp_path / "out.spdx.json"))[0])
    assert [p["name"] for p in _packages(tmp_path / "out.spdx")] == ["requests"]


# ── hostile input fails closed ───────────────────────────────────────────────


_XXE = b"""<?xml version="1.0"?>
<!DOCTYPE bom [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components>
<component type="library"><name>&xxe;</name><version>1</version></component></components></bom>"""

_BILLION_LAUGHS = b"""<?xml version="1.0"?>
<!DOCTYPE bom [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>
<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components>
<component type="library"><name>&c;</name><version>1</version></component></components></bom>"""


@pytest.mark.parametrize("payload", [_XXE, _BILLION_LAUGHS])
def test_cyclonedx_xml_refuses_dtds_and_entities(tmp_path: Path, payload: bytes) -> None:
    path = tmp_path / "bom.xml"
    path.write_bytes(payload)
    for load in (load_sbom, load_sbom_agents):
        with pytest.raises(ValueError, match="CycloneDX XML rejected"):
            load(str(path))


def test_non_cyclonedx_xml_is_refused() -> None:
    with pytest.raises(ValueError, match="not a CycloneDX BOM"):
        decode_sbom_document(b"<project><dependencies/></project>")


def test_deeply_nested_components_fail_closed() -> None:
    depth = 200
    body = "".join(f'<component type="library"><name>c{i}</name><version>1</version><components>' for i in range(depth))
    body += "".join("</components></component>" for _ in range(depth))
    doc = f'<bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1"><components>{body}</components></bom>'
    with pytest.raises(ValueError, match="nesting"):
        decode_sbom_document(doc.encode())


def test_oversized_documents_are_refused_before_parsing() -> None:
    oversized = b"SPDXVersion: SPDX-2.3\n" + b"#" * (10 * 1024 * 1024)
    with pytest.raises(ValueError, match="10 MiB"):
        decode_sbom_document(oversized)


@pytest.mark.parametrize(
    "text",
    [
        "SPDXVersion: SPDX-2.3\nPackageName: x\nPackageDescription: <text>never closed\n",
        "SPDXVersion: SPDX-2.3\nthis line has no tag\n",
        "SPDXVersion: SPDX-3.0\n",
        "SPDXVersion: SPDX-2.3\nRelationship: only-two TOKENS\n",
    ],
)
def test_malformed_tag_value_fails_closed(text: str) -> None:
    with pytest.raises(ValueError):
        decode_sbom_document(text)


def test_minimal_tag_value_document_is_accepted(tmp_path: Path) -> None:
    path = tmp_path / "bom.spdx"
    path.write_text("SPDXVersion: SPDX-2.3\nDataLicense: CC0-1.0\nSPDXID: SPDXRef-DOCUMENT\n")
    assert load_sbom(str(path))[:2] == ([], "spdx-2")


def test_tag_value_carries_cloud_inventory_evidence_like_json(tmp_path: Path) -> None:
    from agent_bom.models import AIBOMReport
    from agent_bom.output.spdx2_fmt import to_spdx2, to_spdx2_tagvalue

    inventory = {"provider": "aws", "account_id": "example-account", "instances": [{"id": "i-1", "name": "web"}]}
    report = AIBOMReport(cloud_inventory_data=inventory)
    (tmp_path / "ctx.spdx.json").write_text(json.dumps(to_spdx2(report)))
    (tmp_path / "ctx.spdx").write_text(to_spdx2_tagvalue(report))

    def evidence(path: Path) -> object:
        agents, _ = load_sbom_agents(str(path))
        found = dict(agents[0].metadata["sbom_import"]["cloud_inventory"])
        found["import_provenance"] = {k: v for k, v in found["import_provenance"].items() if k != "document_sha256"}
        return found

    assert evidence(tmp_path / "ctx.spdx") == evidence(tmp_path / "ctx.spdx.json")
    assert evidence(tmp_path / "ctx.spdx")["account_id"] == "example-account"


def test_report_diff_reads_xml_and_tag_value_sboms() -> None:
    from agent_bom.history import load_report_or_sbom

    names = lambda report: sorted(p["name"] for a in report["agents"] for s in a["mcp_servers"] for p in s["packages"])  # noqa: E731
    assert names(load_report_or_sbom(FIXTURES / "syft-like.cdx.xml")) == names(load_report_or_sbom(FIXTURES / "syft-like.cdx.json"))
    assert names(load_report_or_sbom(FIXTURES / "syft-like.spdx")) == names(load_report_or_sbom(FIXTURES / "syft-like.spdx.json"))
    assert "lodash" in names(load_report_or_sbom(FIXTURES / "syft-like.cdx.xml"))


def test_utf16_json_sboms_still_load(tmp_path: Path) -> None:
    path = tmp_path / "bom.json"
    path.write_bytes((FIXTURES / "syft-like.cdx.json").read_text().encode("utf-16"))
    assert _packages(path) == _packages(FIXTURES / "syft-like.cdx.json")
