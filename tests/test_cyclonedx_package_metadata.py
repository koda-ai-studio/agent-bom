"""CycloneDX package components carry every populated metadata field, and only those."""

from __future__ import annotations

from datetime import datetime

from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package
from agent_bom.output.cyclonedx_fmt import to_cyclonedx


def _component(pkg: Package) -> dict:
    agent = Agent(
        name="a",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/c.json",
        mcp_servers=[MCPServer(name="s", command="npx", packages=[pkg])],
    )
    report = AIBOMReport(agents=[agent], generated_at=datetime(2026, 1, 1), scan_id="00000000-0000-4000-8000-000000000001")
    return next(c for c in to_cyclonedx(report)["components"] if c["type"] == "library")


def test_populated_package_metadata_fields_are_exported_in_order() -> None:
    component = _component(
        Package(
            name="left-pad",
            version="1.3.0",
            ecosystem="npm",
            license_expression="MIT OR Apache-2.0",
            supplier="Example Org",
            author="Jane Dev",
            description="Pads strings",
            copyright_text="Copyright 2026 Example Org",
            homepage="https://example.test/left-pad",
            repository_url="https://example.test/left-pad.git",
            download_url="https://example.test/left-pad-1.3.0.tgz",
            scorecard_score=7.5,
        )
    )
    assert component["licenses"] == [{"expression": "MIT OR Apache-2.0"}]
    assert component["supplier"] == {"name": "Example Org"}
    assert component["author"] == "Jane Dev"
    assert component["description"] == "Pads strings"
    assert component["copyright"] == "Copyright 2026 Example Org"
    assert component["externalReferences"] == [
        {"type": "website", "url": "https://example.test/left-pad"},
        {"type": "vcs", "url": "https://example.test/left-pad.git"},
        {"type": "distribution", "url": "https://example.test/left-pad-1.3.0.tgz"},
    ]
    assert {"name": "agent-bom:scorecard-score", "value": "7.5"} in component["properties"]
    keys = list(component)
    assert keys.index("licenses") < keys.index("supplier") < keys.index("author") < keys.index("description")
    assert keys.index("description") < keys.index("copyright") < keys.index("externalReferences")


def test_single_license_and_partial_references() -> None:
    component = _component(Package(name="x", version="1", ecosystem="npm", license="MIT", repository_url="https://example.test/x.git"))
    assert component["licenses"] == [{"license": {"id": "MIT"}}]
    assert component["externalReferences"] == [{"type": "vcs", "url": "https://example.test/x.git"}]
    for absent in ("supplier", "author", "description", "copyright"):
        assert absent not in component


def test_bare_package_has_no_optional_metadata() -> None:
    component = _component(Package(name="x", version="1", ecosystem="npm"))
    for absent in ("licenses", "supplier", "author", "description", "copyright", "externalReferences", "hashes", "evidence"):
        assert absent not in component
    assert not any(p["name"] == "agent-bom:scorecard-score" for p in component["properties"])
