"""Keep narrative owners bounded without losing persisted finding evidence."""

from copy import deepcopy
from pathlib import Path

from agent_bom.output import compliance_narrative


def test_narrative_owners_fit_the_architecture_file_target():
    root = Path(compliance_narrative.__file__).parent
    oversized = {
        path.name: len(path.read_text().splitlines())
        for path in root.glob("compliance_narrative*.py")
        if len(path.read_text().splitlines()) > 600
    }
    assert oversized == {}, "Narrative owners must not require file-size allowances"


def test_persisted_finding_projection_preserves_mixed_mapping_evidence():
    rows = [
        {
            "id": "credential-fixture",
            "finding_type": "CREDENTIAL_EXPOSURE",
            "title": "Exposed credential in agent configuration",
            "asset": {"asset_type": "agent", "name": "support-agent"},
            "severity": "high",
            "effective_severity": "critical",
            "risk_score": "invalid",
            "owner": "platform-team",
            "sla_due_at": "2026-11-01T00:00:00Z",
            "soc2_tags": ["CC6.1"],
            "controls": [{"framework": "soc2", "id": "CC6.1"}, {"framework": "owasp-mcp", "control": "MCP01"}, None],
            "framework_tags": ["soc2:CC6.2", "owasp_mcp:MCP01", "unknown:X", "malformed"],
            "cwe_ids": ["CWE-798", ""],
        },
        {
            "cve_id": "CVE-2026-0001",
            "package": "@scope/package@1.2.3",
            "effective_reach_score": "7.5",
            "affected_agents": ["build-agent"],
            "fixed_version": "1.2.4",
            "is_kev": True,
        },
    ]
    original = deepcopy(rows)
    credential, advisory = compliance_narrative.blast_radii_from_finding_rows(rows)
    assert rows == original
    assert credential.soc2_tags == ["CC6.1", "CC6.2"]
    assert credential.owasp_mcp_tags == ["MCP01"]
    assert credential.vulnerability.severity.value == "critical"
    assert credential.vulnerability.cwe_ids == ["CWE-798"]
    assert credential.risk_score == 0.0
    assert credential.finding_type == "CREDENTIAL_EXPOSURE"
    assert credential.owner == "platform-team"
    assert credential.sla_due_at == "2026-11-01T00:00:00Z"
    assert [agent.name for agent in credential.affected_agents] == ["support-agent"]
    assert (advisory.package.name, advisory.package.version) == ("@scope/package", "1.2.3")
    assert advisory.vulnerability.id == "CVE-2026-0001"
    assert advisory.vulnerability.fixed_version == "1.2.4"
    assert advisory.vulnerability.is_kev is True
    assert advisory.risk_score == 7.5
    assert advisory.finding_type == "CVE"
