"""An agent reaching a credential or privileged tool through MCP maps to OWASP MCP01 and MCP02."""

from __future__ import annotations

from agent_bom.finding import FindingSource, FindingType
from agent_bom.framework_mapping import controls_for_finding_shape


def test_agent_reaches_privileged_maps_to_owasp_mcp_secret_and_scope_controls() -> None:
    tags = controls_for_finding_shape(FindingType.COMBINATION, source=FindingSource.MCP_SCAN, rule_id="AGENT_REACHES_PRIVILEGED")
    assert tags["owasp_mcp_tags"] == ["MCP01", "MCP02"]
    assert tags["owasp_tags"] == ["LLM06"]
    assert tags["owasp_agentic_tags"] == ["ASI03"]


def test_non_agent_toxic_combinations_do_not_gain_mcp_tags() -> None:
    tags = controls_for_finding_shape(FindingType.COMBINATION, source=FindingSource.MCP_SCAN, rule_id="PUBLIC_EXPOSED_KEV")
    assert "owasp_mcp_tags" not in tags
