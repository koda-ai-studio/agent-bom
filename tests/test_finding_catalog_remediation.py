from agent_bom.finding_scope import safe_finding_response_payload
from agent_bom.graph.toxic_findings import TOXIC_RULES


def _combination_row(rule_id: str, guidance: str) -> dict:
    return {
        "id": "f-1",
        "finding_type": "COMBINATION",
        "source": "GRAPH_ANALYSIS",
        "severity": "high",
        "remediation_guidance": guidance,
        "evidence": {"rule_id": rule_id, "node_ids": ["agent:a"]},
    }


def test_combination_response_restores_catalog_remediation():
    rule = TOXIC_RULES[0]

    payload = safe_finding_response_payload(_combination_row(rule.id, "/Users/someone/secret/path"))

    assert payload["remediation_guidance"] == rule.remediation


def test_unknown_rule_keeps_remediation_withheld():
    payload = safe_finding_response_payload(_combination_row("NOT_A_RULE", "free text from a row"))

    assert payload["remediation_guidance"] is None


def test_non_graph_finding_free_text_stays_withheld():
    row = _combination_row(TOXIC_RULES[0].id, "Expected: ['read'] in /etc/app/config.json")
    row["finding_type"] = "PROMPT_SECURITY"
    row["source"] = "MCP_SCAN"

    payload = safe_finding_response_payload(row)

    assert payload["remediation_guidance"] is None
