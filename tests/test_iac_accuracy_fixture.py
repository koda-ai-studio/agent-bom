"""Precision/recall pins for the planted-issue corpus in ``fixtures/iac_accuracy``.

Every planted issue is asserted at its exact line, and every planted
look-alike (scoped policy, private bucket, safe workflow, ...) is asserted to
stay quiet, so a regression in either direction fails here.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.iac import scan_iac_with_context
from agent_bom.iac.models import IaCFinding

FIXTURE = Path(__file__).parent / "fixtures" / "iac_accuracy"


def _scan(sub: str) -> list[IaCFinding]:
    return scan_iac_with_context(FIXTURE / sub).findings


def _lines(findings: list[IaCFinding], rule_id: str) -> list[int]:
    return sorted(f.line_number for f in findings if f.rule_id == rule_id)


class TestTerraformIamWildcards:
    def test_jsonencode_policy_document_and_star_colon_star_are_detected_at_their_lines(self) -> None:
        findings = [f for f in _scan("terraform/iam.tf")]
        assert _lines(findings, "TF-SEC-004") == [7, 8, 19, 28, 29]

    def test_scoped_policies_are_not_flagged(self) -> None:
        findings = _scan("terraform/iam.tf")
        flagged = {f.line_number for f in findings if f.rule_id in {"TF-SEC-004", "TF-SEC-010"}}
        assert not flagged & set(range(32, 50))

    def test_deny_statement_with_wildcard_is_not_a_grant(self, tmp_path: Path) -> None:
        tf = tmp_path / "deny.tf"
        tf.write_text(
            'data "aws_iam_policy_document" "guard" {\n'
            "  statement {\n"
            '    effect    = "Deny"\n'
            '    actions   = ["*"]\n'
            '    resources = ["*"]\n'
            "  }\n"
            "}\n"
            'resource "aws_iam_policy" "deny_json" {\n'
            "  policy = jsonencode({\n"
            '    Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]\n'
            "  })\n"
            "}\n"
        )
        findings = scan_iac_with_context(tf).findings
        assert not [f for f in findings if f.rule_id in {"TF-SEC-004", "TF-SEC-010"}]

    def test_service_wide_wildcard_is_distinct_from_full_wildcard(self, tmp_path: Path) -> None:
        tf = tmp_path / "svc.tf"
        tf.write_text(
            'resource "aws_iam_user_policy" "s3_all" {\n'
            "  policy = jsonencode({\n"
            '    Statement = [{ Effect = "Allow", Action = ["s3:*"], Resource = "arn:aws:s3:::b" }]\n'
            "  })\n"
            "}\n"
        )
        findings = scan_iac_with_context(tf).findings
        assert _lines(findings, "TF-SEC-010") == [3]
        assert _lines(findings, "TF-SEC-004") == []
