"""Precision/recall pins for the planted-issue corpus in ``fixtures/iac_accuracy``.

Every planted issue is asserted at its exact line, and every planted
look-alike (scoped policy, private bucket, safe workflow, ...) is asserted to
stay quiet, so a regression in either direction fails here.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

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


class TestTerraformPublicS3:
    def test_bucket_acl_resource_and_disabled_public_access_flags_are_detected(self) -> None:
        findings = _scan("terraform/s3.tf")
        assert _lines(findings, "TF-SEC-002") == [7]
        assert _lines(findings, "TF-SEC-022") == [12]

    def test_private_bucket_with_full_block_is_not_flagged_public(self) -> None:
        findings = _scan("terraform/s3.tf")
        public = [f for f in findings if f.rule_id in {"TF-SEC-002", "TF-SEC-022"} and f.line_number >= 18]
        assert public == []

    def test_block_for_another_bucket_does_not_cover_this_one(self, tmp_path: Path) -> None:
        tf = tmp_path / "other.tf"
        tf.write_text(
            'resource "aws_s3_bucket" "a" {\n  bucket = "a"\n}\n'
            'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n'
            'resource "aws_s3_bucket_public_access_block" "a" {\n'
            "  bucket                  = aws_s3_bucket.a.id\n"
            "  block_public_acls       = true\n"
            "  block_public_policy     = true\n"
            "  ignore_public_acls      = true\n"
            "  restrict_public_buckets = true\n"
            "}\n"
        )
        findings = scan_iac_with_context(tf).findings
        assert _lines(findings, "TF-SEC-022") == [4]


class TestCompose:
    def test_every_planted_compose_issue_is_reported_at_its_line(self) -> None:
        findings = _scan("compose")
        by_line = {f.line_number: f.rule_id for f in findings}
        assert by_line == {
            4: "COMPOSE-001",
            5: "COMPOSE-003",
            6: "COMPOSE-004",
            8: "COMPOSE-005",
            10: "COMPOSE-002",
            12: "COMPOSE-006",
            16: "COMPOSE-005",
            18: "COMPOSE-006",
        }
        assert all(f.file_path == "docker-compose.yml" and f.category == "compose" for f in findings)

    def test_secret_findings_name_the_variable_never_the_value(self) -> None:
        secrets = [f for f in _scan("compose") if f.rule_id == "COMPOSE-006"]
        assert {"DATABASE_PASSWORD", "API_TOKEN"} <= {word for f in secrets for word in f.message.replace("'", " ").split()}
        assert all("REPLACE_ME" not in f.message and "REPLACE_ME" not in f.title for f in secrets)

    def test_interpolated_secret_is_not_hardcoded(self, tmp_path: Path) -> None:
        compose = tmp_path / "compose.yaml"
        compose.write_text("services:\n  a:\n    image: x:1\n    environment:\n      DB_PASSWORD: ${DB_PASSWORD}\n")
        assert [f for f in scan_iac_with_context(compose).findings if f.rule_id == "COMPOSE-006"] == []

    def test_compose_scanner_verdict_ran(self) -> None:
        verdicts = {v.scanner_id: v for v in scan_iac_with_context(FIXTURE / "compose").verdicts}
        assert verdicts["compose"].status == "ran"
        assert verdicts["compose"].files_scanned == 1

    def test_unrecognised_explicit_file_is_not_evaluated_rather_than_clean(self, tmp_path: Path) -> None:
        other = tmp_path / "settings.yaml"
        other.write_text("feature: true\n")
        result = scan_iac_with_context(other)
        assert result.findings == []
        assert result.not_evaluated == ["settings.yaml"]
        assert all(v.status != "ran" for v in result.verdicts)


class TestGitHubActionsFindings:
    def test_planted_workflow_issues_are_findings_with_lines(self) -> None:
        findings = [f for f in _scan(".github") if f.file_path.endswith("ci.yml")]
        assert {(f.rule_id, f.line_number, f.severity) for f in findings} == {
            ("GHA-001", 11, "high"),
            ("GHA-002", 9, "medium"),
            ("GHA-003", 15, "high"),
            ("GHA-003", 18, "high"),
            ("GHA-004", 1, "low"),
        }
        assert all(f.category == "github_actions" for f in findings)

    def test_write_all_permissions_is_flagged_at_its_line(self) -> None:
        findings = [f for f in _scan(".github") if f.file_path.endswith("wide.yml")]
        assert [(f.rule_id, f.line_number, f.severity) for f in findings] == [("GHA-004", 3, "medium")]

    def test_hardened_workflow_is_clean(self) -> None:
        assert [f for f in _scan(".github") if f.file_path.endswith("safe.yml")] == []

    def test_findings_paths_are_repository_relative(self) -> None:
        paths = {f.file_path for f in _scan(".github")}
        assert paths == {"workflows/ci.yml", "workflows/wide.yml"}

    def test_explicit_workflow_file_is_evaluated(self) -> None:
        result = scan_iac_with_context(FIXTURE / ".github" / "workflows" / "ci.yml")
        assert result.not_evaluated == []
        assert {f.rule_id for f in result.findings} == {"GHA-001", "GHA-002", "GHA-003", "GHA-004"}


class TestKubernetesLines:
    def test_findings_point_at_the_offending_key_in_the_second_document(self) -> None:
        findings = _scan("k8s")
        assert _lines(findings, "K8S-001") == [20]
        assert _lines(findings, "K8S-011") == [18]
        assert _lines(findings, "K8S-014") == [26]
        assert _lines(findings, "K8S-004") == [17]

    def test_no_deployment_finding_falls_back_to_line_one(self) -> None:
        assert [f.rule_id for f in _scan("k8s") if f.line_number < 8] == []

    def test_env_secret_and_capability_lines(self, tmp_path: Path) -> None:
        manifest = tmp_path / "pod.yaml"
        manifest.write_text(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers:\n    - name: c\n      image: x:1\n"
            "      env:\n        - name: DB_PASSWORD\n          value: literal-value\n"
            "      securityContext:\n        capabilities:\n          add: [NET_RAW]\n"
        )
        findings = scan_iac_with_context(manifest).findings
        assert _lines(findings, "K8S-007") == [10]
        assert _lines(findings, "K8S-018") == [14]


class TestHelmTemplates:
    def _chart_findings(self, findings: list[IaCFinding]) -> set[tuple[str, int]]:
        return {(f.rule_id, f.line_number) for f in findings if f.file_path == "templates/deployment.yaml"}

    def test_textual_fallback_finds_privileged_and_host_network_and_says_rendering_skipped(self, monkeypatch) -> None:
        monkeypatch.setattr("agent_bom.iac.helm_templates.shutil.which", lambda _name: None)
        result = scan_iac_with_context(FIXTURE / "chart")
        assert {("K8S-002", 8), ("K8S-001", 13)} <= self._chart_findings(result.findings)
        helm = next(v for v in result.verdicts if v.scanner_id == "helm")
        assert helm.status == "ran"
        assert "rendering skipped" in helm.reason

    @pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")
    def test_rendered_chart_maps_findings_back_to_template_lines(self) -> None:
        result = scan_iac_with_context(FIXTURE / "chart")
        assert {("K8S-002", 8), ("K8S-001", 13)} <= self._chart_findings(result.findings)
        helm = next(v for v in result.verdicts if v.scanner_id == "helm")
        assert "rendered with helm template" in helm.reason

    def test_template_files_are_not_counted_as_clean_kubernetes(self, monkeypatch) -> None:
        monkeypatch.setattr("agent_bom.iac.helm_templates.shutil.which", lambda _name: None)
        verdicts = {v.scanner_id: v for v in scan_iac_with_context(FIXTURE / "chart").verdicts}
        assert verdicts["kubernetes"].status == "not-applicable"
