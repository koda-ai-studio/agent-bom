"""TF-SEC-051: literal secrets in Terraform resource arguments."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.iac.terraform_security import scan_terraform_security

# Assembled at runtime so no credential-shaped literal lives in the repo.
LITERAL = "Rds" + "Pass" + "-" + "4821" + "q"


def _scan(tmp_path: Path, body: str) -> list:
    tf = tmp_path / "main.tf"
    tf.write_text(body, encoding="utf-8")
    return [f for f in scan_terraform_security(tf) if f.rule_id == "TF-SEC-051"]


def test_rds_literal_password_is_reported_on_its_line(tmp_path: Path) -> None:
    body = f'resource "aws_db_instance" "main" {{\n  engine   = "postgres"\n  username = "app"\n  password = "{LITERAL}"\n}}\n'
    findings = _scan(tmp_path, body)
    assert [(f.line_number, f.severity) for f in findings] == [(4, "critical")]
    assert LITERAL not in findings[0].message
    assert "password" in findings[0].message


@pytest.mark.parametrize(
    "arg",
    ["master_password", "secret", "token", "access_key", "private_key", "admin_password", "client_secret"],
)
def test_each_secret_argument_name_is_reported(tmp_path: Path, arg: str) -> None:
    body = f'resource "aws_rds_cluster" "c" {{\n  engine = "aurora"\n\n  {arg} = "{LITERAL}"\n}}\n'
    assert [f.line_number for f in _scan(tmp_path, body)] == [4]


def test_nested_block_secret_is_reported_once_per_argument(tmp_path: Path) -> None:
    body = f'resource "aws_instance" "web" {{\n  connection {{\n    password    = "{LITERAL}"\n    private_key = "{LITERAL}x"\n  }}\n}}\n'
    assert [f.line_number for f in _scan(tmp_path, body)] == [3, 4]


@pytest.mark.parametrize(
    "value",
    [
        "var.db_password",
        "data.aws_ssm_parameter.db.value",
        "random_password.db.result",
        "aws_secretsmanager_secret_version.db.secret_string",
        'jsondecode(aws_secretsmanager_secret_version.db.secret_string)["password"]',
        '"${var.db_password}"',
        '"${random_password.db.result}"',
        '""',
        '"changeme"',
        '"<password>"',
        '"REPLACE_ME"',
        '"xxxxxxxx"',
        '"your-password-here"',
        "null",
    ],
)
def test_references_and_placeholders_are_not_reported(tmp_path: Path, value: str) -> None:
    body = f'resource "aws_db_instance" "main" {{\n  password = {value}\n}}\n'
    assert _scan(tmp_path, body) == []


def test_non_secret_arguments_and_secret_lookalike_names_are_not_reported(tmp_path: Path) -> None:
    body = (
        'resource "aws_db_instance" "main" {\n'
        '  manage_master_user_password = "true"\n'
        '  password_wo_version = "1"\n'
        '  token_validity_units = "hours"\n'
        f'  description = "{LITERAL}"\n'
        "}\n"
    )
    assert _scan(tmp_path, body) == []


def test_commented_out_secret_is_not_reported(tmp_path: Path) -> None:
    body = f'resource "aws_db_instance" "main" {{\n  # password = "{LITERAL}"\n  password = var.p\n}}\n'
    assert _scan(tmp_path, body) == []
