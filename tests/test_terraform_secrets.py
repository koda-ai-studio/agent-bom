"""Terraform hardcoded-secret detection: real literals are caught, metadata is not."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.terraform import _detect_hardcoded_secrets, _read_tf_files

ROOT = Path(__file__).resolve().parents[1]


def _detect(tmp_path: Path, body: str) -> list[str]:
    tf = tmp_path / "main.tf"
    tf.write_text(body, encoding="utf-8")
    return [secret.variable_name for secret in _detect_hardcoded_secrets([(tf, tf.read_text())])]


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        (
            'variable "openai_api_key" {\n  type    = string\n  default = "' + "sk-" + "abc123realkey4567890123" + '"\n}\n',
            ["openai_api_key"],
        ),
        (
            'variable "db_password" {\n  description = "Database password."\n  sensitive = true\n  default = "Hunter2Hunter2!"\n}\n',
            ["db_password"],
        ),
        ('resource "x" "y" {\n  api_token = "' + "ghp" + "_0123456789abcdefABCDEF" + '"\n}\n', ["API_TOKEN"]),
        ('locals {\n  anthropic_key = "' + "sk-" + "ant-api03-0123456789abcdef" + '"\n}\n', ["ANTHROPIC_KEY"]),
    ],
)
def test_real_secret_literals_are_flagged(tmp_path, body, expected):
    assert _detect(tmp_path, body) == expected


@pytest.mark.parametrize(
    "body",
    [
        # A description is documentation, not the default value.
        'variable "create_auth_secret" {\n  description = "Whether to create an empty Secrets Manager secret container."\n'
        "  type = bool\n  default = true\n}\n",
        'variable "api_key" {\n  description = "API key used by the collector, supplied at apply time."\n  type = string\n}\n',
        # Names that reference a secret rather than hold one.
        'variable "auth_secret_name" {\n  type = string\n  default = "agent-bom/control-plane/auth"\n}\n',
        'variable "api_key_secret_name" {\n  type = string\n  default = "agent-bom-api-key"\n}\n',
        'variable "key_vault_secret_reader_principal_ids" {\n  type = list(string)\n  default = []\n}\n',
        'variable "federated_credential_audience" {\n  type = string\n  default = "api://AzureADTokenExchange"\n}\n',
        'variable "runtime_credentials_generation" {\n  type = string\n  default = "generation-0001"\n}\n',
        'variable "backup_secret_arn" {\n  type = string\n  default = "arn:aws:secretsmanager:us-east-1:111122223333:secret:x"\n}\n',
        # Interpolations and references are not literals.
        'resource "kubernetes_manifest" "tls" {\n  secretName = "${var.name}-control-plane-tls"\n}\n',
        'resource "x" "y" {\n  password = "${random_password.db.result}"\n}\n',
        # A sentence assigned to a credential-named key is prose, not a key.
        'resource "x" "y" {\n  token = "rotate this token every ninety days"\n}\n',
        # Placeholders stay unflagged.
        'variable "openai_api_key" {\n  default = "placeholder"\n}\n',
    ],
)
def test_metadata_and_references_are_not_flagged(tmp_path, body):
    assert _detect(tmp_path, body) == []


def test_description_before_a_real_default_reports_the_default(tmp_path):
    body = 'variable "service_token" {\n  description = "Service token used for webhook calls."\n  default = "tok_live_0123456789abcd"\n}\n'
    assert _detect(tmp_path, body) == ["service_token"]


def test_repository_terraform_has_no_hardcoded_secret_findings():
    directories = sorted({path.parent for path in (ROOT / "deploy" / "terraform").rglob("*.tf")})
    assert directories, "deploy/terraform has no Terraform modules"
    findings = [
        f"{directory.relative_to(ROOT)}/{secret.file}:{secret.line} {secret.variable_name}"
        for directory in directories
        for secret in _detect_hardcoded_secrets(_read_tf_files(directory))
    ]
    assert findings == []
