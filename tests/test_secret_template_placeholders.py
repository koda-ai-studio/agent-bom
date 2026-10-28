"""Template expressions, format verbs and key-name literals are not hardcoded credentials.

A config template renders ``{{ .Env.PASSWORD }}`` at deploy time, a Go format
string fills ``%v`` at run time, and ``CLIOptPassword = "password"`` names a
flag. None of them hold a credential. Findings under a test-fixture directory
such as ``testdata/`` are kept, downgraded to ``low`` with a stated reason, so
nothing is hidden.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.finding import secret_dict_to_finding
from agent_bom.iac.terraform_security import scan_terraform_security
from agent_bom.scanners.secret_lines import is_placeholder_value, scan_text
from agent_bom.secret_scanner import scan_secrets

# Assembled at runtime so no credential-shaped literal lives in the repo.
_REAL_PASSWORD = "s3cr3t" + "-Value_" + "9"
_REAL_DSN = "postgres://" + "admin:" + "S3cr3t" + "Pass" + "@db.internal:5432/app"
_LONG_TOKEN = "".join(chr(ord("a") + (i * 7) % 26) if i % 3 else str(i % 10) for i in range(40))


@pytest.mark.parametrize(
    "value",
    [
        '{{ default .Env.CASSANDRA_PASSWORD "" }}',
        "{{ $visibility_pwd }}",
        "{{ .Values.db.password }}",
        "${DB_PASSWORD}",
        "${var.db_password}",
        "$DB_PASSWORD",
        "%v",
        "%s",
        "%d",
        "%q",
        "%(password)s",
        "{}",
        "{password}",
        "<password>",
        "<your-token>",
        "password",
        "PASSWORD",
        "passwd",
        "secret",
        "token",
        "api_key",
        "api-key",
        "access_token",
    ],
)
def test_template_and_key_name_values_are_placeholders(value: str) -> None:
    assert is_placeholder_value(value)


@pytest.mark.parametrize(
    "value",
    [
        _REAL_PASSWORD,
        _LONG_TOKEN,
        "abc{{" + _LONG_TOKEN + "}}",
        _LONG_TOKEN + "%v",
        "$" + _LONG_TOKEN + "!x",
        "password1234",
        "secret-sauce-9",
        "%",
        "{{",
        "{{ unterminated",
    ],
)
def test_real_shaped_values_are_not_placeholders(value: str) -> None:
    assert not is_placeholder_value(value)


@pytest.mark.parametrize(
    "line",
    [
        'password: "{{ default .Env.CASSANDRA_PASSWORD "" }}"',
        'password: "{{ $visibility_pwd }}"',
        "password: {{ $visibility_pwd }}",
        'password: "${DB_PASSWORD}"',
        'password: "$DB_PASSWORD"',
        "DB_PASSWORD={{ .Values.password }}",
        'dsn := fmt.Sprintf("postgres://%v:%v@%v/%v?%v", user, pw, host, db, params)',
        'url = "mysql://%s:%s@%s/%s"',
        'url = "postgres://admin:%s@db.internal/app"',
        'CLIOptPassword = "password"',
        'secret = "secret"',
        'token = "<your-token>"',
    ],
)
def test_template_lines_produce_no_finding(line: str) -> None:
    assert list(scan_text(line)) == []


@pytest.mark.parametrize(
    "line, severity",
    [
        (f'password: "{_REAL_PASSWORD}"', "high"),
        (f'url = "{_REAL_DSN}"', "critical"),
        (f'password = "abc{{{{{_LONG_TOKEN}}}}}"', "high"),
        (f'api_key = "{_LONG_TOKEN}{{{{x}}}}"', "critical"),
        (f'password = "{{{{ {_REAL_PASSWORD}"', "high"),
    ],
)
def test_real_secrets_next_to_template_syntax_stay_reported(line: str, severity: str) -> None:
    found = list(scan_text(line))
    assert found and found[0].severity == severity


def _write_tree(root: Path) -> None:
    (root / "config.yaml").write_text(
        "cassandra:\n"
        '  password: "{{ default .Env.CASSANDRA_PASSWORD "" }}"\n'
        "visibility:\n"
        '  password: "{{ $visibility_pwd }}"\n'
        f'  control_password: "{_REAL_PASSWORD}"\n',
        encoding="utf-8",
    )
    (root / "db.go").write_text(
        "package db\n\n"
        'const CLIOptPassword = "password"\n\n'
        'var dsn = fmt.Sprintf("postgres://%v:%v@%v/%v?%v", u, p, h, d, q)\n'
        f'var controlDSN = "{_REAL_DSN}"\n',
        encoding="utf-8",
    )
    fixture = root / "pkg" / "testdata"
    fixture.mkdir(parents=True)
    (fixture / "fixture.yaml").write_text(f'password: "{_REAL_PASSWORD}"\nurl: "{_REAL_DSN}"\n', encoding="utf-8")


def test_tree_reports_only_controls_and_downgrades_testdata(tmp_path: Path) -> None:
    _write_tree(tmp_path)

    result = scan_secrets(tmp_path)

    by_file: dict[str, list] = {}
    for finding in result.findings:
        by_file.setdefault(finding.file_path, []).append(finding)

    assert [(f.line_number, f.secret_type, f.severity) for f in by_file["config.yaml"]] == [(5, "Hardcoded password", "high")]
    assert [(f.line_number, f.secret_type, f.severity) for f in by_file["db.go"]] == [(6, "Connection String", "critical")]
    fixture_path = str(Path("pkg") / "testdata" / "fixture.yaml")
    fixture_findings = by_file[fixture_path]
    assert {f.severity for f in fixture_findings} == {"low"}
    assert {f.secret_type for f in fixture_findings} == {"Hardcoded password", "Connection String"}
    assert all(f.downgrade_reason and "testdata" in f.downgrade_reason for f in fixture_findings)
    assert all(f.downgrade_reason is None for f in by_file["config.yaml"] + by_file["db.go"])
    assert set(by_file) == {"config.yaml", "db.go", fixture_path}
    assert result.files_scanned == 3
    blob = str(result.to_dict())
    assert _REAL_PASSWORD not in blob and "S3cr3t" not in blob
    assert "downgrade_reason" in blob


def test_downgrade_reason_reaches_the_unified_finding() -> None:
    row = {
        "file": "pkg/testdata/fixture.yaml",
        "line": 1,
        "type": "Hardcoded password",
        "severity": "low",
        "preview": "[SECRET_REDACTED]",
        "category": "secret",
        "downgrade_reason": "test fixture path (testdata)",
    }
    finding = secret_dict_to_finding(row)
    assert finding.severity == "low"
    assert finding.evidence["downgrade_reason"] == "test fixture path (testdata)"


@pytest.mark.parametrize("value", ['"%s"', '"{{ .Values.password }}"', '"$DB_PASSWORD"', '"password"'])
def test_terraform_shares_the_template_placeholder_rejection(tmp_path: Path, value: str) -> None:
    tf = tmp_path / "main.tf"
    tf.write_text(f'resource "aws_db_instance" "main" {{\n  password = {value}\n}}\n', encoding="utf-8")
    assert [f for f in scan_terraform_security(tf) if f.rule_id == "TF-SEC-051"] == []
