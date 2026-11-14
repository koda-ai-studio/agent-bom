"""Identifier-shaped values are not secrets; loopback CI DSNs are kept but lowered."""

from pathlib import Path

import pytest

from agent_bom.secret_scanner import scan_content


def _secrets(source: str, path: str) -> list:
    return [f for f in scan_content(source, Path(path), path) if f.category in {"secret", "credential"}]


def _pw(*parts: str) -> str:
    return "".join(parts)


@pytest.mark.parametrize(
    ("source", "path"),
    [
        ('  secret: "bg-ink-secondary opacity-60",', "ui/components/overview/issue-strip.tsx"),
        ("export const BAR = {\n  secret: 'flex items-center text-ink-secondary',\n};", "ui/bar.tsx"),
        ('    "hardcoded_secret": "data_access",', "src/pkg/behavior.py"),
        ('    "secret_scope": "workspace-admin-only",', "src/pkg/scopes.py"),
        ("const KIND = { client_secret: 'token_exchange' };", "ui/lib/kinds.ts"),
        ('  secret: "bg-ink-secondary opacity-60"', "config/theme.yaml"),
    ],
)
def test_class_lists_and_identifiers_are_not_secrets(source, path):
    assert _secrets(source, path) == []


@pytest.mark.parametrize(
    ("source", "path"),
    [
        ('PASSWORD="' + _pw("regression-", "fixture-", "password") + '"', ".env"),
        ('  client_secret: "' + _pw("token_", "exchange") + '"', "config/app.yaml"),
        ('db_password = "' + _pw("staging-", "admin-", "pass") + '"', "src/pkg/settings.py"),
    ],
)
def test_word_phrase_values_in_config_or_password_keys_still_report(source, path):
    assert _secrets(source, path), source


@pytest.mark.parametrize(
    "value",
    [
        _pw("Zq8", "vR2m", "Lp9x", "Tq4w"),
        _pw("s3cr", "et-Pa", "ss!", "2024"),
        _pw("prod", "_", "Xk29", "_", "db"),
        _pw("correct ", "horse ", "battery ", "staple"),
    ],
)
@pytest.mark.parametrize("key", ["secret", "password", "hardcoded_secret"])
def test_real_looking_secrets_still_report(key, value):
    source = f'{key} = "{value}"'
    assert _secrets(source, "src/pkg/settings.py"), source


def _dsn(user: str, password: str, host: str) -> str:
    return "postgresql://" + user + ":" + password + "@" + host + ":5432/agent_bom"


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "[::1]", "127.0.0.53"])
@pytest.mark.parametrize("path", [".github/workflows/ci.yml", ".github/workflows/scale.yaml", ".gitlab-ci.yml"])
def test_loopback_dsn_in_ci_workflow_is_downgraded_not_dropped(path, host):
    source = "      DATABASE_URL: " + _dsn("app", _pw("app", "pass", "91"), host)
    findings = _secrets(source, path)
    assert [f.secret_type for f in findings] == ["Connection String"]
    assert findings[0].severity == "low"
    assert "loopback" in (findings[0].downgrade_reason or "")


@pytest.mark.parametrize(
    ("path", "host"),
    [
        (".github/workflows/ci.yml", "db.internal.corp"),
        (".github/workflows/ci.yml", "10.0.4.12"),
        ("deploy/values.yaml", "127.0.0.1"),
        ("src/app/settings.py", "localhost"),
    ],
)
def test_remote_or_non_ci_dsn_keeps_critical(path, host):
    source = "DATABASE_URL = '" + _dsn("app", _pw("app", "pass", "91"), host) + "'"
    findings = _secrets(source, path)
    assert [f.severity for f in findings if f.secret_type == "Connection String"] == ["critical"]
