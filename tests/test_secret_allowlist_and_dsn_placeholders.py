"""Secret-scanner allowlists and generic DSN samples are labelled or dropped, never reported as live leaks."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.secret_scanner import scan_content, scan_secrets


def _credentials(source: str, rel_path: str) -> list:
    return [f for f in scan_content(source, Path(rel_path), rel_path) if f.category in {"credential", "secret"}]


def test_values_in_a_gitleaks_allowlist_are_lowered_and_labelled(tmp_path: Path) -> None:
    pw = "Tr0ub4dor" + "-fixture-7"
    (tmp_path / ".gitleaks.toml").write_text(f"[allowlist]\nregexes = [\n  '''admin_password = \"{pw}\"''',\n]\n", encoding="utf-8")
    findings = [f for f in scan_secrets(tmp_path).findings if f.file_path == ".gitleaks.toml"]
    assert findings, "the allowlisted value is still recorded"
    assert {f.severity for f in findings} == {"low"}
    assert all("allowlist" in (f.downgrade_reason or "") for f in findings)


def test_the_same_value_outside_an_allowlist_keeps_its_severity() -> None:
    pw = "Tr0ub4dor" + "-fixture-7"
    findings = _credentials(f'admin_password = "{pw}"\n', "settings.toml")
    assert findings and {f.severity for f in findings} != {"low"}


@pytest.mark.parametrize(
    "line",
    [
        "- A password in a connection string (`postgresql://user:pass@host`) is a credential.",
        "Placeholder examples (`SECRET_KEY = 'development key'`) are no longer reported.",
    ],
)
@pytest.mark.parametrize("name", ["CHANGELOG.md", "docs/guide.rst"])
def test_plain_word_samples_in_prose_documentation_are_not_credentials(line: str, name: str) -> None:
    assert _credentials(line + "\n", name) == []


@pytest.mark.parametrize(
    ("line", "name"),
    [
        ("Set `postgresql://svc:Hx7pq2Lr9@db.internal/prod` in production.", "CHANGELOG.md"),
        ('URI = "postgresql://user:pass@db.internal/prod"', "settings.py"),
    ],
)
def test_specific_values_in_docs_and_plain_words_in_code_still_report(line: str, name: str) -> None:
    assert [f.secret_type for f in _credentials(line + "\n", name)] == ["Connection String"]
