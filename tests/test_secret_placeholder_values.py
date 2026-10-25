"""Obvious placeholder values in example config are not hardcoded-credential findings."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.secret_scanner import scan_secrets


def _scan(tmp_path: Path, line: str):
    (tmp_path / "config.py").write_text(line + "\n", encoding="utf-8")
    return scan_secrets(str(tmp_path)).findings


@pytest.mark.parametrize(
    "line",
    [
        'api_key = "REPLACE_WITH_YOUR_API_KEY"',
        'headers = {"Authorization": "Bearer your-token-here"}',
        'access_token = "YOUR_ACCESS_TOKEN_HERE"',
        'api_key = "insert-your-api-key-here"',
        'api_key = "xxxxxxxxxxxxxxxxxxxxxxxx"',
        'api_key = "<your-openai-api-key>"',
        'api_key = "changeme-changeme-changeme"',
        'api_key = "example-api-key-for-docs-only"',
        'api_key = "dummy-api-key-value-1234"',
        'api_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"',
        'api_key = "0000000000000000000000000000"',
        'password = "REPLACE_ME_PLEASE"',
        'headers = {"Authorization": "Bearer <token>"}',
    ],
)
def test_placeholder_values_are_not_reported(tmp_path: Path, line: str) -> None:
    assert _scan(tmp_path, line) == []


def _real_shaped_lines() -> list[str]:
    body = "".join(chr(ord("a") + (i * 7) % 26) if i % 3 else str(i % 10) for i in range(32))
    return [
        f'api_key = "{body}"',
        f'headers = {{"Authorization": "Bearer {body}"}}',
        f'password = "{body[:14]}"',
        "openai_key = " + '"' + "sk-" + "proj-" + body + body[:16] + '"',
    ]


@pytest.mark.parametrize("line", _real_shaped_lines())
def test_real_looking_values_are_still_reported(tmp_path: Path, line: str) -> None:
    findings = _scan(tmp_path, line)

    assert findings
    assert findings[0].severity in {"critical", "high"}
