"""Secret rules judge the value on the line: code reading a secret holds no secret."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from agent_bom.scanners.secret_lines import match_credential, match_file_secret, scan_text
from agent_bom.secret_scanner import scan_content

GITHUB_SHAPED = "gh" + "p_" + "a1B2c3D4" * 5
GOOGLE_SHAPED = "AI" + "za" + "b" * 35
AWS_SHAPED = "AK" + "IA" + "QWERTYUIOP234567"

_LONG_VALUE = "abc123" + "def456ghi789jkl012"
_PLAIN_VALUE = "plain" + "fixture7"
_MIXED_VALUE = "Xy7-Qz9" + "-fixture"
_SHORT_VALUE = "abcd1234" + "efgh5678"
_PHRASE_VALUE = "Tr0ub4dor" + "-fixture-7"


def _types(name: str, text: str) -> list[str]:
    return [finding.secret_type for finding in scan_content(text, Path(name), name)]


@pytest.mark.parametrize(
    "line",
    [
        'cohere_api_key = get_from_dict_or_env(values, "cohere_api_key", "COHERE_API_KEY")',
        "self.mathpix_api_key = get_from_dict_or_env(",
        "gitlab_personal_access_token = get_from_dict_or_env(",
        "client = Wrapper(openweathermap_api_key=openweathermap_api_key)",
        "api_key=self.minimax_api_key,",
        "base_url=self.gateway_uri, api_key=self.javelin_api_key",
        'const apiKey = await resolveProviderApiKeyFromStore("x")',
        "apiKey: this.providerSettings.upstreamApiKey,",
        'String apiKey = System.getenv("PROVIDER_API_KEY");',
    ],
)
def test_code_reading_a_key_is_not_a_hardcoded_key(line):
    assert match_credential(line, code_file=True) is None


@pytest.mark.parametrize(
    "line",
    [
        'api_key = "abcdefghijklmnopqrstuvwxyz"',
        f"api_key = '{_LONG_VALUE}'",
        'URL = "https://api.invalid/v1?api_key=abcdefghijklmnopqrstuvwxyz"',
        f"api_key={_LONG_VALUE}",
        "api_key=abc-def-ghi-jkl-mno-pqr-stu",
    ],
)
def test_literals_in_code_files_still_report(line):
    assert match_credential(line, code_file=True) is not None


@pytest.mark.parametrize(
    "line",
    [
        "API_KEY=abcdefghijklmnopqrstuvwxyz",
        "api_key: abcdefghijklmnopqrstuvwxyz_value",
        "export ACCESS_TOKEN=provider_session_value_abc",
    ],
)
def test_bare_values_in_config_files_are_literals(line):
    assert match_credential(line, code_file=False) is not None


@pytest.mark.parametrize(
    "line",
    [
        'api_key=lookup_the_provider_service_key("x")',
        "api_key=self.provider_service_key",
        "apiKey: process.env.PROVIDER_SERVICE_KEY",
        "upstream_api_key=upstream_service_api_key",
    ],
)
def test_unmistakable_references_are_recognized_in_any_file(line):
    assert match_credential(line, code_file=False) is None


def test_a_real_format_passed_to_a_lookup_call_is_still_found():
    assert match_credential(f'x_api_key = lookup_value_from_env("{GOOGLE_SHAPED}")', code_file=True) is not None
    assert match_credential(f'cohere_api_key = get_from_dict_or_env(values, "k", "{AWS_SHAPED}")', code_file=True) is not None
    assert _types("settings.py", f'x_api_key = lookup_value_from_env("{GITHUB_SHAPED}")') == ["GitHub Token"]


@pytest.mark.parametrize(
    "line",
    [
        'DB_PASSWORD = os.environ["DB_PASSWORD"]',
        'DB_PASSWORD = os.getenv("DB_PASSWORD")',
        "ACCESS_TOKEN = fetch_access_token()",
        "SESSION_SECRET = settings.session_secret",
    ],
)
def test_env_style_rules_do_not_report_code(line):
    assert match_file_secret(line, code_file=True) is None


def test_env_style_rules_still_report_a_literal():
    assert match_file_secret(f"DB_PASSWORD={_PLAIN_VALUE}") is not None
    assert match_file_secret(f'DB_PASSWORD = "{_PLAIN_VALUE}"', code_file=True) is not None


@pytest.mark.parametrize(
    "line",
    [
        '"LABEL_PASSWORD": "Mevcut Parola",',
        '"LABEL_NEW_PASSWORD": "Nouveaumotdepasse",',
        '"MANDATORY_PASSWORD": "Bitte gib ein Passwort ein",',
        '"LABEL_REPEAT_PASSWORD": "現在のパスワード",',
        '"FORGOT_PASSWORD": "¿Olvidaste tu contraseña?",',
        '"MANDATORY_PASSWORD": "Fournissez un mot de passe s\'il vous plaît.",',
    ],
)
def test_translation_labels_are_not_passwords(line):
    assert match_file_secret(line, translation_file=True) is None


@pytest.mark.parametrize(
    "line",
    [
        f'"support_password": "{_MIXED_VALUE}",',
        '"password": "Tr0ub4dor&3xyz",',
        f'"secret": "{_SHORT_VALUE}",',
    ],
)
def test_secret_shaped_values_in_translation_files_still_report(line):
    assert match_file_secret(line, translation_file=True) is not None


def test_label_keys_and_label_values_outside_translation_files():
    assert match_file_secret('LABEL_PASSWORD: "Current password value",') is None
    assert match_file_secret('forgotPassword: "Forgot your password?",') is None
    assert match_file_secret('password: "correct horse battery staple",') is not None
    assert match_file_secret(f'LABEL_PASSWORD: "{_PHRASE_VALUE}",') is not None


def test_translation_rule_applies_by_directory_and_only_to_the_label_rules(tmp_path):
    text = f'{{"LABEL_PASSWORD": "Mot de passe actuel", "token": "{GITHUB_SHAPED}"}}'
    assert _types("src/assets/i18n/fr.json", text) == ["GitHub Token"]
    assert _types("data/static/locales/de_DE.yaml", 'LABEL_PASSWORD: "Aktuelles Passwort"') == []
    assert _types("config/app.json", '{"password": "Mot de passe actuel"}') == ["Hardcoded password"]


@pytest.mark.parametrize(
    ("name", "line"),
    [
        ("config/app.yml", "image: 'https://cdn.invalid/products/123456789.jpg'"),
        ("config/app.yml", "url: https://store.invalid/filedetails/?id=1969196030"),
        ("config/app.yml", "thumb: assets/images/123-45-6789.png"),
        ("data/app.json", '"logo": "/assets/public/images/products/415-555-0199.svg",'),
        ("data/app.json", '"text": "see <a href=\\"https://store.invalid/x/?id=1970691216\\">here</a>"'),
    ],
)
def test_personal_data_patterns_do_not_match_inside_urls_or_asset_paths(name, line):
    assert _types(name, line) == []


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("ssn: 123-45-6789", "US SSN"),
        ("phone: 415-555-0199", "US Phone Number"),
        ("callback: https://api.invalid/lookup?ssn=123-45-6789", "US SSN"),
        ("contact: jane.doe@mail.invalid", "Email Address"),
        ("contact: mailto:jane.doe@mail.invalid", "Email Address"),
    ],
)
def test_personal_data_outside_a_locator_still_reports(line, expected):
    assert _types("config/app.yml", line) == [expected]


def test_locator_check_stays_fast_on_one_long_line():
    line = ",".join(f'"https://cdn.invalid/products/{index:09d}.jpg"' for index in range(40_000))
    started = time.perf_counter()
    assert _types("data/catalog.json", line) == []
    assert time.perf_counter() - started < 20


def test_scan_text_keeps_judging_instruction_files_conservatively():
    assert [row.secret_type for row in scan_text("api_key=abcdefghijklmnopqrstuvwxyz")] == ["Generic API Key"]
    assert list(scan_text("api_key=self.provider_service_key")) == []
