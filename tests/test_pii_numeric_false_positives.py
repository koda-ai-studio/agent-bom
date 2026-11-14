"""Plain numbers are not phone or card numbers; formatted and Luhn-valid values still are.

Test card numbers are published network test values assembled at runtime so no
real-shaped value is committed as a literal.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.proxy_scanner import redact_pii
from agent_bom.runtime.detectors import CredentialLeakDetector
from agent_bom.runtime.patterns import luhn_valid
from agent_bom.secret_scanner import scan_content

_VISA_TEST = "4111" + "1111" * 3
_VISA_BAD_CHECKSUM = _VISA_TEST[:-1] + "2"
_MC_TEST = "5555" + "5555" + "5555" + "4444"
_PHONE = "-".join(("415", "555", "0132"))


def _pii(content: str, name: str = "data.json") -> list[str]:
    findings = scan_content(content, Path(name), name)
    return [f.secret_type for f in findings if f.category == "pii"]


@pytest.mark.parametrize(
    "line",
    [
        '{"ms": 3.4000000953674316}',
        '{"maximum": 1000000000}',
        '{"fetched_at": 1784399059.28}',
        '{"fetched_at": 1793377325.794105}',
        '{"wal_bytes": 1004060472}',
        '{"plan": [9.4990234375, 1.0]}',
        '{"account_scope": "11111111-2222-3333-4444-555555555555"}',
        '{"overview": "a non-canonical spelling such as 0177.0.0.1, 2130706433 or 127.1"}',
        '{"value": 4111111111111111e3}',
    ],
)
def test_plain_numbers_in_json_are_not_pii(line: str) -> None:
    assert _pii(line) == []


@pytest.mark.parametrize("line", ["maximum: 1000000000", "fetched_at: 1784399059.286154", "ratio: 3.4000000953674316"])
def test_plain_numbers_in_yaml_are_not_pii(line: str) -> None:
    assert _pii(line, "config.yaml") == []


@pytest.mark.parametrize(
    "line",
    [
        f'{{"phone": "{_PHONE}"}}',
        f'{{"phone": {_PHONE.replace("-", "")}}}',
        f'{{"contact": "({_PHONE[:3]}) {_PHONE[4:]}"}}',
        f'{{"mobile_number": "{_PHONE.replace("-", "")}"}}',
    ],
)
def test_real_phone_numbers_in_json_are_still_found(line: str) -> None:
    assert _pii(line) == ["US Phone Number"]


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (f'{{"card_number": "{_VISA_TEST}"}}', "Credit Card (Visa)"),
        (f'{{"note": "{" ".join(_VISA_TEST[i : i + 4] for i in range(0, 16, 4))}"}}', "Credit Card (Visa)"),
        (f'{{"pan": "{_MC_TEST}"}}', "Credit Card (Mastercard)"),
    ],
)
def test_luhn_valid_cards_are_still_found(line: str, expected: str) -> None:
    assert _pii(line) == [expected]


def test_card_with_bad_checksum_is_not_a_card() -> None:
    assert _pii(f'{{"card_number": "{_VISA_BAD_CHECKSUM}"}}') == []


def test_luhn() -> None:
    assert luhn_valid(_VISA_TEST)
    assert luhn_valid(_MC_TEST)
    assert not luhn_valid(_VISA_BAD_CHECKSUM)
    assert not luhn_valid("1004060472")
    assert not luhn_valid("")


class TestRuntimeGatewayRedaction:
    def test_redacts_formatted_phone_and_luhn_valid_card(self) -> None:
        text = f"Call {_PHONE} or charge {_VISA_TEST}"
        redacted = CredentialLeakDetector.redact(text)
        assert _PHONE not in redacted
        assert _VISA_TEST not in redacted
        assert "[REDACTED:US Phone Number]" in redacted
        assert "[REDACTED:Credit Card (Visa)]" in redacted

    def test_alerts_on_luhn_valid_card(self) -> None:
        alerts = CredentialLeakDetector().check("query", f"Card: {_VISA_TEST}")
        assert any(a.details.get("pii_type") == "Credit Card (Visa)" for a in alerts)

    @pytest.mark.parametrize(
        "text",
        [
            '{"ms": 3.4000000953674316}',
            f"order {_VISA_BAD_CHECKSUM}",
            "fetched_at 1784399059.286154",
            "id 11111111-2222-3333-4444-555555555555",
        ],
    )
    def test_leaves_numbers_that_are_not_pii(self, text: str) -> None:
        assert CredentialLeakDetector.redact(text) == text
        assert not [a for a in CredentialLeakDetector().check("t", text) if a.detector == "pii_leak"]

    def test_proxy_redaction_keeps_luhn_and_float_rules(self) -> None:
        assert "[REDACTED:credit_card]" in redact_pii(f"Card: {_VISA_TEST}")
        assert redact_pii(f"order {_VISA_BAD_CHECKSUM}") == f"order {_VISA_BAD_CHECKSUM}"
        assert redact_pii('{"ms": 3.4000000953674316}') == '{"ms": 3.4000000953674316}'
        assert "[REDACTED:phone]" in redact_pii(f"Call {_PHONE}")
