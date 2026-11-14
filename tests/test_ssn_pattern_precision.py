"""A US SSN is a separated 3-2-4 value or a number under an SSN field, never any 9-digit run."""

from pathlib import Path

import pytest

from agent_bom.runtime.detectors import CredentialLeakDetector
from agent_bom.runtime.patterns import PII_PATTERNS
from agent_bom.secret_scanner import scan_content

SSN = dict(PII_PATTERNS)["US SSN"]


def _ssn(area: str, group: str, serial: str, sep: str = "-") -> str:
    return sep.join((area, group, serial))


REAL_SHAPES = [
    _ssn("123", "45", "6789"),
    "SSN " + _ssn("123", "45", "6789", " "),
    "ssn: " + "123" + "45" + "6789",
    '"social_security_number": "' + "123" + "45" + "6789" + '"',
]

NOT_SSN = [
    '"total_bytes": ' + "324" + "926" + "487",
    "iso-27001-2022",
    "iso-" + "27001" + "-2022",
    "build " + "123" + "456" + "789",
    _ssn("123", "45", "6789", "."),
    "123-45" + " 6789",
    _ssn("000", "45", "6789"),
    _ssn("666", "45", "6789"),
    _ssn("123", "00", "6789"),
    _ssn("123", "45", "0000"),
    "id=" + "1234567890",
]


@pytest.mark.parametrize("text", REAL_SHAPES)
def test_real_ssn_shapes_match(text):
    assert SSN.search(text)


@pytest.mark.parametrize("text", NOT_SSN)
def test_digit_runs_and_identifiers_are_not_ssn(text):
    assert not SSN.search(text)


@pytest.mark.parametrize("suffix", [".json", ".yaml", ".env"])
def test_secret_scanner_ignores_bare_digit_runs_in_config(suffix):
    source = '{"total_bytes": ' + "324926487" + ', "standard": "iso-27001-2022"}'
    path = "data" + suffix
    assert not [f for f in scan_content(source, Path(path), path) if f.secret_type == "US SSN"]


@pytest.mark.parametrize("suffix", [".json", ".yaml"])
def test_secret_scanner_still_reports_ssn_fields_and_formatted_values(suffix):
    path = "data" + suffix
    for source in ('{"ssn": ' + "123456789" + "}", '{"value": "' + _ssn("123", "45", "6789") + '"}'):
        assert any(f.secret_type == "US SSN" for f in scan_content(source, Path(path), path)), source


def test_runtime_gateway_flags_formatted_ssn_but_not_byte_counts():
    detector = CredentialLeakDetector()
    leak = detector.check("tool", "customer " + _ssn("123", "45", "6789"))
    assert any(a.details.get("pii_type") == "US SSN" for a in leak)
    benign = detector.check("tool", '{"total_bytes": ' + "324926487" + "}")
    assert not any(a.details.get("pii_type") == "US SSN" for a in benign)
    redacted = CredentialLeakDetector.redact("ssn " + _ssn("123", "45", "6789"))
    assert _ssn("123", "45", "6789") not in redacted
