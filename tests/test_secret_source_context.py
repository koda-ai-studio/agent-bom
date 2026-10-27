"""Source syntax distinguishes personal fields from arithmetic and documentation."""

from pathlib import Path

import pytest

from agent_bom.secret_scanner import scan_content


@pytest.mark.parametrize(
    "source",
    [
        "h = 1927868237 * (n + 1)",
        "h = h * 69069 + 907133923",
        "x += 0.026818732 * sin(7.101753784 * p)",
        'digits = "0123456789"',
        '"""Example: x = 123456789"""',
        'snippet = "   >>> x = 123456789"',
    ],
)
def test_arithmetic_and_digit_tables_are_not_personal_data(source):
    assert not [f for f in scan_content(source, Path("module.py"), "module.py") if f.category == "pii"]


@pytest.mark.parametrize(
    ("source", "kind"),
    [
        ("ssn = 123456789", "US SSN"),
        ('customer_ssn = "123456789"', "US SSN"),
        ("phone_number = 2125550199", "US Phone Number"),
        ('value = "123-45-6789"', "US SSN"),
        ('value = "212-555-0199"', "US Phone Number"),
        ('user_email = "person@example.test"', "Email Address"),
        ('"""customer_email = person@example.test"""', "Email Address"),
    ],
)
def test_personal_fields_and_formatted_values_still_report(source, kind):
    assert any(f.secret_type == kind for f in scan_content(source, Path("module.py"), "module.py"))


@pytest.mark.parametrize("suffix", [".json", ".yaml", ".env"])
def test_structured_data_retains_numeric_detection(suffix):
    source = '{"value": 123456789}'
    assert any(f.secret_type == "US SSN" for f in scan_content(source, Path("data" + suffix), "data" + suffix))


def test_inline_comment_email_is_not_an_assigned_personal_value():
    source = 'value = re.sub("old", "new", value)  # contributor@example.test'
    assert not [f for f in scan_content(source, Path("module.py"), "module.py") if f.category == "pii"]


def test_python_author_metadata_is_not_a_private_contact_record():
    source = '__author__ = "Contributor <contributor@example.test>"'
    assert not [f for f in scan_content(source, Path("module.py"), "module.py") if f.category == "pii"]


def test_public_copyright_contact_is_not_a_private_contact_record():
    source = "Copyright (c) 2000-2010, Example Foundation; mailto:contact@example.test"
    assert not [f for f in scan_content(source, Path("module.py"), "module.py") if f.category == "pii"]


def test_credentials_in_docstrings_and_metadata_remain_reported():
    value = "fixture-" + "password-381"
    for source in [f'"""password = "{value}"\n"""', f"__author__ = 'password=\"{value}\"'"]:
        assert any(f.category == "secret" for f in scan_content(source, Path("module.py"), "module.py"))


@pytest.mark.parametrize(
    ("fixture", "path"),
    [("urllib_request", "urllib/request.py"), ("smtplib_sendmail", "smtplib.py")],
)
def test_exact_public_stdlib_documentation_samples(fixture, path):
    source = (Path(__file__).parent / "fixtures/source_samples" / (fixture + ".py")).read_text()
    assert scan_content(source, Path(path), path) == []


def test_documentation_password_outside_known_docstring_still_reports():
    source = (Path(__file__).parent / "fixtures/source_samples/urllib_request.py").read_text()
    literal = "passwd=" + repr("geheim" + "$parole")
    findings = scan_content(source + literal, Path("urllib/request.py"), "urllib/request.py")
    assert len(findings) == 1 and findings[0].line_number > 60
    assert scan_content(literal, Path("urllib/request.py"), "urllib/request.py")
    assert scan_content(source, Path("application.py"), "application.py")


def test_modified_public_docstring_does_not_receive_sample_exemption():
    source = (Path(__file__).parent / "fixtures/source_samples/urllib_request.py").read_text()
    source = source.replace("geheim" + "$parole", "fixture-" + "password-983")
    assert any(f.category == "secret" for f in scan_content(source, Path("urllib/request.py"), "urllib/request.py"))
