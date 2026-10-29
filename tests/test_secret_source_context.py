"""Source syntax distinguishes personal fields from arithmetic and documentation."""

import json
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


@pytest.mark.parametrize(
    "field,value", [("expire", 4294967294), ("imgOptMaxInputPixels", 268402689), ("turbopackStaleOutputMaxAge", 604800000)]
)
def test_next_build_numeric_limits_are_not_personal_records(field, value):
    source = json.dumps(
        {"version": 1, "config": {"cacheLife": {"default": {field: value}}} if field == "expire" else {"experimental": {field: value}}}
    )
    path = "app/.next/required-server-files.json"
    assert not [f for f in scan_content(source, Path(path), path) if f.category == "pii"]


def test_next_build_metadata_still_reports_personal_fields_and_secrets():
    source = '{"ssn":123456789}\npassword = "fixture-' + 'credential-387"'
    path = "app/.next/required-server-files.json"
    findings = scan_content(source, Path(path), path)
    assert {f.category for f in findings} == {"pii", "secret"}


def test_cloud_service_account_address_is_machine_identity_not_personal_email():
    source = 'placeholder:"agent-bom@project.iam.gserviceaccount.com"'
    assert not [f for f in scan_content(source, Path("page.js"), "page.js") if f.category == "pii"]


def test_issue_style_map_is_not_a_credential_assignment():
    source = (
        'const styles={vulnerability:"bg-ink-secondary",misconfiguration:"bg-ink-tertiary",'
        'secret:"bg-ink-secondary opacity-60",pii:"bg-ink-secondary opacity-45"};'
    )
    assert scan_content(source, Path("page.js"), "page.js") == []


@pytest.mark.parametrize(
    "source",
    [
        'const config={secret:"fixture-' + 'credential-387"};',
        'const styles={vulnerability:"bg-ink-secondary",misconfiguration:"bg-ink-tertiary",secret:"fixture-'
        + 'credential-387",pii:"bg-ink-secondary opacity-45"};',
        'const config={secret:"bg-ink-secondary opacity-60"};',
    ],
)
def test_secret_literals_outside_a_complete_style_map_still_report(source):
    assert any(f.category == "secret" for f in scan_content(source, Path("page.js"), "page.js"))


@pytest.mark.parametrize(
    "source,kind",
    [
        ('{"version":1,"config":{"cacheLife":{"default":{"expire":4294967294}},"env":{"phone":2125550199}}}', "US Phone Number"),
        ('{"version":1,"config":{"experimental":{"imgOptMaxInputPixels":268402689},"env":{"ssn":123456789}}}', "US SSN"),
        ('const x={service:"reader@project.iam.gserviceaccount.com",person:"person@example.test"}', "Email Address"),
    ],
)
def test_non_personal_match_does_not_hide_later_personal_value(source, kind):
    path = "app/.next/required-server-files.json"
    assert any(f.secret_type == kind for f in scan_content(source, Path(path), path))


def test_numeric_settings_outside_next_manifest_still_report():
    source = '{"expire":4294967294}'
    assert any(f.category == "pii" for f in scan_content(source, Path("data.json"), "data.json"))


def test_style_map_does_not_hide_another_secret_on_same_minified_line():
    source = (
        'const styles={vulnerability:"bg-ink-secondary",secret:"bg-ink-secondary opacity-60",'
        'pii:"bg-ink-secondary opacity-45"};const config={secret:"fixture-' + 'credential-387"};'
    )
    assert any(f.category == "secret" for f in scan_content(source, Path("page.js"), "page.js"))


def test_next_manifest_application_fields_are_not_exempted_as_build_settings():
    source = json.dumps({"version": 1, "config": {"env": {"expire": 123456789}}})
    path = "app/.next/required-server-files.json"
    assert any(f.secret_type == "US SSN" for f in scan_content(source, Path(path), path))


@pytest.mark.parametrize("name", ["pwd", "spwd"])
def test_stdlib_module_documentation_links_are_not_passwords(name):
    source = f"module_docs = {{'{name}': '{name}#module-{name}'}}"
    path = "usr/local/lib/python3.14/pydoc_data/module_docs.py"
    assert scan_content(source, Path(path), path) == []


@pytest.mark.parametrize("variant", ["changed", "other_file", "other_owner", "invalid", "oversized", "literal"])
def test_module_link_exemption_requires_exact_catalog_context(variant):
    source = "module_docs = {'spwd': 'spwd#module-spwd'}"
    path = "pydoc_data/module_docs.py"
    if variant == "changed":
        source = source.replace("spwd#module-spwd", "fixture-" + "credential-381")
    elif variant == "other_file":
        path = "app/module_docs.py"
    elif variant == "other_owner":
        source = source.replace("module_docs =", "settings =")
    elif variant == "invalid":
        source += "\n("
    elif variant == "oversized":
        source += "\n#" + "x" * (256 * 1024)
    else:
        source = "spwd = 'spwd#module-spwd'"
    assert any(f.category == "secret" for f in scan_content(source, Path(path), path))


def test_module_link_mask_preserves_adjacent_secret_and_duplicate_entry():
    value = "fixture-" + "credential-381"
    source = f"label = '日本'; module_docs = {{'spwd': 'spwd#module-spwd', 'spwd': '{value}'}}; password = '{value}'"
    path = "pydoc_data/module_docs.py"
    findings = scan_content(source, Path(path), path)
    assert any(f.category == "secret" and f.line_number == 1 for f in findings)
    assert value not in str(findings)
