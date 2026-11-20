"""Documentation domains, no-reply and transport accounts, and package maintainer metadata are not personal data."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.secret_scanner import scan_content


def _pii(source: str, name: str) -> list[str]:
    return [f.secret_type for f in scan_content(source, Path(name), name) if f.category == "pii"]


@pytest.mark.parametrize(
    "address",
    [
        "security@example.com",
        "oss@example.org",
        "ops@example.net",
        "team@mail.example.com",
        "security@northstar.example",
        "user@acme.test",
        "qualification-user@example.invalid",
        "root@localhost.localhost",
        "34316639+octo@users.noreply.github.com",
        "noreply@github.com",
        "no-reply@service.dev",
        "git@github.com",
        "git@gitlab.com",
        "compute@developer.gserviceaccount.com",
        "app@my-project.appspot.gserviceaccount.com",
    ],
)
@pytest.mark.parametrize(("template", "name"), [('owner_email: "{}"\n', "config.yaml"), ('{{"email": "{}"}}', "data.json")])
def test_non_personal_addresses_are_not_pii(address, template, name):
    assert _pii(template.format(address), name) == []


@pytest.mark.parametrize(
    ("template", "name"),
    [('owner_email: "{}"\n', "config.yaml"), ('{{"email": "{}"}}', "data.json"), ('user_email = "{}"', "module.py")],
)
def test_a_routable_personal_address_still_reports(template, name):
    assert _pii(template.format("jane.doe@acme-widgets.net"), name) == ["Email Address"]


def test_lookalike_domains_are_not_treated_as_reserved():
    for address in ("jane@example.co", "jane@myexample.com", "jane@example.com.evil.net", "jane@testing.io", "jane@git-hub.com"):
        assert _pii(f'owner_email: "{address}"\n', "config.yaml") == ["Email Address"], address


@pytest.mark.parametrize(
    ("line", "name"),
    [
        ('    {name = "Pat Maintainer", email = "pat@acme-widgets.net"}', "pyproject.toml"),
        ('  "author": "Pat Maintainer <pat@acme-widgets.net>",', "package.json"),
        ("author_email = pat@acme-widgets.net", "setup.cfg"),
        ('authors = ["Pat Maintainer <pat@acme-widgets.net>"]', "Cargo.toml"),
    ],
)
def test_package_maintainer_metadata_is_public_not_personal(line, name):
    assert _pii(line, name) == []


def test_contact_fields_outside_package_metadata_still_report():
    assert _pii('email = "pat@acme-widgets.net"', "settings.toml") == ["Email Address"]
    assert _pii('  "billing_contact": "pat@acme-widgets.net",', "package.json") == ["Email Address"]
