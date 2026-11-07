"""Docstring examples and translation catalogs are not leaked credentials or personal data."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.secret_scanner import scan_content

MONGO_DOCSTRING = '''
class MongoDBSession:
    @classmethod
    def from_uri(cls, uri: str):
        """Create a session from a MongoDB URI string.

        Args:
            uri: MongoDB connection URI,
                e.g. ``"mongodb://localhost:27017"`` or
                ``"mongodb+srv://user:pass@cluster.example.com"``.
        """
        return cls(uri)
'''

FLASK_DOCSTRING = '''
class Config(dict):
    """Works exactly like a dict.

    Either you can fill the config from a config file::

        DEBUG = True
        SECRET_KEY = 'development key'
        app.config.from_object(__name__)
    """
'''


def _scan(content: str, rel_path: str = "pkg/module.py"):
    return scan_content(content, Path(rel_path), rel_path)


@pytest.mark.parametrize("content", [MONGO_DOCSTRING, FLASK_DOCSTRING])
def test_placeholder_examples_in_docstrings_are_not_findings(content):
    assert _scan(content) == []


@pytest.mark.parametrize(
    "line",
    [
        '        ``"mongodb+srv://admin:Zq7v9KpX2mLr@prod-cluster.a1b2c.mongodb.net"``.',
        "        SECRET_KEY = 'f8Kq2xZr7Lw9Pm3V'",
        '        "postgres://svc:S3cr3t-Pa55w0rd@db.internal:5432/app"',
    ],
)
def test_real_looking_secrets_inside_docstrings_still_report(line):
    content = f'def connect():\n    """Connect.\n\n{line}\n    """\n'
    findings = _scan(content)
    assert findings and findings[0].line_number == 4


@pytest.mark.parametrize(
    "line",
    [
        'URI = "mongodb+srv://user:pass@cluster.example.com"',
        "SECRET_KEY = 'development key'",
    ],
)
def test_the_same_values_in_executable_code_still_report(line):
    assert _scan(f"{line}\n")


def test_unparseable_python_gets_no_docstring_exemption():
    content = 'def broken(:\n    """\n    SECRET_KEY = \'development key\'\n    """\n'
    assert _scan(content)


@pytest.mark.parametrize(
    "rel_path,line",
    [
        ("web/locales/de.json", '  "support_contact": "Kontakt: support.team@company-mail.de",'),
        ("app/i18n/fr.yaml", "contact_email: jean.dupont@entreprise-mail.fr"),
    ],
)
def test_personal_data_in_translation_catalogs_is_low_with_a_reason(rel_path, line):
    findings = [f for f in _scan(line + "\n", rel_path) if f.category == "pii"]
    assert findings
    assert all(f.severity == "low" and "translation" in (f.downgrade_reason or "") for f in findings)


def test_personal_data_outside_translation_catalogs_keeps_its_severity():
    findings = [f for f in _scan("contact_email: jean.dupont@entreprise-mail.fr\n", "app/config/fr.yaml") if f.category == "pii"]
    assert findings and all(f.severity == "medium" and f.downgrade_reason is None for f in findings)
