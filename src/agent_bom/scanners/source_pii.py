"""Context for numeric PII in source code; runtime and dataset matchers stay separate."""

from __future__ import annotations

import re

_SOURCE_PARTS = re.compile(r"'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"|#.*$")
_AUTHOR = re.compile(r"^\s*__(?:author|authors|credits|maintainer|email)__\s*=")
_COPYRIGHT_CONTACT = re.compile(r"(?i)^\s*Copyright\s+(?:\(c\)\s*)?\d{4}(?:-\d{4})?,[^\n]*;\s*mailto:$")
_NUMERIC_FIELDS = {
    "US SSN": re.compile(r"(?i)(?:^|[^a-z0-9])(?:[a-z]+_)*(?:ssn|social_?security(?:_?number)?)['\"]?\s*[=:]\s*['\"]?\s*$"),
    "US Phone Number": re.compile(r"(?i)(?:^|[^a-z0-9])(?:[a-z]+_)*(?:phone|phone_?number|telephone|mobile|tel)['\"]?\s*[=:]\s*['\"]?\s*$"),
}

# A bare digit run is a phone or card number only under a field that says so.
_BARE_NUMBER_FIELD = re.compile(
    r"(?i)(?:^|[^a-z0-9])(?:[a-z]+[_-])*(?:phone|telephone|mobile|tel|fax|cell|card|credit_?card|cc|pan)"
    r"(?:[_-]?(?:number|num|no))?['\"]?\s*[=:]\s*['\"]?\s*$"
)
_BARE_NUMBER = re.compile(r"\+?\d+")
_BARE_NUMBER_TYPES = frozenset({"US Phone Number", "Credit Card (Visa)", "Credit Card (Mastercard)", "Credit Card (Amex)"})

# RFC 2606 / RFC 6761 names that can never deliver to a person.
_RESERVED_TLDS = frozenset({"example", "invalid", "localhost", "test"})
_RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
_NO_REPLY_LOCAL_PARTS = frozenset({"noreply", "no-reply", "donotreply", "do-not-reply"})
# Provider-issued or transport addresses that identify a machine, not a person.
_MACHINE_DOMAINS = ("gserviceaccount.com", "users.noreply.github.com")
_SCM_SSH_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org", "ssh.dev.azure.com"})

_PACKAGE_METADATA_FILES = frozenset({"pyproject.toml", "setup.cfg", "setup.py", "package.json", "Cargo.toml"})
_MAINTAINER_FIELD = re.compile(
    r"(?i)(?:^|[^a-z0-9_])(?:authors?|maintainers?|contributors?|author_email|maintainer_email|email)[\"']?\s*[=:]"
)


def _domain_is_or_under(domain: str, suffix: str) -> bool:
    return domain == suffix or domain.endswith("." + suffix)


def non_personal_email(address: str) -> bool:
    """Reserved documentation domains, no-reply mailboxes and machine accounts reach no person."""
    local, _, domain = address.lower().rpartition("@")
    if not local or not domain:
        return False
    if domain.rsplit(".", 1)[-1] in _RESERVED_TLDS or any(_domain_is_or_under(domain, d) for d in _RESERVED_DOMAINS):
        return True
    if local in _NO_REPLY_LOCAL_PARTS or any(_domain_is_or_under(domain, d) for d in _MACHINE_DOMAINS):
        return True
    return local == "git" and domain in _SCM_SSH_HOSTS


def machine_identity_match(name: str, match: re.Match[str]) -> bool:
    """An email match that names a machine, mailbox placeholder or documentation domain, not a person."""
    return name == "Email Address" and non_personal_email(match.group())


def package_metadata_contact(file_name: str, line: str, name: str, match: re.Match[str]) -> bool:
    """Author and maintainer addresses in a package manifest are published registry metadata."""
    return name == "Email Address" and file_name in _PACKAGE_METADATA_FILES and bool(_MAINTAINER_FIELD.search(line[: match.start()]))


def bare_number_has_field(line: str, name: str, match: re.Match[str]) -> bool:
    """A phone or card value with no separators needs a phone or card field name.

    Byte counts, epoch timestamps, limits and ids are bare ten- and
    sixteen-digit runs in JSON and YAML; formatted values carry their own
    evidence.
    """
    if name not in _BARE_NUMBER_TYPES or not _BARE_NUMBER.fullmatch(match.group()):
        return True
    return bool(_BARE_NUMBER_FIELD.search(line[: match.start()]))


def source_pii_match(line: str, name: str, match: re.Match[str]) -> bool:
    """Require a personal field for bare numeric values; retain formatted strings.

    An equals sign alone does not turn arithmetic, digit alphabets, or numeric
    format examples into personal data. Quoted formatted phone/SSN values and
    explicitly named numeric fields remain findings. Public author metadata
    and inline comments are not private contact records. Credential matching
    runs independently and does not use these exclusions.
    """
    if name == "Email Address" and (_AUTHOR.match(line) or _COPYRIGHT_CONTACT.match(line[: match.start()])):
        return False
    quoted = False
    for part in _SOURCE_PARTS.finditer(line):
        if part.start() <= match.start() < part.end():
            if part.group().startswith("#"):
                return False
            quoted = True
            break
    field = _NUMERIC_FIELDS.get(name)
    if field is None:
        return True
    # A field-led match (``ssn = 123456789``) carries its own field name.
    value = match.group()
    field_name = value[: next((i for i, char in enumerate(value) if char.isdigit()), 0)]
    if field.search(line[: match.start()] + field_name):
        return True
    return quoted and not match.group().isdigit()
