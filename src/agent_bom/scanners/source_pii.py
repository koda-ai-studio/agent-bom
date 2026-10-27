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
    if field.search(line[: match.start()]):
        return True
    return quoted and not match.group().isdigit()
