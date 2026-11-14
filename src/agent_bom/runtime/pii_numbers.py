"""Number-shaped PII checks a regex cannot express, shared by every PII matcher."""

from __future__ import annotations

import re
from collections.abc import Callable

# A phone or card number stands alone: a digit run inside a float
# (``3.4000000953674316``), an exponent, a longer number or a dashed id such as
# a UUID is not one.
NUMBER_START = r"(?<![\w.])(?<!\d-)"
NUMBER_END = r"(?!\w)(?![.-]\d)"

PII_CARD_TYPES = frozenset({"Credit Card (Visa)", "Credit Card (Mastercard)", "Credit Card (Amex)"})


def luhn_valid(digits: str) -> bool:
    """Return True when an all-digit string passes the Luhn checksum."""
    if not digits.isdigit():
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2:
            value = value * 2 - 9 if value > 4 else value * 2
        total += value
    return total % 10 == 0


def pii_value_valid(pii_type: str, value: str) -> bool:
    """Checks a regex cannot express: a card number must pass Luhn."""
    if pii_type in PII_CARD_TYPES:
        return luhn_valid(re.sub(r"\D", "", value))
    return True


def pii_matches(pii_type: str, pattern: re.Pattern, text: str) -> list[re.Match[str]]:
    """Every match of *pattern* in *text* that is a valid *pii_type* value."""
    return [match for match in pattern.finditer(text) if pii_value_valid(pii_type, match.group(0))]


def redact_pii_matches(
    pii_type: str,
    pattern: re.Pattern,
    text: str,
    replacement: str,
    *,
    valid: Callable[[str], bool] | None = None,
) -> str:
    """Replace only the valid *pii_type* values; other matches stay as written."""

    def _replace(match: re.Match[str]) -> str:
        value = match.group(0)
        ok = valid(value) if valid is not None else pii_value_valid(pii_type, value)
        return replacement if ok else value

    return pattern.sub(_replace, text)
