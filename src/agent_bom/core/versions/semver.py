"""Strict SemVer 2.0 precedence, shared by the npm-family, Cargo/Pub/Hex/Swift and Go comparators."""

from __future__ import annotations

import re

__all__ = ["_STRICT_SEMVER", "_compare_strict_semver"]


_STRICT_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$")


def _compare_strict_semver(left: str, right: str) -> int | None:
    """Compare strict SemVer strings, including arbitrary prerelease tags.

    Build metadata never affects precedence (SemVer 2.0 and OSV ``SEMVER`` ranges),
    even for Pub, whose own tooling orders build numbers.
    """
    left_match = _STRICT_SEMVER.fullmatch(left.strip())
    right_match = _STRICT_SEMVER.fullmatch(right.strip())
    if left_match is None or right_match is None:
        return None
    left_base = tuple(int(left_match.group(index)) for index in (1, 2, 3))
    right_base = tuple(int(right_match.group(index)) for index in (1, 2, 3))
    if left_base != right_base:
        return (left_base > right_base) - (left_base < right_base)
    left_pre = left_match.group(4)
    right_pre = right_match.group(4)
    if left_pre is None or right_pre is None:
        if left_pre == right_pre:
            return 0
        return -1 if left_pre is not None else 1
    left_parts = left_pre.split(".")
    right_parts = right_pre.split(".")
    for left_part, right_part in zip(left_parts, right_parts):
        if left_part == right_part:
            continue
        left_numeric = left_part.isdigit()
        right_numeric = right_part.isdigit()
        if left_numeric and right_numeric:
            return (int(left_part) > int(right_part)) - (int(left_part) < int(right_part))
        if left_numeric != right_numeric:
            return -1 if left_numeric else 1
        return (left_part > right_part) - (left_part < right_part)
    return (len(left_parts) > len(right_parts)) - (len(left_parts) < len(right_parts))
