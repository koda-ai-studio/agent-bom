"""npm-style version ranges as the Node.js security working group writes them.

The core vulnerability index (github.com/nodejs/security-wg, ``vuln/core``)
states ``vulnerable`` and ``patched`` as npm semver ranges: ``||`` unions of
space-separated comparator sets built from ``N.x``, ``N.N.x``, bare majors,
exact versions, ``^``, ``~`` and ``>=``/``>``/``<``/``<=``/``=``. Node.js
releases are plain ``MAJOR.MINOR.PATCH`` versions, so prerelease and hyphen
ranges are refused: anything outside this grammar raises ``ValueError`` and the
caller fails the assessment closed instead of skipping the advisory.

An empty expression admits nothing, so an advisory with no patched releases
patches no version (npm would read it as ``*``).
"""

from __future__ import annotations

import re

Version = tuple[int, int, int]
Comparator = tuple[str, Version]

_RELEASE = re.compile(r"v?([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})")
_PARTIAL = re.compile(r"v?([0-9]{1,6})(?:\.([0-9]{1,6}|[xX*]))?(?:\.([0-9]{1,6}|[xX*]))?")
_OPERATOR = re.compile(r"(>=|<=|>|<|=|\^|~)?(.*)")
_OPERATOR_SPACE = re.compile(r"(>=|<=|>|<|=|\^|~)\s+")


def parse_version(value: str) -> Version:
    """A plain release version such as ``24.15.0``; anything else raises ``ValueError``."""
    match = _RELEASE.fullmatch(value.strip())
    if match is None:
        raise ValueError(f"Not a plain Node.js release version: {value!r}")
    return int(match[1]), int(match[2]), int(match[3])


def _partial(text: str) -> tuple[int | None, int | None, int | None]:
    if text in {"*", "x", "X"}:
        return None, None, None
    match = _PARTIAL.fullmatch(text)
    if match is None:
        raise ValueError(f"Unsupported version in range: {text!r}")
    parts = [None if part is None or part in {"x", "X", "*"} else int(part) for part in match.groups()]
    if parts[1] is None and parts[2] is not None:
        raise ValueError(f"Unsupported version in range: {text!r}")
    return parts[0], parts[1], parts[2]


def _next(major: int, minor: int | None) -> Version:
    """First release after a partial ``major`` or ``major.minor``."""
    return (major + 1, 0, 0) if minor is None else (major, minor + 1, 0)


def _expand(token: str) -> list[Comparator]:
    match = _OPERATOR.fullmatch(token)
    if match is None:
        raise ValueError(f"Unsupported comparator: {token!r}")
    operator, text = match.groups()
    major, minor, patch = _partial(text)
    if major is None:
        if operator not in {None, "=", ">="}:
            raise ValueError(f"Unsupported comparator: {token!r}")
        return [(">=", (0, 0, 0))]
    floor: Version = (major, minor or 0, patch or 0)
    full = patch is not None
    if operator in {None, "="}:
        return [("=", floor)] if full else [(">=", floor), ("<", _next(major, minor))]
    if operator == "^":
        if major:
            ceiling: Version = (major + 1, 0, 0)
        elif minor is None:
            ceiling = (1, 0, 0)
        elif minor or not full:
            ceiling = (0, minor + 1, 0)
        else:
            ceiling = (0, 0, (patch or 0) + 1)
        return [(">=", floor), ("<", ceiling)]
    if operator == "~":
        return [(">=", floor), ("<", _next(major, minor))]
    if operator == ">=":
        return [(">=", floor)]
    if operator == "<":
        return [("<", floor)]
    if operator == ">":
        return [(">", floor)] if full else [(">=", _next(major, minor))]
    # "<="
    return [("<=", floor)] if full else [("<", _next(major, minor))]


def parse_range(expression: str) -> list[list[Comparator]]:
    """Comparator sets of a ``||`` union; every set must hold for a version to match it."""
    if not expression.strip():
        return []
    if re.search(r"\s-\s", expression):
        raise ValueError(f"Hyphen ranges are not supported: {expression!r}")
    sets: list[list[Comparator]] = []
    for alternative in expression.split("||"):
        tokens = _OPERATOR_SPACE.sub(r"\1", alternative.strip()).split()
        if not tokens:
            raise ValueError(f"Empty alternative in range: {expression!r}")
        sets.append([comparator for token in tokens for comparator in _expand(token)])
    return sets


def _holds(version: Version, comparator: Comparator) -> bool:
    operator, bound = comparator
    return {
        "=": version == bound,
        ">=": version >= bound,
        ">": version > bound,
        "<": version < bound,
        "<=": version <= bound,
    }[operator]


def satisfies(version: Version, expression: str) -> bool:
    return any(all(_holds(version, comparator) for comparator in group) for group in parse_range(expression))


def range_bounds(expression: str) -> list[tuple[Version | None, Version | None]]:
    """Per comparator set: the lowest release it admits and its exclusive ceiling, where exact."""
    bounds: list[tuple[Version | None, Version | None]] = []
    for group in parse_range(expression):
        floors = [bound for operator, bound in group if operator in {">=", "="}]
        ceilings = [bound for operator, bound in group if operator == "<"]
        exact = all(operator in {">=", "=", "<"} for operator, _ in group)
        bounds.append((max(floors) if floors and exact else None, min(ceilings) if ceilings and exact else None))
    return bounds
