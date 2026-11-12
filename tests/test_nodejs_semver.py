"""npm-style ranges as the Node.js security working group writes them."""

from __future__ import annotations

import pytest

from agent_bom.scanners.nodejs_semver import parse_version, range_bounds, satisfies


@pytest.mark.parametrize(
    ("version", "expression", "expected"),
    [
        # x-ranges and bare majors cover a whole release line
        ("24.15.0", "22.x || 24.x || 26.x", True),
        ("25.0.0", "22.x || 24.x || 26.x", False),
        ("24.15.0", "24", True),
        ("8.5.3", "8.5.x", True),
        ("8.6.0", "8.5.x", False),
        ("1.0.0", "*", True),
        # exact versions
        ("8.5.0", "8.5.0", True),
        ("8.5.1", "8.5.0", False),
        ("8.5.0", "=8.5.0", True),
        # caret stays on the major line, and narrows for 0.x
        ("24.22.1", "^24.22.1", True),
        ("24.30.0", "^24.22.1", True),
        ("24.22.0", "^24.22.1", False),
        ("25.0.0", "^24.22.1", False),
        ("0.10.48", "^0.10.40", True),
        ("0.11.0", "^0.10.40", False),
        ("0.0.4", "^0.0.3", False),
        ("0.0.3", "^0.0.3", True),
        # tilde stays on the minor line
        ("4.4.9", "~4.4.2", True),
        ("4.5.0", "~4.4.2", False),
        ("4.4.1", "~4.4.2", False),
        # comparators, with and without a space after the operator
        ("10.9.0", ">= 10.9.0", True),
        ("10.8.9", ">= 10.9.0", False),
        ("6.1.0", ">=6.0.0 <6.2.0 || 5.x || 4.x", True),
        ("6.2.0", ">=6.0.0 <6.2.0 || 5.x || 4.x", False),
        ("5.12.0", ">=6.0.0 <6.2.0 || 5.x || 4.x", True),
        ("10.99.99", "<= 10", True),
        ("11.0.0", "<= 10", False),
        ("10.0.0", "< 10", False),
        ("9.99.0", "< 10", True),
        ("10.1.0", "<=10.0", False),
        ("10.0.9", "<=10.0", True),
        ("6.0.1", ">6.0.0", True),
        ("6.0.0", ">6.0.0", False),
        ("7.0.0", "> 6", True),
        ("6.9.9", "> 6", False),
        ("6.1.0", "> 6.0", True),
        ("6.0.9", "> 6.0", False),
        # an empty patched expression patches nothing
        ("24.0.0", "", False),
    ],
)
def test_satisfies_follows_npm_range_semantics(version: str, expression: str, expected: bool) -> None:
    assert satisfies(parse_version(version), expression) is expected


@pytest.mark.parametrize(
    "expression",
    [
        "1.2.3 - 2.3.4",  # hyphen ranges never appear in the index; refuse rather than guess
        ">=1.2.3-rc.1",  # prerelease comparators
        "latest",
        "^",
        ">= ",
        "1.2.3.4",
        "|| 4.x",
        "4.x ||",
    ],
)
def test_unsupported_grammar_fails_closed(expression: str) -> None:
    with pytest.raises(ValueError):
        satisfies((4, 0, 0), expression)


@pytest.mark.parametrize("version", ["24.15", "24.15.0.1", "v24.15.0-rc.1", "24.15.0-nightly", "", "x.y.z"])
def test_installed_version_must_be_a_plain_release(version: str) -> None:
    with pytest.raises(ValueError):
        parse_version(version)


def test_parse_version_accepts_a_v_prefix() -> None:
    assert parse_version("v24.15.0") == (24, 15, 0)


def test_bounds_name_each_sets_inclusive_floor_and_exclusive_ceiling() -> None:
    assert range_bounds("^22.23.4 || >= 10.9.0 || 8.5.x || >=6.0.0 <6.2.0") == [
        ((22, 23, 4), (23, 0, 0)),
        ((10, 9, 0), None),
        ((8, 5, 0), (8, 6, 0)),
        ((6, 0, 0), (6, 2, 0)),
    ]
    # a strict lower bound or an inclusive full upper bound names no exact release
    assert range_bounds(">6.0.0 <=6.4.1") == [(None, None)]
    assert range_bounds("<= 10") == [(None, (11, 0, 0))]
