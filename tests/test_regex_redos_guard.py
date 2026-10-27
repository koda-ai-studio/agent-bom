"""Guard: no module-level regex in the image/IaC/registry modules backtracks catastrophically.

Every compiled pattern is searched against hostile inputs built from repeated
option-like tokens (``-a::``, ``:::``, ``--a=--a``, long whitespace, ...). An
exponential pattern blows past the per-search budget within a few dozen
repetitions; a polynomial one fails the scaling check (10x input must cost
less than 30x time).
"""

from __future__ import annotations

import importlib
import pkgutil
import re
import time

import pytest

_PACKAGES = ("agent_bom.iac", "agent_bom.image_evidence", "agent_bom.oci_registry")
_MODULES = ("agent_bom.image", "agent_bom.floating_refs", "agent_bom.core.image_ref", "agent_bom.parsers.oci_layer_secrets")
_UNITS = (
    "-a::",
    "a::",
    ":::",
    "-a::a::a::a::a ",
    "--a=--a ",
    "a=a ",
    "-a ",
    " ",
    "\t",
    "a",
    "a-",
    "a.",
    "a_",
    "a/",
    "${a",
    "$a",
    "0",
    "x::x ",
    '"a"=',
    "|1 a=",
    "sha256/",
    "a:a",
    "-",
    "*",
    "..",
    "a b",
)
_PREFIXES = (
    "",
    "RUN ",
    "apt-get ",
    "sudo apt-get ",
    "apk ",
    "yum ",
    "pip install ",
    "chmod ",
    "curl ",
    "a=a ",
    "# a=",
    "|1 ",
    "$",
    "--chmod=",
    "FROM ",
    "localhost/",
    '"',
)
_SUFFIX = "\x01!"
_SEARCH_BUDGET_SECONDS = 0.05
_NOISE_FLOOR_SECONDS = 0.003


def _module_names() -> list[str]:
    names = list(_MODULES)
    for package_name in _PACKAGES:
        package = importlib.import_module(package_name)
        names.append(package_name)
        names.extend(f"{package_name}.{info.name}" for info in pkgutil.iter_modules(package.__path__))
    return names


def _patterns() -> list[tuple[str, re.Pattern[str]]]:
    found: dict[int, tuple[str, re.Pattern[str]]] = {}
    for name in _module_names():
        for attr, value in vars(importlib.import_module(name)).items():
            if isinstance(value, re.Pattern) and isinstance(value.pattern, str):
                found.setdefault(id(value), (f"{name}.{attr}", value))
    return sorted(found.values(), key=lambda item: item[0])


def _elapsed(pattern: re.Pattern[str], text: str) -> float:
    best = float("inf")
    for _ in range(3):
        start = time.perf_counter()
        pattern.search(text)
        best = min(best, time.perf_counter() - start)
    return best


def _hostile_failures(pattern: re.Pattern[str]) -> list[str]:
    failures: list[str] = []
    for prefix in _PREFIXES:
        for unit in _UNITS:
            repeats = 2
            while repeats <= 32:
                if _elapsed(pattern, prefix + unit * repeats + _SUFFIX) > _SEARCH_BUDGET_SECONDS:
                    failures.append(f"exponential: {prefix!r} + {unit!r} x {repeats}")
                    break
                repeats *= 2
            else:
                small = _elapsed(pattern, prefix + unit * 40 + _SUFFIX)
                large = _elapsed(pattern, prefix + unit * 400 + _SUFFIX)
                if large > 30 * small + _NOISE_FLOOR_SECONDS:
                    failures.append(f"super-linear: {prefix!r} + {unit!r} ({small * 1e3:.2f}ms -> {large * 1e3:.2f}ms)")
    return failures


_ALL_PATTERNS = _patterns()


def test_guard_discovers_the_patterns_it_must_cover() -> None:
    from agent_bom.iac import dockerfile_build_rules, dockerfile_rules
    from agent_bom.oci_registry import auth

    covered = {id(pattern) for _name, pattern in _ALL_PATTERNS}
    for pattern in (dockerfile_build_rules._APT_INSTALL_RE, dockerfile_rules._PKG_INSTALL_RE, auth._CHALLENGE_PARAM_RE):
        assert id(pattern) in covered
    assert len(_ALL_PATTERNS) > 50


@pytest.mark.parametrize(("name", "pattern"), _ALL_PATTERNS, ids=[name for name, _ in _ALL_PATTERNS])
def test_pattern_has_no_catastrophic_backtracking(name: str, pattern: re.Pattern[str]) -> None:
    failures = _hostile_failures(pattern)
    assert not failures, f"{name} backtracks on hostile input: {failures[:3]}"


def test_reported_apt_option_token_input_is_linear() -> None:
    from agent_bom.iac.dockerfile_build_rules import _APT_INSTALL_RE

    for repeats in (8, 10, 200):
        start = time.perf_counter()
        assert _APT_INSTALL_RE.match("apt-get " + "-a::a::a::a::a " * repeats + "x") is None
        assert time.perf_counter() - start < 0.5, f"{repeats} option tokens took too long"


@pytest.mark.parametrize(
    ("segment", "matches"),
    [
        ("apt-get install -y curl", True),
        ("apt-get -o Dpkg::Options::=--force-confnew install curl", True),
        ("apt-get -y -q install curl", True),
        ("DEBIAN_FRONTEND=noninteractive sudo -E /usr/bin/apt-get install curl", True),
        ("apt-get update", False),
        ("apt-get -o a::b::c update", False),
    ],
)
def test_apt_install_pattern_still_matches_real_commands(segment: str, matches: bool) -> None:
    from agent_bom.iac.dockerfile_build_rules import _APT_INSTALL_RE

    assert bool(_APT_INSTALL_RE.match(segment)) is matches


def test_challenge_params_still_parse() -> None:
    from agent_bom.oci_registry.auth import parse_challenge

    challenge = parse_challenge('Bearer realm="https://auth.example.test/token",service="registry.example.test",scope="repository:a/b:pull"')
    assert challenge is not None
    assert challenge.params == {
        "realm": "https://auth.example.test/token",
        "service": "registry.example.test",
        "scope": "repository:a/b:pull",
    }
