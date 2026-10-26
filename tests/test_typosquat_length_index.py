"""The length-indexed typosquat matcher returns exactly what the full scan returned.

A match needs at most ``_MAX_EDITS`` edits, so a popular name whose length
differs by more than that can never be returned; the single-substitution
fallback only ever matches equal lengths. Skipping those candidates must not
change any answer, including ties, which keep the popular set's order.
"""

from __future__ import annotations

import random
from difflib import SequenceMatcher

import pytest

from agent_bom import malicious
from agent_bom.malicious import (
    _EDIT1_MIN_LEN,
    _KNOWN_LEGITIMATE,
    _MAX_EDITS,
    _POPULAR_PACKAGES,
    _edit_distance,
    _extends,
    _single_substitution,
    typosquat_target,
)


def _reference_target(name: str, popular: frozenset[str], legitimate: frozenset[str], threshold: float = 0.85) -> str | None:
    """The unindexed algorithm, kept verbatim as the oracle."""
    if name in popular or name in legitimate:
        return None
    best_ratio, best_match = 0.0, ""
    matcher = SequenceMatcher(None, "", name, autojunk=False)
    for candidate in popular:
        if 2 * min(len(name), len(candidate)) < threshold * (len(name) + len(candidate)) or _extends(name, candidate):
            continue
        matcher.set_seq1(candidate)
        if matcher.quick_ratio() < threshold:
            continue
        ratio = matcher.ratio()
        if ratio > best_ratio and ratio >= threshold and _edit_distance(name, candidate, _MAX_EDITS) <= _MAX_EDITS:
            best_ratio, best_match = ratio, candidate
    if best_match:
        return best_match
    if len(name) >= _EDIT1_MIN_LEN:
        return next((c for c in sorted(popular) if _single_substitution(name, c)), None)
    return None


def _mutations(name: str, rng: random.Random) -> list[str]:
    letters = "abcdefghijklmnopqrstuvwxyz-0123456789"
    out = [name + rng.choice(letters), name[1:], name[:-1] + rng.choice(letters), name + "-js", name.replace("e", "3")]
    if len(name) > 3:
        i = rng.randrange(len(name) - 1)
        out.append(name[:i] + name[i + 1] + name[i] + name[i + 2 :])
        out.append(name[:i] + name[i + 2 :])
    return out


@pytest.mark.parametrize("ecosystem", sorted(_POPULAR_PACKAGES))
def test_indexed_matcher_equals_full_scan(ecosystem: str) -> None:
    popular = _POPULAR_PACKAGES[ecosystem]
    legitimate = _KNOWN_LEGITIMATE.get(ecosystem, frozenset())
    rng = random.Random(5991)
    names = [m for name in sorted(popular) for m in _mutations(name, rng)]
    names += [f"bench-pkg-{i}" for i in range(300)] + ["", "a", "x" * 80]
    mismatches = [(n, typosquat_target(n, ecosystem, popular, legitimate), _reference_target(n, popular, legitimate)) for n in names]
    mismatches = [row for row in mismatches if row[1] != row[2]]
    assert not mismatches[:10]
    assert any(typosquat_target(n, ecosystem, popular, legitimate) for n in names), "corpus must exercise real matches"


def test_plain_set_input_still_supported() -> None:
    popular = set(_POPULAR_PACKAGES["npm"])
    assert typosquat_target("expresss", "npm", popular, frozenset()) == "express"


def test_index_is_built_once_per_popular_set() -> None:
    malicious._popular_index.cache_clear()
    popular = _POPULAR_PACKAGES["pypi"]
    for i in range(50):
        typosquat_target(f"reqeusts{i}", "pypi", popular, frozenset())
    assert malicious._popular_index.cache_info().misses == 1
