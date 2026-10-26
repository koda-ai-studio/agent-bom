"""Malicious package detection — MAL- prefix from OSV + typosquat heuristics.

The OpenSSF Malicious Packages repository publishes reports in OSV format
with MAL- prefixed IDs. These are indexed in OSV.dev and returned in
agent-bom's existing batch scan results. This module makes detection
explicit and adds typosquat distance checking against popular packages.

Reference: https://github.com/ossf/malicious-packages
"""

from __future__ import annotations

import functools
import json
import re
from difflib import SequenceMatcher
from pathlib import Path
from typing import TYPE_CHECKING

from agent_bom.checksums import locked_from_public_registry

if TYPE_CHECKING:
    from agent_bom.models import Package, Vulnerability


# CWE "malicious code" family: Embedded Malicious Code and its children
# (trojan, non-replicating/replicating code, trapdoor, logic bomb, spyware).
# GitHub's reviewed malware advisories carry GHSA ids, not MAL- ids, and are
# marked by CWE-506 in OSV ``database_specific.cwe_ids``.
_MALICIOUS_CODE_CWES: frozenset[str] = frozenset({"CWE-506", "CWE-507", "CWE-508", "CWE-509", "CWE-510", "CWE-511", "CWE-512"})

# Advisory titles that describe the package itself as malware ("crossenv is
# malware", "Malicious Package in flatmap-stream"). Attacker wording such as
# "a malicious user can ..." must not match.
_MALWARE_SUMMARY = re.compile(
    r"\bmalicious\s+(?:package|code|version|release|dependency)s?\b"
    r"|\b(?:is|are|contains?|includes?|was|were)\s+(?:a\s+piece\s+of\s+)?malware\b"
    r"|\bembedded\s+malicious\b",
    re.IGNORECASE,
)


# CWE-506 (Embedded Malicious Code) is how GitHub malware advisories such as
# crossenv and event-stream 3.3.6 reach OSV: as GHSA ids with no MAL- alias.
MALWARE_CWE = "CWE-506"


def is_malicious_vuln(vuln_id: str, cwe_ids: list[str] | None = None) -> bool:
    """Check if a vulnerability ID (or its CWE tags) indicates a known malicious package."""
    return vuln_id.upper().startswith("MAL-") or MALWARE_CWE in (cwe_ids or [])


def _is_malicious_advisory(ids: list[str], cwe_ids: list[str], summary: str) -> bool:
    if any(is_malicious_vuln(i) for i in ids if isinstance(i, str)):
        return True
    if any(isinstance(c, str) and c.upper() in _MALICIOUS_CODE_CWES for c in cwe_ids):
        return True
    return bool(summary and _MALWARE_SUMMARY.search(summary))


def is_malicious_osv_record(record: dict) -> bool:
    """True when a raw OSV record is a malicious-package advisory (MAL-, CWE-506 or malware title)."""
    raw_specific = record.get("database_specific")
    db_specific: dict = raw_specific if isinstance(raw_specific, dict) else {}
    ids = [str(record.get("id") or ""), *(record.get("aliases") or [])]
    return _is_malicious_advisory(ids, list(db_specific.get("cwe_ids") or []), str(record.get("summary") or ""))


def is_malicious_advisory(vuln: Vulnerability) -> bool:
    """True when a parsed vulnerability is a malicious-package advisory."""
    return _is_malicious_advisory([vuln.id, *vuln.aliases], list(vuln.cwe_ids), vuln.summary or "")


def flag_malicious_from_vulns(package: Package) -> None:
    """Flag a package as malicious if any vulnerability is a malicious-package advisory.

    Covers OpenSSF MAL- ids and GHSA malware advisories (CWE-506 family or a
    "... is malware" title). Mutates package.is_malicious and
    package.malicious_reason in-place.
    """
    mal_ids = [v.id for v in package.vulnerabilities if is_malicious_advisory(v)]
    if mal_ids:
        package.is_malicious = True
        package.malicious_reason = f"Known malicious package ({', '.join(mal_ids[:3])})"


# Scoped npm packages from known orgs are NOT confusion risks
_SAFE_NPM_SCOPES: frozenset[str] = frozenset(
    {
        "@modelcontextprotocol/",
        "@anthropic-ai/",
        "@google-cloud/",
        "@azure/",
        "@aws-sdk/",
        "@types/",
        "@babel/",
        "@eslint/",
        "@eslint-community/",
        "@opentelemetry/",
        "@typescript-eslint/",
        "@testing-library/",
        "@playwright/",
        "@vercel/",
        "@next/",
    }
)


# ─── Typosquat detection ─────────────────────────────────────────────────────

# Names attackers imitate, per ecosystem, from public download and dependent
# rankings plus documented campaign targets. ``established`` holds the ranked
# projects that sit within squat distance of a target (``psycopg2``/``psycopg``)
# and so are never reported. Built and documented by
# scripts/generate_popular_packages.py.
_REFERENCE = json.loads((Path(__file__).parent / "data" / "popular_packages.json").read_text(encoding="utf-8"))
_POPULAR_PACKAGES: dict[str, frozenset[str]] = {eco: frozenset(names) for eco, names in _REFERENCE["popular"].items()}
_ESTABLISHED: dict[str, frozenset[str]] = {eco: frozenset(names) for eco, names in _REFERENCE["established"].items()}


# Genuine packages whose names resemble a popular neighbour closely enough to
# trip the ratio gate below. Each entry is a real, upstream-maintained project
# verified against its registry metadata — not a suppression of a real hit.
#
# Deliberately a curated list rather than a rule. The obvious general rule —
# "a trailing major-version digit means a legitimate successor" — is wrong in
# the dangerous direction: ``requests2`` and ``requests3`` were real typosquat
# campaigns, so exempting that shape would trade a false positive for a false
# negative. Names only land here once the upstream project is confirmed.
_KNOWN_LEGITIMATE: dict[str, frozenset[str]] = {
    "npm": frozenset(
        {
            # Independent React-compatible UI framework, published by the
            # Preact project as a first-class public npm package.
            "preact",
            # dcodeIO's pure-JS bcrypt, published since 2013.
            "bcryptjs",
            # TJ Holowaychuk's original test framework (visionmedia/expresso).
            "expresso",
        }
    ),
    "pypi": frozenset(
        {
            # The httpx successor, by httpx's own author (github.com/pydantic/httpx2).
            # Reaches most dependency trees transitively via the openai SDK.
            "httpx2",
            # Official LangChain Hub API client.
            "langchainhub",
            # boto 2, the predecessor of boto3 from the same project.
            "boto",
            # Fabric 2+ published by Fabric's maintainer (fabfile.org).
            "fabric2",
            # Long-standing Python 3 fork of Fabric 1 (mathiasertl/fabric).
            "fabric3",
            # SQL over DataFrames (yhat/pandasql), published since 2013.
            "pandasql",
            # Beautiful Soup 3 by the same author as beautifulsoup4.
            "beautifulsoup",
            # Globality's OpenAPI spec library, published since 2016.
            "openapi",
        }
    ),
}


# Names at least this long are eligible for the single-substitution catch below.
# Below this, one edited character is too weak a signal (``core`` vs ``cors``,
# ``flask`` vs ``flash``) and would create false positives on real packages.
_EDIT1_MIN_LEN = 6


def _single_substitution(a: str, b: str) -> bool:
    """Return True when equal-length ``a`` and ``b`` differ in exactly one char.

    Restricting to equal length (a pure substitution) avoids flagging legitimate
    length-shifted neighbours such as ``panda`` vs ``pandas``.
    """
    if len(a) != len(b):
        return False
    diff = 0
    for ca, cb in zip(a, b):
        if ca != cb:
            diff += 1
            if diff > 1:
                return False
    return diff == 1


# Real squats are one or two edits from their target (``urlib3``, ``reqeusts``,
# ``python3-dateutil``). On long names a shared prefix alone pushes the ratio
# past the threshold (``eslint-plugin-vitest`` vs ``eslint-plugin-jest``), so a
# match must also be within this many edits.
_MAX_EDITS = 2


def canonical_name(name: str, ecosystem: str) -> str:
    """Lowercase ``name``; on PyPI also fold ``-``, ``_`` and ``.`` together as pip does."""
    lowered = name.lower()
    return re.sub(r"[-_.]+", "-", lowered) if ecosystem.lower() == "pypi" else lowered


def _edit_distance(a: str, b: str, limit: int) -> int:
    """Optimal-string-alignment distance (adjacent transposition = 1), capped at ``limit + 1``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        row = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            row[j] = min(prev[j] + 1, row[j - 1] + 1, prev[j - 1] + (ca != cb))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                row[j] = min(row[j], prev2[j - 2] + 1)
        if min(row) > limit:
            return limit + 1
        prev2, prev = prev, row
    return prev[-1]


def _extends(name: str, target: str) -> bool:
    """True when ``name`` is ``target`` plus whole ``-`` tokens, the shape of a plugin or binding."""
    return name.startswith(target + "-") or name.endswith("-" + target)


@functools.lru_cache(maxsize=8)
def _popular_index(popular: frozenset[str]) -> tuple[tuple[str, ...], dict[int, tuple[int, ...]], dict[int, tuple[str, ...]]]:
    """Popular names in iteration order, their positions by length, and the sorted names by length."""
    ordered = tuple(popular)
    positions: dict[int, list[int]] = {}
    for index, candidate in enumerate(ordered):
        positions.setdefault(len(candidate), []).append(index)
    by_length: dict[int, list[str]] = {}
    for candidate in sorted(popular):
        by_length.setdefault(len(candidate), []).append(candidate)
    return ordered, {k: tuple(v) for k, v in positions.items()}, {k: tuple(v) for k, v in by_length.items()}


def _typosquat_candidates(name: str, popular: frozenset[str] | set[str]) -> tuple[list[str] | frozenset[str] | set[str], tuple[str, ...]]:
    """Only names within ``_MAX_EDITS`` of ``name``'s length can match, kept in the set's own order for ties."""
    if not isinstance(popular, frozenset):
        return popular, tuple(c for c in sorted(popular) if len(c) == len(name))
    ordered, positions, by_length = _popular_index(popular)
    near = sorted(i for delta in range(-_MAX_EDITS, _MAX_EDITS + 1) for i in positions.get(len(name) + delta, ()))
    return [ordered[i] for i in near], by_length.get(len(name), ())


def typosquat_target(
    name: str, ecosystem: str, popular: frozenset[str] | set[str], legitimate: frozenset[str], threshold: float = 0.85
) -> str | None:
    """Return the entry of ``popular`` that canonical ``name`` imitates, or None."""
    if name in popular or name in legitimate:
        return None
    best_ratio = 0.0
    best_match = ""
    candidates, same_length = _typosquat_candidates(name, popular)
    # difflib caches its analysis of the second sequence, so hold ``name`` there.
    matcher = SequenceMatcher(None, "", name, autojunk=False)
    for candidate in candidates:
        # 2*min/(sum) bounds the ratio from above: skip without building anything.
        if 2 * min(len(name), len(candidate)) < threshold * (len(name) + len(candidate)) or _extends(name, candidate):
            continue
        matcher.set_seq1(candidate)
        if matcher.quick_ratio() < threshold:
            continue
        ratio = matcher.ratio()
        if ratio > best_ratio and ratio >= threshold and _edit_distance(name, candidate, _MAX_EDITS) <= _MAX_EDITS:
            best_ratio = ratio
            best_match = candidate
    if best_match:
        return best_match

    # A single-character substitution on a short-ish name (``djanga`` vs
    # ``django``) scores 0.833 < 0.85 and slips past the ratio gate. Catch the
    # equal-length one-edit case explicitly for names long enough that one edited
    # character is a strong signal, without lowering the ratio threshold (which
    # would pull in genuine near-neighbours).
    if len(name) >= _EDIT1_MIN_LEN:
        return next((c for c in same_length if _single_substitution(name, c)), None)
    return None


def check_typosquat(name: str, ecosystem: str, threshold: float = 0.85) -> str | None:
    """Check if a package name looks like a typosquat of a popular package.

    Returns the suspected target package name, or None if no match.
    Uses SequenceMatcher ratio — same approach as parsers/skill_audit.py — capped
    at ``_MAX_EDITS`` edits.
    """
    eco = ecosystem.lower()
    popular = _POPULAR_PACKAGES.get(eco, frozenset())
    if not popular:
        return None

    normalized = canonical_name(name, eco)

    # Official scoped npm packages such as @babel/core are allowed to look
    # similar to older unscoped package names like babel-core.
    if eco == "npm" and any(normalized.startswith(scope) for scope in _SAFE_NPM_SCOPES):
        return None

    legitimate = _KNOWN_LEGITIMATE.get(eco, frozenset()) | _ESTABLISHED.get(eco, frozenset())
    return typosquat_target(normalized, eco, popular, legitimate, threshold)


# ── Dependency confusion detection ─────────────────────────────────────────
#
# Dependency confusion attacks exploit the gap between private/internal
# package registries and public ones. An attacker publishes a package on
# PyPI/npm with the same name as an internal package, at a higher version,
# and the package manager prefers the public one.
#
# Detection heuristics (no network — static analysis only):
# 1. Package name matches common internal naming patterns
# 2. Package not found in OSV/NVD (no vulnerability data = likely private)
# 3. Package has no registry metadata (version resolution failed)

# Patterns that strongly suggest internal/private package names.
_STRONG_INTERNAL_NAME_PATTERNS: frozenset[str] = frozenset(
    {
        "private-",
        "corp-",
        "company-",
        "-internal",
        "-private",
        "-corp",
    }
)

# Service-ish tokens are weak signals. They are common in public SDKs and npm
# utility packages, so only use them when no public registry version was
# resolved.
_WEAK_INTERNAL_NAME_PATTERNS: frozenset[str] = frozenset(
    {
        "internal-",
        "-infra",
        "-platform",
        "-shared",
        "-common",
        "-utils",
        "-service",
        "-api",
    }
)

# Public SDK families commonly use service-oriented package names such as
# ``azure-mgmt-servicebus`` or ``google-api-core``. Those names contain broad
# internal-looking tokens (-api, -common, -service) but are public namespace
# conventions, not dependency-confusion signals by themselves.
_SAFE_PUBLIC_NAME_PREFIXES_BY_ECOSYSTEM: dict[str, frozenset[str]] = {
    "pypi": frozenset(
        {
            "azure-",
            "google-",
            "googleapis-",
            "opentelemetry-",
        }
    ),
}


def check_dependency_confusion(package: "Package") -> str | None:
    """Check if a package name looks like it could be a dependency confusion target.

    Returns a warning string if the name matches internal naming patterns
    and has no vulnerability data (suggesting it may be a private package
    that an attacker could shadow on a public registry).

    Returns None if no confusion risk detected.
    """
    name = package.name.lower()
    eco = package.ecosystem.lower()

    # Go dependencies use origin-qualified module paths rather than unscoped
    # public-registry names. Tokens such as ``go-internal`` are normal project
    # names there and do not establish the PyPI/npm shadowing condition this
    # heuristic is designed to detect.
    if eco in {"go", "golang"}:
        return None

    # Scoped npm packages from known orgs are safe
    if eco == "npm" and any(name.startswith(scope) for scope in _SAFE_NPM_SCOPES):
        return None

    if any(name.startswith(prefix) for prefix in _SAFE_PUBLIC_NAME_PREFIXES_BY_ECOSYSTEM.get(eco, frozenset())):
        return None

    # Check for internal naming patterns. Weak service-ish tokens only count
    # when the package does not have a concrete public-registry version.
    has_strong_internal_pattern = any(pat in name for pat in _STRONG_INTERNAL_NAME_PATTERNS)
    has_weak_internal_pattern = any(pat in name for pat in _WEAK_INTERNAL_NAME_PATTERNS)
    has_internal_pattern = has_strong_internal_pattern or has_weak_internal_pattern
    if not has_internal_pattern:
        return None

    # If the package has vulnerability data, it's a known public package
    if package.vulnerabilities:
        return None

    # A digest-pinned artifact from the ecosystem's public registry is a public
    # package; an internal-looking name alone is not confusion evidence.
    if locked_from_public_registry(package):
        return None

    # If version was resolved from a registry, it's a known public package
    resolved_public_version = package.version not in ("unknown", "latest", "")
    if resolved_public_version and not has_strong_internal_pattern:
        return None

    if resolved_public_version:
        # Has a resolved version — likely exists on public registry
        # Only flag if it also has internal naming AND no scorecard data
        if getattr(package, "scorecard_score", None) is not None:
            return None

    return (
        f"Dependency confusion risk: '{package.name}' matches internal naming patterns "
        f"and has no public vulnerability or scorecard data. Verify this package is "
        f"from your intended registry."
    )
