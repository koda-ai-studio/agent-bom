"""Declared version constraints that bound a registry version lookup."""

from __future__ import annotations

from typing import Optional

from agent_bom.models import Package
from agent_bom.parsers.npm_semver import classify_npm_spec
from agent_bom.parsers.npm_semver import satisfies as npm_satisfies

_CONSTRAINT_CHARS = frozenset("^~<>=*|, ")


def _declared_constraint(pkg: Package) -> Optional[str]:
    """Return the declared range/tag that bounds *pkg*'s version, if any.

    ``None`` means the package declares no constraint (or only ``latest``), so
    the ``latest`` lookup is the honest answer. A returned constraint must be
    honoured: resolving it to ``latest`` can report a version the declaration
    excludes and match that version's advisories.
    """
    declared = pkg.declared_version
    if declared is None:
        return None
    declared = declared.strip()
    if declared == "latest":
        return None
    ecosystem = pkg.ecosystem.lower()
    if ecosystem == "npm":
        return None if classify_npm_spec(declared) == "exact" else declared
    if ecosystem == "pypi":
        from packaging.specifiers import InvalidSpecifier, SpecifierSet

        try:
            return declared if declared and str(SpecifierSet(declared)) else None
        except InvalidSpecifier:
            return None
    if pkg.floating_reference and declared and any(ch in _CONSTRAINT_CHARS for ch in declared):
        return declared
    return None


def _constraint_admits(ecosystem: str, version: str, constraint: str) -> bool:
    if ecosystem == "npm":
        return npm_satisfies(version, constraint)
    if ecosystem == "pypi":
        from packaging.specifiers import InvalidSpecifier, SpecifierSet
        from packaging.version import InvalidVersion, Version

        try:
            return SpecifierSet(constraint).contains(Version(version))
        except (InvalidSpecifier, InvalidVersion):
            return False
    return False
