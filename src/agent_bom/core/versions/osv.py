"""OSV range limits, separate from fixes and inclusive last-affected bounds.

The OSV evaluation algorithm requires membership below ANY explicit limit;
absence of limits (or an infinity limit) leaves the range unrestricted.
https://ossf.github.io/osv-schema/#evaluation
"""

from __future__ import annotations

from functools import cmp_to_key, lru_cache
from operator import ge, gt, lt

from agent_bom.core.versions.distro import OS_DISTRO_COMPARATOR_FAMILIES
from agent_bom.core.versions.ordering import compare_version_order
from agent_bom.core.versions.ranges import normalize_introduced
from agent_bom.core.versions.validation import _looks_like_commit_sha


def is_release_range(range_data: dict) -> bool:
    """Only ecosystem/semver ranges can place a package release version."""
    return (range_data.get("type") or "ECOSYSTEM") in ("SEMVER", "ECOSYSTEM")


def range_limits(events: list[dict]) -> tuple[str | None, ...]:
    """Return OR-ed exclusive bounds; an empty string represents infinity."""
    limits = {
        event["limit"] if isinstance(event["limit"], str) and event["limit"].strip() else None for event in events if "limit" in event
    }
    if not limits or "*" in limits:
        return ("",)
    return tuple(sorted(limits, key=lambda value: value or ""))


def before_limit(version: str, limit: str | None, ecosystem: str) -> bool | None:
    """Return unknown for unorderable bounds or metadata lost by an old DB."""
    if limit is None:
        return None
    if not limit:
        return True
    if _looks_like_commit_sha(limit):
        return None
    order = compare_version_order(version, limit, ecosystem)
    return order < 0 if order is not None else None


def range_match_state(
    version: str,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
    ecosystem: str = "",
    limit_version: str | None = "",
) -> str:
    limit_state = before_limit(version, limit_version, ecosystem)
    if limit_state is False:
        return "unaffected"
    ambiguous = limit_state is None
    uncomparable = False
    for bound, excludes in ((normalize_introduced(introduced), lt), (fixed, ge), (last_affected, gt)):
        if not bound:
            continue
        if _looks_like_commit_sha(bound):
            uncomparable = True
            continue
        comparison = compare_version_order(version, bound, ecosystem)
        if comparison is None:
            ambiguous = True
        elif excludes(comparison, 0):
            return "unaffected"
    if uncomparable:
        return "uncomparable"
    return "unknown" if ambiguous else "affected"


def ordered_range_events(events: list[dict], ecosystem: str) -> list[dict]:
    """Apply the OSV timeline in version order; source ordering is optional."""

    def compare(left: dict, right: dict) -> int:
        left_kind = next((key for key in ("introduced", "fixed", "last_affected") if key in left), "")
        right_kind = next((key for key in ("introduced", "fixed", "last_affected") if key in right), "")
        a, b = left[left_kind], right[right_kind]
        first_a, first_b = left_kind == "introduced" and a == "0", right_kind == "introduced" and b == "0"
        if first_a != first_b:
            return -1 if first_a else 1
        order = compare_version_order(a, b, ecosystem)
        if order is None:
            return 0  # the range evaluator retains incomparable-bound uncertainty
        if order:
            return order
        # A reintroduction at the same version opens the next interval.
        return (left_kind == "introduced") - (right_kind == "introduced")

    timeline = [event for event in events if any(key in event for key in ("introduced", "fixed", "last_affected"))]
    return sorted(timeline, key=cmp_to_key(compare))


def range_windows(events: list[dict], ecosystem: str = "") -> list[tuple[str | None, str | None, str | None]]:
    """Split OSV range ``events`` into ``(introduced, fixed, last_affected)`` windows.

    A window opens on ``introduced`` and closes on ``fixed`` or
    ``last_affected``; one left open at the end runs through latest. A range
    with no ``introduced`` at all is vulnerable from 0.
    """
    windows: list[tuple[str | None, str | None, str | None]] = []
    introduced: str | None = None
    window_open = False
    has_introduced = any("introduced" in event for event in events)
    for event in ordered_range_events(events, ecosystem):
        if "introduced" in event:
            if not window_open:
                introduced = event["introduced"]
                window_open = True
        elif "fixed" in event:
            if window_open or not has_introduced:
                windows.append((introduced, event["fixed"], None))
            introduced, window_open = None, False
        elif "last_affected" in event:
            if window_open or not has_introduced:
                windows.append((introduced, None, event["last_affected"]))
            introduced, window_open = None, False
    if window_open:
        windows.append((introduced, None, None))
    if not windows:
        windows.append((None, None, None))
    return windows


# Map a (possibly release-suffixed) DB ecosystem to a base family the version
# comparator understands. The RPM/apk distro families (Red Hat, Rocky, AlmaLinux,
# openSUSE/SUSE, Wolfi, Chainguard) come from ``core.versions.distro`` so the
# routing and comparator maps never drift apart.
_ECO_FAMILY_TO_COMPARATOR = {
    "debian": "deb",
    "ubuntu": "deb",
    "deb": "deb",
    "alpine": "apk",
    "apk": "apk",
    "rpm": "rpm",
    "linux": "rpm",
    **OS_DISTRO_COMPARATOR_FAMILIES,
}


def comparator_ecosystem(ecosystem: str) -> str:
    """Normalise a DB ecosystem to a key the version comparator can order.

    DB ``affected`` rows store distro ecosystems with a release suffix
    (``debian:10``, ``alpine:v3.18``, ``ubuntu:22.04``). The ecosystem-aware
    version comparator only recognises the base families (``deb``/``apk``/
    ``rpm``); handed the suffixed form it cannot pick a distro comparator and
    returns "unknown" for every range. That silently flips already-fixed distro
    advisories into conservative false positives (e.g. ``bash 5.0-4`` reported
    against a fix of ``4.3-9.1``). Normalising to the base family restores
    correct version ordering.
    """
    base = (ecosystem or "").split(":", 1)[0].strip().lower()
    return _ECO_FAMILY_TO_COMPARATOR.get(base, base)


@lru_cache(maxsize=131072)
def _cached_version_match_state(
    version: str,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
    ecosystem: str = "",
    limit_version: str | None = "",
) -> str:
    return range_match_state(version, introduced, fixed, last_affected, ecosystem, limit_version)


def version_match_state(
    version: str,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
    ecosystem: str = "",
    limit_version: str | None = "",
) -> str:
    """Classify one affected-range row for a version; the one verdict scan time and re-match share.

    Returns ``affected`` / ``unaffected`` for a definitive comparison,
    ``unknown`` for a genuine version-vs-version ambiguity, or ``uncomparable``
    when a bound is a git SHA / non-version token that can never match a
    concrete release (never a reason to include).
    """
    return _cached_version_match_state(version, introduced, fixed, last_affected, comparator_ecosystem(ecosystem), limit_version)


def is_valid_fix_version(version: str) -> bool:
    """Check if a string looks like a usable package version."""
    if not version or not any(c.isdigit() for c in version):
        return False
    stripped = version.lstrip("v")
    if len(stripped) == 40 and all(c in "0123456789abcdef" for c in stripped):
        return False
    if 7 <= len(stripped) <= 12 and all(c in "0123456789abcdef" for c in stripped):
        return False
    return True
