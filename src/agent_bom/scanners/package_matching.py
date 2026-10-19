"""Scanners package matching helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_bom.advisory_ids import MATCH_CONFIDENCE_AMBIGUOUS_DISTRO_RELEASE
from agent_bom.core.versions.osv import before_limit, is_release_range, range_limits
from agent_bom.core.versions.osv import range_windows as _range_windows
from agent_bom.models import Package, Vulnerability
from agent_bom.os_advisory import apk_advisory_ecosystems, rpm_advisory_ecosystems, scope_rpm_advisory
from agent_bom.package_utils import (
    alpine_osv_fallback_ecosystems,
    alpine_release_branch,
    debian_release_branch,
    normalize_package_name,
    ubuntu_release_branch,
)
from agent_bom.scanners.osv import candidate_package_names as _candidate_package_names
from agent_bom.scanners.osv import ecosystem_matches as _ecosystem_matches

if TYPE_CHECKING:
    pass


def _scanners_patchable(name: str) -> Any:
    """Resolve a test-patchable symbol from ``agent_bom.scanners``."""
    import agent_bom.scanners as scanners_mod

    return getattr(scanners_mod, name)


def _emit_scan_warning(message: str) -> None:
    _scanners_patchable("record_scan_warning")(message)


# Map ecosystem names to OSV ecosystem identifiers
ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "composer": "Packagist",
    "swift": "SwiftURL",
    "pub": "Pub",
    "hex": "Hex",
    # conda packages are pip-installable and tracked under PyPI in OSV
    "conda": "PyPI",
    # OS package ecosystems are distro-versioned in OSV, so query_osv_batch
    # resolves them dynamically from package distro metadata rather than using
    # these flat placeholders directly.
    "deb": "Debian",
    "apk": "Alpine",
    # RPM covers RHEL, CentOS, Fedora, Rocky, Alma — OSV "Linux" is the
    # cross-distro ecosystem that matches all RPM-based advisories.
    "rpm": "Linux",
}

_DEBIAN_OSV_FALLBACKS = ("Debian:11", "Debian:12", "Debian:13", "Debian:14")

_ALPINE_OSV_FALLBACKS = alpine_osv_fallback_ecosystems()


def _resolve_osv_ecosystems(pkg: Package, *, for_local_db: bool) -> list[str]:
    """Return OSV ecosystem identifier(s) for a package.

    ``for_local_db`` selects the key variant: the local DB stores RPM-distro
    advisories under a per-major key (e.g. ``Red Hat:enterprise_linux:8``) while
    the live OSV API is queried with the bare distro ecosystem it accepts
    (``Red Hat``). Every other ecosystem resolves identically for both paths.
    """
    eco_key = pkg.ecosystem.lower()

    if eco_key == "deb":
        distro_name = (pkg.distro_name or "").lower()
        distro_version = (pkg.distro_version or "").strip()
        if distro_name == "debian" and distro_version:
            return [f"Debian:{debian_release_branch(distro_version)}"]
        if distro_name == "ubuntu" and distro_version:
            normalized = ubuntu_release_branch(distro_version)
            if normalized.count(".") == 1:
                return [f"Ubuntu:{normalized}:LTS", f"Ubuntu:{normalized}"]
            return [f"Ubuntu:{normalized}"]
        return list(_DEBIAN_OSV_FALLBACKS)

    if eco_key == "apk":
        # Wolfi/Chainguard are apk-based but use their own version-less ecosystems.
        non_alpine = apk_advisory_ecosystems(pkg.distro_name)
        if non_alpine:
            return non_alpine
        distro_version = (pkg.distro_version or "").strip()
        if distro_version:
            # Alpine advisories are keyed by minor branch (``v3.16``), so a full
            # VERSION_ID (``3.16.9``) must be truncated or every lookup returns 0 rows.
            return [f"Alpine:{alpine_release_branch(distro_version)}"]
        return list(_ALPINE_OSV_FALLBACKS)

    if eco_key == "rpm":
        # RHEL/CentOS, Rocky, AlmaLinux and openSUSE Leap advisories are carried
        # by the OSV bulk export under distro-specific ecosystems. Fall back to
        # the cross-distro "Linux" ecosystem only when the distro is unresolved.
        distro = rpm_advisory_ecosystems(pkg.distro_name, pkg.distro_version, for_local_db=for_local_db)
        if distro:
            return distro

    osv_ecosystem = ECOSYSTEM_MAP.get(eco_key)
    return [osv_ecosystem] if osv_ecosystem else []


def ambiguous_distro_releases(pkg: Any) -> tuple[str, list[str]] | None:
    """Release branches a distro package is being matched against blindly.

    An apk/deb package with no usable release metadata is queried against EVERY
    supported release branch. That union is deliberate — picking one branch would
    silently drop true positives for all the others, and under-reporting is the
    worse failure for a scanner. But the union cannot distinguish "vulnerable on
    your release" from "vulnerable on some release", and the fix version it
    resolves belongs to whichever branch happened to match. Returns
    ``(distro_label, branches)`` when that is the situation, else ``None``.
    """
    # ``merge_local_vulns`` accepts any package-shaped object, so read
    # defensively rather than assuming the full Package dataclass.
    eco_key = str(getattr(pkg, "ecosystem", "") or "").lower()
    distro_name = getattr(pkg, "distro_name", None)
    distro_version = str(getattr(pkg, "distro_version", "") or "").strip()
    if eco_key == "deb":
        if str(distro_name or "").lower() in {"debian", "ubuntu"} and distro_version:
            return None
        return "Debian/Ubuntu", list(_DEBIAN_OSV_FALLBACKS)
    if eco_key == "apk":
        if apk_advisory_ecosystems(distro_name):
            # Wolfi/Chainguard are undated rolling repos: one version-less
            # ecosystem, so there is no release to be ambiguous about.
            return None
        if distro_version:
            return None
        return "Alpine", list(_ALPINE_OSV_FALLBACKS)
    return None


def _apply_distro_release_ambiguity(pkg: Any, vulns: list[Vulnerability]) -> None:
    """Mark findings produced by a blind multi-release match, in place.

    Three things the union previously left unsaid:

    * ``match_confidence_tier`` claimed ``osv_range`` confidence for a match
      whose release is unknown,
    * ``fixed_version`` recommended a branch-specific upgrade target that can
      belong to a different release branch than the installed package
      (``openssl@3.0.11-r0`` was told to upgrade to the v3.23 branch's
      ``3.5.7-r0``), and
    * nothing reached ``scan_warnings``, so the ambiguity was invisible.
    """
    ambiguity = ambiguous_distro_releases(pkg)
    if not ambiguity or not vulns:
        return
    distro_label, branches = ambiguity
    branch_names = [branch.split(":", 1)[-1] for branch in branches]
    for vuln in vulns:
        vuln.match_confidence_tier = MATCH_CONFIDENCE_AMBIGUOUS_DISTRO_RELEASE
        vuln.fixed_version = None
    label = f"{getattr(pkg, 'name', '?')}@{getattr(pkg, 'version', '?')}"
    _emit_scan_warning(
        f"{label}: no {distro_label} release was specified, so it was matched against all "
        f"{len(branch_names)} release branches ({', '.join(branch_names)}). Findings may not apply "
        f"to your release and fix recommendations are withheld — re-run with the distro release to "
        f"resolve both."
    )


def _scope_advisory_to_package_release(vuln_data: dict, package: Package) -> dict | None:
    """Keep only affected entries for the package's observed OS release.

    OSV query responses are release-scoped, but their enriched advisory record
    contains every distro branch.  Passing that full record to fix extraction
    lets a Debian 14 fix appear actionable on Debian 12/13.  Preserve the
    conservative unscoped behavior when release metadata is absent; otherwise
    an explicitly different release is not evidence for this package.
    """
    if package.ecosystem.lower() not in {"deb", "apk", "rpm"} or ambiguous_distro_releases(package):
        return vuln_data
    if package.ecosystem.lower() == "rpm":
        return scope_rpm_advisory(vuln_data, package.distro_name, package.distro_version)
    expected = {value.lower() for value in _resolve_osv_ecosystems(package, for_local_db=False)}
    if not expected:
        return vuln_data
    expected_families = {value.split(":", 1)[0] for value in expected}
    affected = list(vuln_data.get("affected", []))
    same_family = [
        entry for entry in affected if str(entry.get("package", {}).get("ecosystem", "")).lower().split(":", 1)[0] in expected_families
    ]
    if not same_family:
        return vuln_data
    release_entries = [entry for entry in same_family if str(entry.get("package", {}).get("ecosystem", "")).lower() in expected]
    if not release_entries:
        return None
    return {**vuln_data, "affected": release_entries}


def _osv_ecosystems_for_package(pkg: Package) -> list[str]:
    """Return one or more OSV ecosystem identifiers for a package (live API path)."""
    return _resolve_osv_ecosystems(pkg, for_local_db=False)


def _db_ecosystems_for_package(pkg: Package) -> list[str]:
    """Return normalized local-DB ecosystem keys for a package."""
    return [eco.lower() for eco in _resolve_osv_ecosystems(pkg, for_local_db=True)]


def _version_matches_list(version: str, versions_list: list[str], ecosystem: str = "") -> bool:
    """Whether ``version`` equals any entry in an OSV ``affected[].versions`` list.

    Uses version-normalized equality so PEP 440 / SemVer trailing-zero forms
    match (``2.2.0`` == ``2.2``, ``2.3`` == ``2.3.0``). Falls back to the raw
    membership test first for speed and for versions that don't parse.
    """
    if version in versions_list:
        return True
    from agent_bom.version_utils import compare_version_order

    for candidate in versions_list:
        if candidate == version:
            return True
        try:
            if compare_version_order(version, candidate, ecosystem) == 0:
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _version_in_window(
    version: str,
    window: tuple[str | None, str | None, str | None],
    ecosystem: str,
) -> bool:
    """Return whether *version* falls inside one vulnerable window.

    Delegates to :func:`version_utils.version_in_range` so the OSV walker and
    the DB/GHSA read paths share ONE range engine with ONE policy. This module
    used to carry its own copy that skipped any bound it could not compare
    (``if fixed_cmp is not None and fixed_cmp >= 0``) — failing OPEN, so the
    same package got opposite verdicts depending on which engine served the
    query. ``version_in_range`` fails CLOSED and records the dropped bound.
    """
    from agent_bom.version_utils import normalize_introduced, version_in_range

    introduced, fixed, last_affected = window
    # ``introduced: 0`` is not a real bound — it means "vulnerable from the
    # beginning", so package identity alone establishes the match and no
    # comparison should be required to confirm it. ``version_in_range`` now
    # applies the same rule for every caller; resolving here too keeps this
    # walker's intent explicit at the call site.
    return version_in_range(version, normalize_introduced(introduced), fixed, last_affected, ecosystem)


def _window_has_commit_bound(window: tuple[str | None, str | None, str | None]) -> bool:
    """Whether any bound in a vulnerable window is a git commit rather than a version.

    ``introduced: "0"`` is OSV's "from the beginning" sentinel, not a commit, so
    a window bounded only by it stays decidable.

    Reuses ``version_utils``' heuristic rather than restating it: the two range
    engines already share one comparison policy, and a second copy of "is this a
    SHA?" is exactly how they drifted apart before.
    """
    from agent_bom.version_utils import _looks_like_commit_sha

    return any(bound and bound != "0" and _looks_like_commit_sha(bound) for bound in window)


def _warn_unresolvable_git_bounds(advisory_id: str, package_name: str, package_version: str) -> None:
    """Record that an advisory was skipped because only commit bounds exist.

    ``record_scan_warning`` dedupes by message, so a corpus with many such
    advisories yields one line per advisory/package pair rather than a flood.
    """
    _emit_scan_warning(
        f"{advisory_id}: {package_name}@{package_version} could not be evaluated — the advisory bounds this "
        f"package only by git commit, which carries no order against a release version. The package may be "
        f"affected; check the advisory directly."
    )


def _matches_advisory_ranges(ranges: list[dict], package_version: str, ecosystem: str, advisory_id: str, package_name: str) -> bool:
    """Evaluate each range independently, retaining unknown-bound warnings."""
    # Check ranges
    comparable_windows = 0
    for rng in ranges:
        if not is_release_range(rng):
            continue

        events = rng.get("events", [])

        limits = [before_limit(package_version, limit, ecosystem) for limit in range_limits(events)]
        if True not in limits:
            if all(value is False for value in limits):
                comparable_windows += 1  # evaluated and outside the exclusive limit
            else:
                _emit_scan_warning(
                    f"{advisory_id}: {package_name}@{package_version} has an "
                    "unresolvable advisory range limit; affected status is unknown. Check the source advisory."
                )
                comparable_windows += 1  # already emitted the specific uncertainty
            continue
        # A range may carry several vulnerable windows as alternating
        # introduced/fixed events. Collect them first, then test each on its
        # own: treating a later ``introduced`` as a reset of the running
        # verdict discards an earlier window the version already matched.
        for window in _range_windows(events, ecosystem):
            # A commit SHA carries no order relative to a release version:
            # placing one inside such a window needs the repository's commit
            # graph, which the scanner does not have. Drop the window here
            # so the guess never reaches the comparator.
            if _window_has_commit_bound(window):
                continue
            comparable_windows += 1
            if _version_in_window(package_version, window, ecosystem):
                return True

    if not comparable_windows:
        # Every window for this package was commit-bounded. The advisory is
        # real but unresolvable here — surface it instead of letting it look
        # like a clean result.
        _warn_unresolvable_git_bounds(advisory_id, package_name, package_version)
    return False


def _is_version_affected(
    vuln_data: dict,
    package_name: str,
    package_version: str,
    ecosystem: str = "",
    source_package: str | None = None,
    aliases: tuple[str, ...] = (),
) -> bool:
    """Check if a specific version falls within the OSV affected ranges.

    Applies ecosystem version ordering to ``affected[].ranges[].events[]``:

    - ``introduced``: version >= introduced means potentially affected
    - ``fixed``: version >= fixed means NOT affected (patched)
    - ``last_affected``: version > last_affected means NOT affected

    Returns True if the version IS affected, False if it's been fixed
    or explicitly names a different package/ecosystem. Missing query-stub
    scope retains the upstream association; incomparable bounds do not match.
    """

    norm_names = _candidate_package_names(package_name, ecosystem, source_package, aliases)

    found_package = False

    for affected in vuln_data.get("affected", []):
        pkg = affected.get("package", {})
        osv_eco = pkg.get("ecosystem", ecosystem)
        # Shared advisories list affected entries across ecosystems; only match
        # against same-ecosystem entries so a different ecosystem's range/version
        # set can't (falsely) include or exclude our package.
        if not _ecosystem_matches(osv_eco, ecosystem):
            continue
        osv_name = normalize_package_name(pkg.get("name", ""), osv_eco)
        if osv_name not in norm_names:
            continue

        found_package = True

        # Check explicit version list first (OSV enumerates affected versions
        # here). Compare version-normalized so "2.2.0" matches an enumerated
        # "2.2" — a raw string ``in`` check drops trailing-zero equivalents.
        versions_list = affected.get("versions", [])
        if versions_list and _version_matches_list(package_version, versions_list, ecosystem):
            return True

        ranges = affected.get("ranges", [])
        if not ranges:
            # No ranges. With an explicit list, that list is the block's whole
            # version statement and this version is not in it. Without one the
            # advisory carries no version scoping at all — stay conservative.
            if versions_list:
                continue
            return True

        if versions_list:
            # ``versions`` enumerates the releases that EXISTED when the
            # advisory was imported; it is not a bound. Treating it as
            # exhaustive dropped every advisory for a release published later
            # than the import (typo3/cms-core 10.4.35 lost all 29 of them) and
            # for any release the importer spelled differently (``v10.4.9``).
            # Fall through to the ranges — but only the ecosystem-typed ones: a
            # GIT tag walk cannot place an ecosystem version string, and its
            # ``introduced: 0`` would match everything.
            ranges = [rng for rng in ranges if is_release_range(rng)]
            if not ranges:
                continue

        if _matches_advisory_ranges(ranges, package_version, ecosystem, vuln_data.get("id", "unknown"), package_name):
            return True

    # Matching coordinates were evaluated, but no version window matched.
    if found_package:
        return False  # ranges were checked and version is outside all of them

    # Explicit other coordinates contradict a cache/query association;
    # preserve the upstream association only for incomplete query stubs.
    return not any(entry.get("package", {}).get("name") for entry in vuln_data.get("affected", []))
