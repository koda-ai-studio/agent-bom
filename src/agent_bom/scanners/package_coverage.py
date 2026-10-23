"""Coverage reporting and supplemental advisory queries."""

from __future__ import annotations

from typing import Any

from agent_bom.constants import AI_PACKAGES as _AI_FRAMEWORK_PACKAGES
from agent_bom.malicious import check_dependency_confusion, check_typosquat
from agent_bom.models import Package
from agent_bom.scanners.local_data_freshness import local_db_untrusted, record_untrusted_local_data
from agent_bom.scanners.package_matching import _db_ecosystems_for_package as _db_ecosystems_for_package
from agent_bom.scanners.package_matching import _emit_scan_warning as _emit_scan_warning
from agent_bom.scanners.package_matching import _scanners_patchable as _scanners_patchable
from agent_bom.scanners.scan_options import IncompleteScanError, ScanOptions, _logger, _package_db_key
from agent_bom.scanners.state import record_coverage_warning


def _flag_remote_lookup_gap(osv_targets: list[Package]) -> None:
    """Flag packages that NOTHING could answer for: no local data, failed remote.

    A remote lookup error already surfaces as a scan warning, but on its own it
    does not say whether the answer was lost. When the local advisory DB also
    holds nothing for the package's ecosystem, a zero-vulnerability result is
    not a clean bill of health — nothing was consulted at all. Record it in the
    structured channel so `check` and `scan` can fail closed deterministically
    instead of reporting a confident ``clean``.
    """
    from agent_bom.scanners.state import peek_coverage_warnings

    if not any(warning.get("kind") == "remote_lookup_error" for warning in peek_coverage_warnings()):
        return
    target_ecosystems = {eco for package in osv_targets for eco in _db_ecosystems_for_package(package)}
    covered_ecos = _scanners_patchable("_db_covered_ecosystems")(target_ecosystems)
    uncovered = [pkg for pkg in osv_targets if not any(eco in covered_ecos for eco in _db_ecosystems_for_package(pkg))]
    if not uncovered:
        return
    gap_ecos = sorted({eco for pkg in uncovered for eco in _db_ecosystems_for_package(pkg)})
    eco_clause = f" ({', '.join(gap_ecos)})" if gap_ecos else ""
    _logger.warning(
        "Remote lookup failed for %d package(s) the local DB has no advisories for%s; results are incomplete",
        len(uncovered),
        eco_clause,
    )
    _emit_scan_warning(
        f"remote lookup failed for {len(uncovered)} package(s) in ecosystem(s)"
        f"{eco_clause} the local vulnerability DB has no advisories for; results are incomplete"
    )
    record_coverage_warning(
        {
            "kind": "remote_lookup_gap",
            "release": f"remote-gap:{','.join(gap_ecos)}",
            "ecosystems": gap_ecos,
            "package_count": len(uncovered),
        }
    )


def _detect_coverage_gaps(scannable: list[Package]) -> list[dict]:
    """Warn about OS releases (typically EOL) the local DB has no advisory data for; never alters matching."""
    coverage_gaps: list[dict] = []
    try:
        from agent_bom.coverage import detect_release_coverage_gaps

        coverage_gaps = detect_release_coverage_gaps(scannable)
        for gap in coverage_gaps:
            record_coverage_warning(gap)
            detail = str(gap.get("detail") or f"Vulnerability coverage for {gap['release']} is incomplete.")
            _emit_scan_warning(detail)
            _scanners_patchable("console").print(f"  [yellow]⚠[/yellow] [bold]Incomplete coverage:[/bold] {detail}")
    except Exception as exc:  # noqa: BLE001
        _logger.debug("coverage-gap detection skipped: %s", exc)
    return coverage_gaps


def _select_osv_targets(
    scannable: list[Package], offline: bool, local_db_targets: list[Package], db_covered: set[str], coverage_gaps: list[dict]
) -> tuple[list[Package], set[str]]:
    """Pick packages the local DB does not cover, plus stale or sparse (EOL) ones; also return covered ecosystems."""
    from agent_bom.coverage import osv_fallback_db_keys

    force_osv_keys = osv_fallback_db_keys(scannable, gaps=coverage_gaps) if not offline else set()
    sparse_osv_keys = force_osv_keys.copy()
    # A covered archive is only authoritative while fresh: online scans keep cached findings as
    # fallback but look for newer advisories even when a stale archive covers the package.
    if not offline and local_db_targets:
        if local_db_untrusted():
            force_osv_keys.update(_package_db_key(package) for package in local_db_targets)
    inventory_ecosystems = {eco for package in scannable for eco in _db_ecosystems_for_package(package)}
    covered_ecos = _scanners_patchable("_db_covered_ecosystems")(inventory_ecosystems)
    # An exact package hit or a complete ecosystem archive is sufficient local evidence; sparse-release
    # fallbacks override both so EOL coverage cannot be mistaken for a clean result.
    osv_targets = [
        p
        for p in scannable
        if (_package_db_key(p) not in db_covered and not any(eco in covered_ecos for eco in _db_ecosystems_for_package(p)))
        or _package_db_key(p) in force_osv_keys
    ]
    if force_osv_keys:
        _logger.info("Refreshing OSV coverage for %d package(s) with stale or sparse local evidence", len(force_osv_keys))
    if sparse_osv_keys:
        _emit_scan_warning(f"sparse local DB OSV fallback for {len(sparse_osv_keys)} package(s)")
    return osv_targets, covered_ecos


def _check_offline_coverage(scannable: list[Package], osv_targets: list[Package], covered_ecos: set[str], demo: bool) -> None:
    if not covered_ecos and osv_targets and not demo:
        # Genuinely empty/missing DB — nothing can be scanned offline.
        raise IncompleteScanError(
            "Offline mode requires a populated local vulnerability DB. Run "
            "`agent-bom db update --source osv` before using `--offline` "
            "(the all-ecosystems archive can exceed 1 GB), or drop `--offline`."
        )
    # A package with no DB rows in an ecosystem the DB covers is clean. Only ecosystems with zero
    # advisories are a real gap: warn loudly, but keep vulnerabilities found for covered packages.
    coverage_candidates = [] if demo else scannable
    uncovered = [p for p in coverage_candidates if not any(eco in covered_ecos for eco in _db_ecosystems_for_package(p))]
    if not uncovered:
        return
    gap_ecos = sorted({eco for p in uncovered for eco in _db_ecosystems_for_package(p)})
    skipped_names = ", ".join(f"{pkg.name}@{pkg.version}" for pkg in uncovered[:5])
    suffix = f" (+{len(uncovered) - 5} more)" if len(uncovered) > 5 else ""
    # A package can map to no DB ecosystem at all; never render an empty "()" in that case.
    eco_note = f" ({', '.join(gap_ecos)})" if gap_ecos else ""
    eco_clause = f" {', '.join(gap_ecos)}" if gap_ecos else ""
    _logger.warning("Offline mode: %d package(s) in ecosystem(s) with no local DB advisories%s skipped", len(uncovered), eco_note)
    _scanners_patchable("console").print(
        f"  [yellow]⚠[/yellow] Offline coverage gap: {len(uncovered)} package(s) in "
        f"ecosystem(s) the local DB has no advisories for{eco_note}: "
        f"{skipped_names}{suffix}. Run `agent-bom db update` for full coverage."
    )
    _emit_scan_warning(
        f"offline coverage gap: {len(uncovered)} package(s) in ecosystem(s){eco_clause} have no advisories in the local vulnerability DB"
    )
    # Structured signal so consumers (e.g. `check`) can fail closed deterministically: a zero-vuln
    # result for an ecosystem the local DB carries no advisories for is NOT a clean bill of health.
    record_coverage_warning(
        {
            "kind": "offline_ecosystem_gap",
            "release": f"offline:{','.join(gap_ecos)}",
            "ecosystems": gap_ecos,
            "package_count": len(uncovered),
        }
    )


_AMD_PACKAGE_PREFIXES = tuple(
    "rocm hip_ hipcc hip_base miopen rocblas rocsolver rccl rocprim rocthrust rocrand rocfft hipsparse hipblas "
    "composablekernel tensorflow_rocm jax_rocm".split()
)


async def _check_nvidia(packages: list[Package]) -> int:
    from agent_bom.scanners.nvidia_advisory import check_nvidia_advisories

    return await check_nvidia_advisories(packages)


async def _check_amd(packages: list[Package]) -> int:
    from agent_bom.scanners.amd_advisory import check_amd_advisories

    return check_amd_advisories(packages)


async def _check_ghsa(packages: list[Package]) -> int:
    from agent_bom.scanners.ghsa_advisory import check_github_advisories

    return await check_github_advisories(packages)


async def _run_supplemental_check(label: str, packages: list[Package], check: Any) -> int:
    new_count = 0
    try:
        new_count = await check(packages)
        if new_count:
            _scanners_patchable("console").print(f"  [green]✓[/green] {label} advisories: {new_count} additional CVE(s)")
    except Exception as exc:
        _logger.warning(label + " advisory check failed for %d package(s): %s", len(packages), exc)
        _scanners_patchable("console").print(f"  [yellow]⚠[/yellow] {label} advisory check skipped: {exc}")
        _emit_scan_warning(f"{label} advisory enrichment skipped")
    return new_count or 0


async def _scan_supplemental_advisories(scannable: list[Package], offline: bool) -> int:
    """Query NVIDIA, AMD PSIRT and GitHub advisories; return the additional CVE count."""
    added = 0
    # nvidia_advisory.py maps NVIDIA CSAF products to bundling frameworks (torch,
    # jax, vllm, etc.) so we pass ALL AI packages — not just nvidia-prefixed ones.
    nvidia_packages = [
        p
        for p in scannable
        if p.name.lower().replace("-", "_") in _AI_FRAMEWORK_PACKAGES
        or p.name.lower().replace("-", "") in _AI_FRAMEWORK_PACKAGES
        or (p.cpe or "").startswith("cpe:2.3:a:nvidia:")
    ]
    if nvidia_packages and not offline:
        added += await _run_supplemental_check("NVIDIA", nvidia_packages, _check_nvidia)

    # AMD PSIRT advisories for ROCm / HIP packages.
    amd_packages = [p for p in scannable if any(p.name.lower().replace("-", "_").startswith(prefix) for prefix in _AMD_PACKAGE_PREFIXES)]
    if amd_packages:
        added += await _run_supplemental_check("AMD", amd_packages, _check_amd)

    if scannable and not offline:
        added += await _run_supplemental_check("GHSA", scannable, _check_ghsa)
    return added


def _flag_suspicious_packages(scannable: list[Package]) -> None:
    for pkg in scannable:
        if not pkg.is_malicious:
            target = check_typosquat(pkg.name, pkg.ecosystem)
            if target:
                pkg.is_malicious = True
                pkg.malicious_reason = f"Possible typosquat of '{target}'"
            # Dependency confusion check
            confusion_warning = check_dependency_confusion(pkg)
            if confusion_warning and not pkg.is_malicious:
                pkg.is_malicious = True
                pkg.malicious_reason = confusion_warning


async def _query_osv_results(
    scannable: list[Package], osv_targets: list[Package], covered_ecos: set[str], scan_options: ScanOptions
) -> dict[str, list[dict]]:
    scan_offline = scan_options.offline
    if scan_offline or (scan_options.prefer_local_db and not osv_targets):
        if scan_offline:
            _check_offline_coverage(scannable, osv_targets, covered_ecos, scan_options.demo_advisories)
        results: dict[str, list[dict]] = {}
    elif scan_options.prefer_local_db and osv_targets:
        # DB is fresh — only query OSV for packages genuinely missing from DB
        _logger.debug("Local DB preferred: querying OSV for %d uncovered package(s) only", len(osv_targets))
        results = await _scanners_patchable("query_osv_batch")(osv_targets)
    elif osv_targets:
        results = await _scanners_patchable("query_osv_batch")(osv_targets)
    else:
        results = {}

    if not scan_offline and osv_targets:
        _flag_remote_lookup_gap(osv_targets)
    record_untrusted_local_data(offline=scan_offline, demo=scan_options.demo_advisories)
    return results
