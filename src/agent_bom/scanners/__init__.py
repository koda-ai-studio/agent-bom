"""Vulnerability scanning — re-exports for ``agent_bom.scanners`` public surface.

The ``package_scan`` re-exports resolve on first use: importing any
``agent_bom.scanners.*`` submodule (the CLI does this for ``--help``) must not
pay for the vulnerability-matching stack.
"""

import importlib
import sys
from types import ModuleType
from typing import TYPE_CHECKING, Any

from agent_bom.scanners.blast_radius import expand_blast_radius_hops
from agent_bom.scanners.registry import (
    ScannerExecutionState,
    ScannerFailureMode,
    ScannerPhase,
    ScannerRegistration,
    builtin_scanner_registrations,
    get_scanner_registration,
    list_registered_scanners,
    register_scanner,
    scanner_registry_summary,
    scanner_registry_warnings,
)
from agent_bom.scanners.risk import (
    advisory_id_severity_fallback,
    cvss_to_severity,
    parse_cvss_vector,
    parse_osv_severity,
    severity_from_label,
)
from agent_bom.scanners.state import (
    _get_api_semaphore,
    consume_coverage_warnings,
    consume_scan_performance,
    consume_scan_warnings,
    peek_coverage_warnings,
    record_coverage_warning,
    record_scan_warning,
    reset_scan_performance,
    reset_scan_warnings,
    reset_scan_warnings_only,
)

if TYPE_CHECKING:
    from agent_bom.scanners.package_scan import (
        _AI_FRAMEWORK_PACKAGES,
        _NON_OSV_ECOSYSTEMS,
        BATCH_DELAY_SECONDS,
        ECOSYSTEM_MAP,
        MAX_CONCURRENT_REQUESTS,
        IncompleteScanError,
        ScanOptions,
        _bump_scan_perf,
        _db_covered_ecosystems,
        _db_ecosystems_for_package,
        _enrich_results_if_needed,
        _get_scan_cache,
        _include_unfixed_enabled,
        _is_valid_fix_version,
        _is_version_affected,
        _local_vuln_to_vulnerability,
        _osv_ecosystems_for_package,
        _parse_cvss4_vector,
        _scan_cache_instance,
        _scan_packages_db_conn,
        _scan_packages_local_db,
        _strip_extras,
        _suppress_unfixed_os_advisories,
        build_vulnerabilities,
        compliance_mode,
        console,
        create_client,
        deduplicate_packages,
        default_scan_options,
        offline_mode,
        parse_fixed_version,
        prefer_local_db,
        query_osv_batch,
        request_with_retry,
        scan_agents,
        scan_agents_sync,
        scan_agents_with_enrichment,
        scan_packages,
        set_include_unfixed,
        set_offline_mode,
    )

_PACKAGE_SCAN_EXPORTS = frozenset(
    {
        "_AI_FRAMEWORK_PACKAGES",
        "_NON_OSV_ECOSYSTEMS",
        "BATCH_DELAY_SECONDS",
        "ECOSYSTEM_MAP",
        "MAX_CONCURRENT_REQUESTS",
        "IncompleteScanError",
        "ScanOptions",
        "_bump_scan_perf",
        "_db_covered_ecosystems",
        "_db_ecosystems_for_package",
        "_enrich_results_if_needed",
        "_get_scan_cache",
        "_include_unfixed_enabled",
        "_is_valid_fix_version",
        "_is_version_affected",
        "_local_vuln_to_vulnerability",
        "_osv_ecosystems_for_package",
        "_parse_cvss4_vector",
        "_scan_cache_instance",
        "_scan_packages_db_conn",
        "_scan_packages_local_db",
        "_strip_extras",
        "_suppress_unfixed_os_advisories",
        "build_vulnerabilities",
        "compliance_mode",
        "console",
        "create_client",
        "deduplicate_packages",
        "default_scan_options",
        "offline_mode",
        "parse_fixed_version",
        "prefer_local_db",
        "query_osv_batch",
        "request_with_retry",
        "scan_agents",
        "scan_agents_sync",
        "scan_agents_with_enrichment",
        "scan_packages",
        "set_include_unfixed",
        "set_offline_mode",
    }
)


__all__ = [
    "BATCH_DELAY_SECONDS",
    "ECOSYSTEM_MAP",
    "IncompleteScanError",
    "MAX_CONCURRENT_REQUESTS",
    "ScanOptions",
    "ScannerExecutionState",
    "ScannerFailureMode",
    "ScannerPhase",
    "ScannerRegistration",
    "_AI_FRAMEWORK_PACKAGES",
    "_NON_OSV_ECOSYSTEMS",
    "_bump_scan_perf",
    "_db_covered_ecosystems",
    "_db_ecosystems_for_package",
    "_enrich_results_if_needed",
    "_get_api_semaphore",
    "_get_scan_cache",
    "_include_unfixed_enabled",
    "_is_valid_fix_version",
    "_is_version_affected",
    "_local_vuln_to_vulnerability",
    "_osv_ecosystems_for_package",
    "_parse_cvss4_vector",
    "_scan_packages_db_conn",
    "_scan_packages_local_db",
    "_scan_cache_instance",
    "_strip_extras",
    "_suppress_unfixed_os_advisories",
    "advisory_id_severity_fallback",
    "build_vulnerabilities",
    "builtin_scanner_registrations",
    "compliance_mode",
    "console",
    "create_client",
    "consume_scan_performance",
    "consume_scan_warnings",
    "cvss_to_severity",
    "deduplicate_packages",
    "default_scan_options",
    "expand_blast_radius_hops",
    "get_scanner_registration",
    "list_registered_scanners",
    "offline_mode",
    "parse_cvss_vector",
    "parse_fixed_version",
    "parse_osv_severity",
    "peek_coverage_warnings",
    "prefer_local_db",
    "query_osv_batch",
    "record_coverage_warning",
    "record_scan_warning",
    "register_scanner",
    "request_with_retry",
    "reset_scan_performance",
    "reset_scan_warnings",
    "reset_scan_warnings_only",
    "scan_agents",
    "scan_agents_sync",
    "scan_agents_with_enrichment",
    "scan_packages",
    "scanner_registry_summary",
    "scanner_registry_warnings",
    "set_include_unfixed",
    "set_offline_mode",
    "severity_from_label",
]


def _package_scan() -> ModuleType:
    return importlib.import_module("agent_bom.scanners.package_scan")


def __getattr__(name: str) -> Any:
    if name == "package_scan":
        return _package_scan()
    if name in _PACKAGE_SCAN_EXPORTS:
        return getattr(_package_scan(), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | _PACKAGE_SCAN_EXPORTS)


class _ScannersModule(ModuleType):
    """Synchronize legacy package patches with the implementation module."""

    def __setattr__(self, name: str, value: object) -> None:
        # The import system binds each submodule onto this package; syncing
        # those would load package_scan on every submodule import.
        if not isinstance(value, ModuleType):
            package_scan = _package_scan()
            if hasattr(package_scan, name):
                _PATCHED_ORIGINALS.setdefault(name, getattr(package_scan, name))
                setattr(package_scan, name, value)
        super().__setattr__(name, value)

    def __delattr__(self, name: str) -> None:
        # unittest.mock removes a patch on a lazily resolved name with delattr;
        # put the implementation module back the way the patch found it.
        if name in _PATCHED_ORIGINALS:
            setattr(_package_scan(), name, _PATCHED_ORIGINALS.pop(name))
        super().__delattr__(name)


_PATCHED_ORIGINALS: dict[str, object] = {}


sys.modules[__name__].__class__ = _ScannersModule
