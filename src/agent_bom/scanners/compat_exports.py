"""Lazy compatibility for historical scanner helper imports.

This registry does not import helpers until callers request them. Mutable scan
controls remain on package_scan; this table contains only legacy helper bindings.
"""

from importlib import import_module
from typing import Any

_EXPORTS = {
    "_target_venv_python": ("agent_bom.scanners.package_preparation", "_target_venv_python"),
    "IncompleteScanError": ("agent_bom.scanners.scan_options", "IncompleteScanError"),
    "_warn_unresolved_packages": ("agent_bom.scanners.package_preparation", "_warn_unresolved_packages"),
    "_strip_extras": ("agent_bom.scanners.package_preparation", "_strip_extras"),
    "merge_local_vulns": ("agent_bom.scanners.local_advisories", "merge_local_vulns"),
    "_local_vuln_to_vulnerability": ("agent_bom.scanners.local_advisories", "_local_vuln_to_vulnerability"),
    "_BATCH_DB_THRESHOLD": ("agent_bom.scanners.local_advisories", "_BATCH_DB_THRESHOLD"),
    "_scan_packages_local_db": ("agent_bom.scanners.local_advisories", "_scan_packages_local_db"),
    "_scan_packages_db_conn": ("agent_bom.scanners.local_advisories", "_scan_packages_db_conn"),
    "_attach_cpe_candidates": ("agent_bom.scanners.local_advisories", "_attach_cpe_candidates"),
    "_scan_packages_demo_advisories": ("agent_bom.scanners.local_advisories", "_scan_packages_demo_advisories"),
    "_scan_packages_local_db_batch": ("agent_bom.scanners.local_advisories", "_scan_packages_local_db_batch"),
    "_apply_installed_versions": ("agent_bom.scanners.package_preparation", "_apply_installed_versions"),
    "_AMD_PACKAGE_PREFIXES": ("agent_bom.scanners.package_coverage", "_AMD_PACKAGE_PREFIXES"),
    "_check_nvidia": ("agent_bom.scanners.package_coverage", "_check_nvidia"),
    "_check_amd": ("agent_bom.scanners.package_coverage", "_check_amd"),
    "_check_ghsa": ("agent_bom.scanners.package_coverage", "_check_ghsa"),
    "_run_supplemental_check": ("agent_bom.scanners.package_coverage", "_run_supplemental_check"),
    "BATCH_DELAY_SECONDS": ("agent_bom.config", "SCANNER_BATCH_DELAY"),
    "_BATCH_SIZE": ("agent_bom.config", "SCANNER_BATCH_SIZE"),
    "MAX_CONCURRENT_REQUESTS": ("agent_bom.config", "SCANNER_MAX_CONCURRENT"),
    "before_limit": ("agent_bom.core.versions.osv", "before_limit"),
    "is_release_range": ("agent_bom.core.versions.osv", "is_release_range"),
    "range_limits": ("agent_bom.core.versions.osv", "range_limits"),
    "_range_windows": ("agent_bom.core.versions.osv", "range_windows"),
    "is_scope_exclusion": ("agent_bom.coverage", "is_scope_exclusion"),
    "_cpe_vendor_hint": ("agent_bom.cpe_match", "cpe_vendor_hint"),
    "OfflineModeError": ("agent_bom.http_client", "OfflineModeError"),
    "request_with_retry": ("agent_bom.http_client", "request_with_retry"),
    "check_dependency_confusion": ("agent_bom.malicious", "check_dependency_confusion"),
    "check_typosquat": ("agent_bom.malicious", "check_typosquat"),
    "Severity": ("agent_bom.models", "Severity"),
    "apk_advisory_ecosystems": ("agent_bom.os_advisory", "apk_advisory_ecosystems"),
    "rpm_advisory_ecosystems": ("agent_bom.os_advisory", "rpm_advisory_ecosystems"),
    "scope_rpm_advisory": ("agent_bom.os_advisory", "scope_rpm_advisory"),
    "alpine_osv_fallback_ecosystems": ("agent_bom.package_utils", "alpine_osv_fallback_ecosystems"),
    "alpine_release_branch": ("agent_bom.package_utils", "alpine_release_branch"),
    "canonical_package_identity": ("agent_bom.package_utils", "canonical_package_identity"),
    "canonical_package_key": ("agent_bom.package_utils", "canonical_package_key"),
    "debian_release_branch": ("agent_bom.package_utils", "debian_release_branch"),
    "normalize_package_name": ("agent_bom.package_utils", "normalize_package_name"),
    "package_purl": ("agent_bom.package_utils", "package_purl"),
    "ubuntu_release_branch": ("agent_bom.package_utils", "ubuntu_release_branch"),
    "_candidate_package_names": ("agent_bom.scanners.osv", "candidate_package_names"),
    "_ecosystem_matches": ("agent_bom.scanners.osv", "ecosystem_matches"),
    "_is_valid_fix_version": ("agent_bom.scanners.osv", "is_valid_fix_version"),
    "_package_lookup_names": ("agent_bom.scanners.osv", "package_lookup_names"),
    "_ALPINE_OSV_FALLBACKS": ("agent_bom.scanners.package_matching", "_ALPINE_OSV_FALLBACKS"),
    "_DEBIAN_OSV_FALLBACKS": ("agent_bom.scanners.package_matching", "_DEBIAN_OSV_FALLBACKS"),
    "ECOSYSTEM_MAP": ("agent_bom.scanners.package_matching", "ECOSYSTEM_MAP"),
    "_db_ecosystems_for_package": ("agent_bom.scanners.package_matching", "_db_ecosystems_for_package"),
    "_matches_advisory_ranges": ("agent_bom.scanners.package_matching", "_matches_advisory_ranges"),
    "_resolve_osv_ecosystems": ("agent_bom.scanners.package_matching", "_resolve_osv_ecosystems"),
    "_version_in_window": ("agent_bom.scanners.package_matching", "_version_in_window"),
    "_version_matches_list": ("agent_bom.scanners.package_matching", "_version_matches_list"),
    "_warn_unresolvable_git_bounds": ("agent_bom.scanners.package_matching", "_warn_unresolvable_git_bounds"),
    "_window_has_commit_bound": ("agent_bom.scanners.package_matching", "_window_has_commit_bound"),
    "ambiguous_distro_releases": ("agent_bom.scanners.package_matching", "ambiguous_distro_releases"),
    "_is_unresolved_version": ("agent_bom.scanners.package_versions", "is_unresolved_version"),
    "_parse_cvss4_vector": ("agent_bom.scanners.risk", "_parse_cvss4_vector"),
    "advisory_id_severity_fallback": ("agent_bom.scanners.risk", "advisory_id_severity_fallback"),
    "cvss_to_severity": ("agent_bom.scanners.risk", "cvss_to_severity"),
    "parse_cvss_vector": ("agent_bom.scanners.risk", "parse_cvss_vector"),
    "severity_from_label": ("agent_bom.scanners.risk", "severity_from_label"),
    "consume_coverage_warnings": ("agent_bom.scanners.state", "consume_coverage_warnings"),
    "consume_scan_performance": ("agent_bom.scanners.state", "consume_scan_performance"),
    "consume_scan_warnings": ("agent_bom.scanners.state", "consume_scan_warnings"),
    "record_coverage_warning": ("agent_bom.scanners.state", "record_coverage_warning"),
    "record_scan_warning": ("agent_bom.scanners.state", "record_scan_warning"),
    "reset_scan_performance": ("agent_bom.scanners.state", "reset_scan_performance"),
    "reset_scan_warnings_only": ("agent_bom.scanners.state", "reset_scan_warnings_only"),
}


def resolve_legacy_export(name: str) -> Any:
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module agent_bom.scanners.package_scan has no attribute {name!r}")
    module, attribute = target
    return getattr(import_module(module), attribute)
