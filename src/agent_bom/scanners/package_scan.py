"""Package and agent vulnerability scanning orchestration."""

# Legacy facade patch targets intentionally remain public.
# ruff: noqa: F401
from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Optional, cast

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from agent_bom.advisory_ids import MATCH_CONFIDENCE_AMBIGUOUS_DISTRO_RELEASE, MATCH_CONFIDENCE_UNVERIFIED_RANGE, upstream_advisory_ids
from agent_bom.atlas import blast_radius_technique_evidence as atlas_technique_evidence
from agent_bom.cis_controls import tag_blast_radius as tag_cis_controls
from agent_bom.cmmc import tag_blast_radius as tag_cmmc
from agent_bom.compliance_utils import apply_effective_blast_radius_tags
from agent_bom.constants import AI_PACKAGES as _AI_FRAMEWORK_PACKAGES
from agent_bom.eu_ai_act import tag_blast_radius as tag_eu_ai_act
from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
from agent_bom.fedramp import tag_blast_radius as tag_fedramp
from agent_bom.http_client import create_client
from agent_bom.iso_27001 import tag_blast_radius as tag_iso_27001
from agent_bom.malicious import flag_malicious_from_vulns
from agent_bom.mitre_attack import tag_blast_radius as tag_attack_techniques
from agent_bom.models import Agent, BlastRadius, MCPServer, Package, Vulnerability
from agent_bom.nist_800_53 import tag_blast_radius as tag_nist_800_53
from agent_bom.nist_ai_rmf import tag_blast_radius as tag_nist_ai_rmf
from agent_bom.nist_csf import tag_blast_radius as tag_nist_csf
from agent_bom.owasp import tag_blast_radius
from agent_bom.owasp_agentic import tag_blast_radius as tag_owasp_agentic
from agent_bom.owasp_mcp import tag_blast_radius as tag_owasp_mcp
from agent_bom.pci_dss import tag_blast_radius as tag_pci_dss
from agent_bom.reachability_cve import advisory_affected_symbols_by_path, advisory_affected_symbols_list
from agent_bom.scanners import cpython_advisory as runtime_cve
from agent_bom.scanners.blast_radius import expand_blast_radius_hops
from agent_bom.scanners.compat_exports import resolve_legacy_export
from agent_bom.scanners.kev_default_join import join_default_kev_catalog
from agent_bom.scanners.local_advisories import _scan_local_advisories, merge_scanner_vulnerabilities
from agent_bom.scanners.osv import enrich_results_if_needed as _enrich_results_if_needed_impl
from agent_bom.scanners.osv import parse_fixed_version, query_osv_batch_impl
from agent_bom.scanners.package_coverage import (
    _check_offline_coverage,
    _detect_coverage_gaps,
    _flag_remote_lookup_gap,
    _flag_suspicious_packages,
    _scan_supplemental_advisories,
    _select_osv_targets,
)
from agent_bom.scanners.package_matching import ECOSYSTEM_MAP as ECOSYSTEM_MAP
from agent_bom.scanners.package_matching import _apply_distro_release_ambiguity as _apply_distro_release_ambiguity
from agent_bom.scanners.package_matching import _emit_scan_warning as _emit_scan_warning
from agent_bom.scanners.package_matching import _is_version_affected as _is_version_affected
from agent_bom.scanners.package_matching import _osv_ecosystems_for_package as _osv_ecosystems_for_package
from agent_bom.scanners.package_matching import _scanners_patchable as _scanners_patchable
from agent_bom.scanners.package_matching import _scope_advisory_to_package_release as _scope_advisory_to_package_release
from agent_bom.scanners.package_preparation import (
    _NON_OSV_ECOSYSTEMS,
    _expand_transitive_packages,
    _prepare_packages,
    _resolve_local_versions,
    _resolve_registry_versions,
    _scan_runtime_packages,
    _select_scannable_packages,
    deduplicate_packages,
)
from agent_bom.scanners.package_versions import eligible_advisories
from agent_bom.scanners.package_versions import is_unresolved_package as _is_unresolved_package
from agent_bom.scanners.risk import osv_cvss_vector, parse_osv_severity
from agent_bom.scanners.scan_options import IncompleteScanError as IncompleteScanError
from agent_bom.scanners.scan_options import ScanOptions, _logger, _package_db_key, console
from agent_bom.scanners.state import _bump_scan_perf, _get_api_semaphore
from agent_bom.scanners.upstream_severity import resolve_upstream_advisory_severity
from agent_bom.soc2 import tag_blast_radius as tag_soc2
from agent_bom.vuln_compliance import tag_vulnerability as _tag_vuln

if TYPE_CHECKING:
    from agent_bom.scan_cache import ScanCache


offline_mode: bool = False


_scan_cache_init_lock = threading.Lock()


_SCAN_CACHE_UNAVAILABLE = object()


def default_scan_options(
    *,
    compliance_enabled: bool = False,
    resolve_transitive: bool = False,
    prefer_local_db: bool | None = None,
    offline: bool | None = None,
    demo_advisories: bool = False,
    project_dir: str | None = None,
) -> ScanOptions:
    """Build per-scan options while preserving legacy offline defaults."""

    return ScanOptions(
        offline=_scanners_patchable("offline_mode") if offline is None else offline,
        compliance_enabled=compliance_enabled,
        resolve_transitive=resolve_transitive,
        prefer_local_db=(prefer_local_db if prefer_local_db is not None else _scanners_patchable("prefer_local_db")),
        demo_advisories=demo_advisories,
        project_dir=project_dir,
    )


def set_offline_mode(value: bool) -> None:
    """Set offline mode in both scanner and http_client transport layer."""
    global offline_mode  # noqa: PLW0603
    offline_mode = value
    from agent_bom.http_client import set_offline

    set_offline(value)


_SUPPRESSIBLE_DISTRO_ECOSYSTEMS = frozenset({"deb", "apk"})


include_unfixed: bool = False


def set_include_unfixed(value: bool) -> None:
    """Toggle surfacing of unfixed (no-dsa/won't-fix) OS-package advisories."""
    global include_unfixed  # noqa: PLW0603
    include_unfixed = value


def _include_unfixed_enabled() -> bool:
    if include_unfixed:
        return True
    raw = os.environ.get("AGENT_BOM_INCLUDE_UNFIXED", "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _suppress_unfixed_os_advisories(packages: list[Package]) -> int:
    """Drop unfixed Debian/Alpine advisories from ``packages`` in place.

    Return and record the number removed by the default OS-package filter.
    Application-ecosystem advisories (PyPI, npm, …) are never touched — an
    unfixed app CVE is still actionable (pin, remove, or mitigate).

    A finding whose release is ambiguous is exempt: its fix was withheld by us
    because it would name another branch's version, which is not the same claim
    as "the distro will not fix this". Without the exemption every such finding
    would be filtered out and an unspecified-release scan would report clean.
    RPM records without a fix remain visible: missing fix metadata does not
    establish the vendor's remediation status.
    """
    if _include_unfixed_enabled():
        return 0
    removed = 0
    for pkg in packages:
        if pkg.ecosystem.lower() not in _SUPPRESSIBLE_DISTRO_ECOSYSTEMS:
            continue
        vulns = getattr(pkg, "vulnerabilities", None)
        if not vulns:
            continue
        kept = [
            v
            for v in vulns
            if (v.fixed_version or "").strip()
            or v.match_confidence_tier in {MATCH_CONFIDENCE_AMBIGUOUS_DISTRO_RELEASE, MATCH_CONFIDENCE_UNVERIFIED_RANGE}
        ]
        removed += len(vulns) - len(kept)
        pkg.vulnerabilities = kept
    _bump_scan_perf("unfixed_os_findings_suppressed", removed)
    return removed


prefer_local_db: bool = False


compliance_mode: bool = False


def _db_covered_ecosystems(ecosystems: set[str] | None = None) -> set[str]:
    """Return the lowercased ecosystems the local vulnerability DB has advisories for.

    An advisory DB only stores *vulnerable* package-versions, so it cannot
    distinguish a genuinely-clean package (queried, no advisories) from one it
    has no data for — both have zero rows. Coverage is therefore meaningful only
    at the ecosystem level: if the DB holds any advisories for an ecosystem, a
    package in that ecosystem with no rows is clean; an ecosystem with zero
    advisories is a real coverage gap. Returns an empty set when the DB is
    missing/unreadable (callers treat that as "no offline coverage at all").

    When ``ecosystems`` is provided, bound the legacy row-inference query to
    those inventory ecosystems. If none match, retain one catalog-presence
    witness so callers can distinguish an uncovered ecosystem from a wholly
    empty DB without enumerating the multi-million-row catalog.
    """
    try:
        from agent_bom.db.schema import (
            DB_PATH,
            db_freshness_days,
            open_existing_db_readonly,
        )

        if db_freshness_days() is None or not DB_PATH.exists():
            return set()
        conn = open_existing_db_readonly(DB_PATH)
        try:
            declared: set[str] = set()
            coverage_mode = "legacy"
            columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(sync_meta)").fetchall()}
            if "metadata_json" in columns:
                meta_row = conn.execute("SELECT metadata_json FROM sync_meta WHERE source = 'osv'").fetchone()
                if meta_row and meta_row[0]:
                    try:
                        metadata = json.loads(meta_row[0])
                    except (json.JSONDecodeError, TypeError):
                        metadata = {}
                    if isinstance(metadata, dict):
                        coverage_mode = str(metadata.get("coverage", "legacy"))
                        declared_ecosystems = metadata.get("ecosystems")
                        if isinstance(declared_ecosystems, list):
                            declared = {str(item).lower() for item in declared_ecosystems if isinstance(item, str) and item}
            requested = {str(item).lower() for item in ecosystems or set() if str(item).strip()}
            if coverage_mode == "selected_ecosystems":
                return declared & requested if ecosystems is not None else declared
            if coverage_mode == "partial":
                return set()

            if ecosystems is None:
                rows = conn.execute("SELECT DISTINCT ecosystem FROM affected").fetchall()
            elif not requested:
                rows = []
            else:
                rows = []
                requested_list = sorted(requested)
                for start in range(0, len(requested_list), 400):
                    chunk = requested_list[start : start + 400]
                    placeholders = ", ".join("?" for _ in chunk)
                    query = f"SELECT DISTINCT ecosystem FROM affected WHERE ecosystem IN ({placeholders})"  # nosec B608
                    rows.extend(conn.execute(query, chunk).fetchall())
                if not rows:
                    # Preserve the existing populated-catalog signal without
                    # enumerating every ecosystem.  Callers use a non-empty set
                    # to distinguish "this inventory ecosystem is uncovered"
                    # from "the advisory DB is completely empty"; the sampled
                    # ecosystem cannot satisfy membership for the uncovered
                    # package, so its verdict remains conservative.
                    sample = conn.execute(
                        "SELECT ecosystem FROM affected WHERE ecosystem IS NOT NULL AND ecosystem <> '' LIMIT 1"
                    ).fetchone()
                    if sample is not None:
                        rows.append(sample)
        finally:
            conn.close()
        # Ecosystem-specific OSV archives can contain cross-ecosystem aliases.
        # Those rows are useful evidence, but they do not prove that the other
        # ecosystem's complete archive was synchronized. Scoped metadata is
        # therefore authoritative; row inference remains only for legacy/full
        # databases that predate the explicit coverage contract.
        inferred = {str(r[0]).lower() for r in rows if r[0]}
        if ecosystems is not None:
            declared &= requested
        return inferred | declared
    except Exception as exc:  # noqa: BLE001
        _logger.debug("Could not read local DB ecosystem coverage: %s", exc)
        return set()


_scan_cache_instance: "ScanCache | object | None" = None


def _get_scan_cache() -> "ScanCache | None":
    """Return the shared ScanCache singleton, or *None* if unavailable."""
    global _scan_cache_instance  # noqa: PLW0603
    if _scan_cache_instance is None:
        with _scan_cache_init_lock:
            if _scan_cache_instance is None:
                try:
                    from agent_bom.scan_cache import ScanCache

                    _scan_cache_instance = ScanCache()
                except Exception as exc:  # noqa: BLE001
                    _logger.warning("ScanCache initialization failed (caching disabled): %s", exc)
                    _emit_scan_warning("scan cache unavailable")
                    _scan_cache_instance = _SCAN_CACHE_UNAVAILABLE  # mark as attempted, don't retry
    if _scan_cache_instance is None or _scan_cache_instance is _SCAN_CACHE_UNAVAILABLE:
        return None
    return cast("ScanCache", _scan_cache_instance)


async def _enrich_results_if_needed(results: dict[str, list[dict]]) -> dict[str, list[dict]]:
    """Enrich minimal OSV batch results with full vuln details where missing."""
    return await _enrich_results_if_needed_impl(
        results,
        console=console,
        record_scan_warning=_scanners_patchable("record_scan_warning"),
        create_client_fn=_scanners_patchable("create_client"),
        request_with_retry_fn=_scanners_patchable("request_with_retry"),
    )


async def query_osv_batch(packages: list[Package]) -> dict[str, list[dict]]:
    """Query OSV API for vulnerabilities in batch."""
    return await query_osv_batch_impl(
        packages,
        console=console,
        get_scan_cache=_scanners_patchable("_get_scan_cache"),
        get_api_semaphore=_get_api_semaphore,
        bump_scan_perf=_bump_scan_perf,
        enrich_results_if_needed_fn=_scanners_patchable("_enrich_results_if_needed"),
        record_scan_warning=_scanners_patchable("record_scan_warning"),
        osv_ecosystems_for_package=_osv_ecosystems_for_package,
        non_osv_ecosystems=_NON_OSV_ECOSYSTEMS,
        create_client_fn=_scanners_patchable("create_client"),
        request_with_retry_fn=_scanners_patchable("request_with_retry"),
    )


def build_vulnerabilities(vuln_data_list: list[dict], package: Package) -> list[Vulnerability]:
    """Convert OSV response data to Vulnerability objects.

    Filters out false positives by verifying the package version falls
    within OSV affected ranges.  Deduplicates by canonical CVE ID.
    """
    vulns = []

    for raw_vuln_data in eligible_advisories(vuln_data_list, package, _emit_scan_warning):
        vuln_data = _scope_advisory_to_package_release(raw_vuln_data, package)
        if vuln_data is None:
            continue
        vuln_id = vuln_data.get("id", "unknown")

        # Version-range filter: skip vulns that don't affect our version
        if package.version and package.version not in ("unknown", "latest"):
            if not _is_version_affected(
                vuln_data,
                package.name,
                package.version,
                package.ecosystem,
                source_package=package.source_package,
                aliases=tuple(package.lookup_names),
            ):
                _logger.debug(
                    "Filtered %s: version %s not in affected range for %s",
                    vuln_id,
                    package.version,
                    package.name,
                )
                continue

        from agent_bom.advisory_ids import canonical_vulnerability_id, match_confidence_tier

        aliases = vuln_data.get("aliases", [])
        canonical_id, all_aliases = canonical_vulnerability_id(vuln_id, aliases)

        severity, cvss_score, sev_source = parse_osv_severity(vuln_data)
        cvss_vector = osv_cvss_vector(vuln_data) if cvss_score is not None else None
        fixed = parse_fixed_version(
            vuln_data,
            package.name,
            package.ecosystem,
            current_version=package.version or "",
            source_package=package.source_package,
            aliases=tuple(package.lookup_names),
        )

        references = [ref.get("url", "") for ref in vuln_data.get("references", []) if ref.get("url")]

        summary = vuln_data.get("summary", vuln_data.get("details", "No description available"))[:200]

        # Extract CWE IDs from database_specific (GHSA entries store them here)
        cwe_ids: list[str] = []
        db_specific = vuln_data.get("database_specific", {})
        if isinstance(db_specific, dict):
            raw_cwes = db_specific.get("cwe_ids", [])
            if isinstance(raw_cwes, list):
                cwe_ids = [c for c in raw_cwes if isinstance(c, str) and c.startswith("CWE-")]

        affected_symbols = advisory_affected_symbols_list(vuln_data)
        affected_symbols_by_path = advisory_affected_symbols_by_path(vuln_data)

        vulns.append(
            Vulnerability(
                id=canonical_id,
                summary=summary,
                severity=severity,
                severity_source=sev_source,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                fixed_version=fixed,
                references=references,
                published_at=vuln_data.get("published"),
                modified_at=vuln_data.get("modified"),
                upstream_ids=upstream_advisory_ids(vuln_data.get("upstream")),
                aliases=all_aliases,
                cwe_ids=cwe_ids,
                affected_symbols=affected_symbols,
                affected_symbols_by_path=affected_symbols_by_path,
                advisory_sources=["osv"],
                match_confidence_tier=match_confidence_tier(
                    advisory_source="osv",
                    db_ecosystem=None,
                    package_ecosystem=package.ecosystem,
                    fixed_version=fixed,
                ),
            )
        )

    from agent_bom.scanners.advisory_merge import merge_advisory_clusters

    vulns = merge_advisory_clusters(vulns)
    _apply_distro_release_ambiguity(package, vulns)
    return vulns


def apply_framework_tags(br: BlastRadius) -> None:
    """Stamp every registered compliance framework's tags onto a blast radius.

    One place, so a framework cannot be published in the registry, offered by
    the API and counted in the coverage tables while no scan ever calls its
    tagger — which is exactly how PCI DSS shipped a full catalog and a full
    tagger that could only ever report ``not_evaluated``.
    ``tests/test_compliance_coverage.py`` asserts this covers the registry.
    """
    br.owasp_tags = tag_blast_radius(br)
    br.atlas_mapping_evidence = atlas_technique_evidence(br)
    br.atlas_tags = list(br.atlas_mapping_evidence)
    br.attack_tags = tag_attack_techniques(br)
    br.nist_ai_rmf_tags = tag_nist_ai_rmf(br)
    br.owasp_mcp_tags = tag_owasp_mcp(br)
    br.owasp_agentic_tags = tag_owasp_agentic(br)
    br.eu_ai_act_tags = tag_eu_ai_act(br)
    br.nist_csf_tags = tag_nist_csf(br)
    br.iso_27001_tags = tag_iso_27001(br)
    br.soc2_tags = tag_soc2(br)
    br.cis_tags = tag_cis_controls(br)
    br.cmmc_tags = tag_cmmc(br)
    br.nist_800_53_tags = tag_nist_800_53(br)
    br.fedramp_tags = tag_fedramp(br)
    br.pci_dss_tags = tag_pci_dss(br)


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
    return results


def _apply_osv_results(scannable: list[Package], osv_targets: list[Package], results: dict[str, list[dict]]) -> int:
    """Merge OSV findings into packages and compliance-tag every vulnerability; return new count."""
    added = 0
    for pkg in osv_targets:
        vuln_data = results.get(_package_db_key(pkg), [])
        if vuln_data:
            new_vulns = _scanners_patchable("build_vulnerabilities")(vuln_data, pkg)
            # Merge: don't duplicate what the local DB (or an imported report) already found
            merged = merge_scanner_vulnerabilities(pkg, new_vulns)
            added += len(merged)
            # Tag each CVE with compliance framework codes (pre-enrichment),
            # including records that replaced an imported external one.
            merged_ids = {id(v) for v in merged}
            for v in pkg.vulnerabilities:
                if id(v) in merged_ids or not v.compliance_tags:
                    v.compliance_tags = _tag_vuln(v, pkg)
            # Flag packages with MAL- prefixed vulnerability IDs as malicious
            flag_malicious_from_vulns(pkg)

    # Back-fill: also run OSV tagging for packages that came from local DB only
    for pkg in scannable:
        if pkg in osv_targets:
            continue  # already processed above
        for v in pkg.vulnerabilities:
            if not v.compliance_tags:
                v.compliance_tags = _tag_vuln(v, pkg)
    return added


def _suppress_unfixed_findings(scannable: list[Package]) -> int:
    """Suppress distro advisories with no fix for the scanned release (no-dsa / won't-fix / EOL open).

    Surface them with set_include_unfixed(True) or AGENT_BOM_INCLUDE_UNFIXED=1.
    """
    unfixed_suppressed = _suppress_unfixed_os_advisories(scannable)
    if unfixed_suppressed:
        _logger.info(
            "Suppressed %d unfixed OS-package advisory finding(s) (no-dsa/won't-fix); set AGENT_BOM_INCLUDE_UNFIXED=1 to include them",
            unfixed_suppressed,
        )
        console.print(
            f"  [dim]Suppressed {unfixed_suppressed} unfixed OS-package finding(s) "
            f"(no-dsa/won't-fix) — set AGENT_BOM_INCLUDE_UNFIXED=1 to include[/dim]"
        )
    return unfixed_suppressed


async def scan_packages(
    packages: list[Package],
    *,
    resolve_transitive: bool = False,
    options: ScanOptions | None = None,
) -> int:
    """Scan a list of packages for vulnerabilities. Returns count of vulns found."""
    scan_options = options or default_scan_options(resolve_transitive=resolve_transitive)
    scan_offline = scan_options.offline
    packages = _prepare_packages(packages)
    packages, runtime_count = await _scan_runtime_packages(packages, scan_offline)

    # Installed versions reflect what's actually on disk, so they are tried before the registry fallback.
    unresolved = [p for p in packages if _is_unresolved_package(p) and p.ecosystem.lower() in ("npm", "pypi", "go")]
    if unresolved:
        _resolve_local_versions(unresolved, scan_options.project_dir)
    await _resolve_registry_versions(packages, scan_offline)

    # Capture the version-resolved direct demo inventory before optional online
    # transitive expansion. Only this curated set is closed evidence; packages
    # discovered outside it still require a real advisory lookup.
    demo_inventory_keys = {_package_db_key(package) for package in packages} if scan_options.demo_advisories else set()
    if scan_options.resolve_transitive and not scan_offline:
        packages = await _expand_transitive_packages(packages)

    scannable = _select_scannable_packages(packages)
    if not scannable:
        return runtime_count

    local_count, db_covered, local_db_targets = _scan_local_advisories(scannable, scan_options, demo_inventory_keys)
    coverage_gaps = _detect_coverage_gaps(scannable)
    osv_targets, covered_ecos = _select_osv_targets(scannable, scan_offline, local_db_targets, db_covered, coverage_gaps)
    results = await _query_osv_results(scannable, osv_targets, covered_ecos, scan_options)

    total_vulns = local_count + runtime_count
    total_vulns += _apply_osv_results(scannable, osv_targets, results)
    total_vulns += await _scan_supplemental_advisories(scannable, scan_offline)
    resolve_upstream_advisory_severity(scannable)
    _flag_suspicious_packages(scannable)
    total_vulns -= _suppress_unfixed_findings(scannable)

    # Ignore-rule suppression is applied once after BlastRadius construction by ``agent_bom.ignores``
    # so JSON/SARIF/VEX/MCP can record why a finding was accepted.
    return total_vulns


def _print_vulnerability_summary(total_vulns: int, findings_count: int, *, agents: list[Agent] | None = None) -> None:
    """Keep empty findings distinct from a complete negative assessment."""
    if total_vulns:
        console.print(f"  [red]⚠ Found {total_vulns} vulnerabilities across {findings_count} findings[/red]")
    else:
        from agent_bom.scanners.state import peek_coverage_warnings, peek_scan_warnings

        run = effective_scan_run(SimpleNamespace(agents=agents or [], coverage_warnings=peek_coverage_warnings()))
        if run.outcome is not ScanOutcome.COMPLETE or peek_scan_warnings():
            console.print("  [yellow]No vulnerabilities confirmed; coverage gaps limit this assessment[/yellow]")
        else:
            console.print("  [green]✓ No known vulnerabilities found[/green]")


async def scan_agents(
    agents: list[Agent],
    *,
    compliance_enabled: bool = False,
    resolve_transitive: bool = False,
    show_scan_banner: bool = True,
    options: ScanOptions | None = None,
) -> list[BlastRadius]:
    """Scan all agents' MCP server packages for vulnerabilities."""
    scan_options = options or default_scan_options(
        compliance_enabled=compliance_enabled,
        resolve_transitive=resolve_transitive,
    )
    if show_scan_banner:
        from agent_bom.output.brand_tokens import PRODUCT_NAME

        console.print(f"\n[bold cyan]{PRODUCT_NAME}[/bold cyan]  [bold]Scanning for vulnerabilities…[/bold]\n")

    _pkg_key = runtime_cve.advisory_instance_key

    # Collect all unique packages
    all_packages = []
    pkg_to_servers: dict[str, list[MCPServer]] = {}
    pkg_to_agents: dict[str, list[Agent]] = {}

    for agent in agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                key = _pkg_key(pkg)
                all_packages.append(pkg)

                if key not in pkg_to_servers:
                    pkg_to_servers[key] = []
                pkg_to_servers[key].append(server)

                if key not in pkg_to_agents:
                    pkg_to_agents[key] = []
                if agent not in pkg_to_agents[key]:
                    pkg_to_agents[key].append(agent)

    # Deduplicate packages for scanning — uses canonical deduplicate_packages()
    # which normalizes by (ecosystem, normalized_name, version) fingerprint.
    unique_packages = deduplicate_packages(all_packages)

    if show_scan_banner:
        console.print(f"  Scanning {len(unique_packages)} unique packages across {len(agents)} agent(s)...")

    total_vulns = await _scanners_patchable("scan_packages")(unique_packages, options=scan_options)
    runtime_cve.propagate_runtime_assessments(all_packages, unique_packages)

    # Propagate vulnerabilities back to all instances
    vuln_map = {}
    for pkg in unique_packages:
        if pkg.vulnerabilities:
            vuln_map[_pkg_key(pkg)] = pkg.vulnerabilities

    for agent in agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                if _pkg_key(pkg) in vuln_map:
                    pkg.vulnerabilities = vuln_map[_pkg_key(pkg)]

    # Build blast radius analysis. Registry enrichment is keyed by MCP server,
    # not by vulnerable package. Keep one cache for the whole scan: a server can
    # expose many packages, and matching the same registry catalog once per
    # package turns a linear build into an avoidable package×catalog walk.
    from agent_bom.parsers import get_registry_entry

    _registry_cache: dict[tuple[str, str, tuple[str, ...], str], dict | None] = {}

    def _registry_key(server: MCPServer) -> tuple[str, str, tuple[str, ...], str]:
        return (
            server.name,
            server.command,
            tuple(server.args),
            server.url or "",
        )

    blast_radii = []
    for pkg in unique_packages:
        if not pkg.vulnerabilities:
            continue

        key = _pkg_key(pkg)
        affected_servers = pkg_to_servers.get(key, [])
        affected_agents = pkg_to_agents.get(key, [])

        # Collect exposed credentials and tools — enrich from registry when server
        # config doesn't have explicit tool/credential data.
        # Cache registry lookups per server to avoid duplicate tool creation.
        #
        # IMPORTANT: Registry-sourced tools are "phantom" — they reflect what
        # the registry CLAIMS the server has, not what was introspected.
        # We include them for visibility but mark them so blast radius
        # consumers can distinguish confirmed vs phantom tools.
        exposed_creds: list[str] = []
        exposed_tools: list = []
        phantom_tools: list = []
        for server in affected_servers:
            server_creds = server.credential_names
            server_tools = list(server.tools)  # copy — don't mutate server

            # Registry enrichment: if no tools/creds known from config, use registry
            if not server_tools or not server_creds:
                registry_key = _registry_key(server)
                if registry_key not in _registry_cache:
                    _registry_cache[registry_key] = get_registry_entry(server)
                reg = _registry_cache[registry_key]
                if reg:
                    if not server_tools and reg.get("tools"):
                        from agent_bom.models import MCPTool

                        server_tools = [
                            MCPTool(
                                name=t,
                                description="(registry — unverified)",
                                discovery_source="registry",
                                discovery_confidence="unverified",
                            )
                            for t in reg["tools"]
                        ]
                    if not server_creds and reg.get("credential_env_vars"):
                        server_creds = reg["credential_env_vars"]

            exposed_creds.extend(server_creds)
            for tool in server_tools:
                if getattr(tool, "discovery_source", None) == "registry" and getattr(tool, "discovery_confidence", None) == "unverified":
                    phantom_tools.append(tool)
                else:
                    exposed_tools.append(tool)

        # Deduplicate credentials and tools to prevent inflation
        exposed_creds_deduped = sorted(set(exposed_creds))
        seen_tool_names: set[str] = set()
        deduped_tools = []
        for t in exposed_tools:
            if t.name not in seen_tool_names:
                seen_tool_names.add(t.name)
                deduped_tools.append(t)
        exposed_tools = deduped_tools
        seen_phantom: set[str] = set()
        deduped_phantom = []
        for t in phantom_tools:
            if t.name not in seen_phantom:
                seen_phantom.add(t.name)
                deduped_phantom.append(t)
        phantom_tools = deduped_phantom

        # AI-native risk context: elevated when an AI framework has creds + tools
        is_ai_framework = (
            pkg.name.lower().replace("-", "_") in {n.replace("-", "_") for n in _AI_FRAMEWORK_PACKAGES}
            or pkg.name.lower() in _AI_FRAMEWORK_PACKAGES
        )
        has_creds = bool(exposed_creds_deduped)
        has_tools = bool(exposed_tools)
        has_phantom_tools = bool(phantom_tools)
        if is_ai_framework and has_creds and has_tools:
            phantom_note = f" (+{len(phantom_tools)} registry-only tool(s) excluded from score)" if has_phantom_tools else ""
            ai_risk_context = (
                f"AI framework '{pkg.name}' runs inside an agent with {len(exposed_creds_deduped)} "
                f"exposed credential(s) and {len(exposed_tools)} confirmed reachable tool(s){phantom_note}. "
                f"A compromise here gives an attacker both identity and capability."
            )
        elif is_ai_framework and has_creds:
            ai_risk_context = (
                f"AI framework '{pkg.name}' has access to {len(exposed_creds_deduped)} "
                f"credential(s). Exploitation could exfiltrate secrets via LLM output."
            )
        elif is_ai_framework:
            ai_risk_context = "AI framework package — vulnerability affects LLM inference/orchestration pipeline."
        else:
            ai_risk_context = None

        for vuln in pkg.vulnerabilities:
            if not vuln.compliance_tags:
                vuln.compliance_tags = _tag_vuln(vuln, pkg)

            # CWE-aware filtering: only expose credentials/tools the vuln
            # type can realistically reach. A DoS (CWE-400) doesn't steal
            # DATABASE_URL. An RCE (CWE-94) does.
            from agent_bom.cwe_impact import (
                build_attack_vector_summary,
                classify_cwe_impact,
                filter_credentials_by_impact,
                filter_tools_by_impact,
            )

            impact_cat = classify_cwe_impact(vuln.cwe_ids)
            filtered_creds = filter_credentials_by_impact(
                impact_cat,
                exposed_creds_deduped,
            )
            filtered_tools = filter_tools_by_impact(
                impact_cat,
                exposed_tools,
            )
            filtered_phantom = filter_tools_by_impact(
                impact_cat,
                phantom_tools,
            )
            attack_summary = build_attack_vector_summary(
                cwe_ids=vuln.cwe_ids,
                category=impact_cat,
                filtered_creds=filtered_creds,
                filtered_tools=filtered_tools,
                severity=vuln.severity.value if vuln.severity else None,
                is_kev=vuln.is_kev,
            )
            if attack_summary:
                if ai_risk_context:
                    ai_risk_context = f"{ai_risk_context} {attack_summary}"
                else:
                    ai_risk_context = attack_summary

            br = BlastRadius(
                vulnerability=vuln,
                package=pkg,
                affected_servers=affected_servers,
                affected_agents=affected_agents,
                exposed_credentials=filtered_creds,
                exposed_tools=filtered_tools,
                phantom_tools=filtered_phantom,
                ai_risk_context=ai_risk_context,
                impact_category=impact_cat,
                all_server_credentials=list(exposed_creds_deduped),
                all_server_tools=list(exposed_tools) + list(phantom_tools),
                attack_vector_summary=attack_summary,
            )
            br.calculate_risk_score()
            # Context-aware tagging remains opt-in for explicit compliance
            # views, but effective framework tags are always materialized.
            if scan_options.compliance_enabled:
                apply_framework_tags(br)
            apply_effective_blast_radius_tags(br)
            blast_radii.append(br)

    # Sort by risk score descending
    blast_radii.sort(key=lambda br: br.risk_score, reverse=True)

    _print_vulnerability_summary(total_vulns, len(blast_radii), agents=agents)

    _logger.info(
        "Scan summary: %d packages scanned, %d vulnerabilities, %d blast radius findings across %d agent(s)",
        len(unique_packages),
        total_vulns,
        len(blast_radii),
        len(agents),
    )

    return blast_radii


async def scan_agents_with_enrichment(
    agents: list[Agent],
    nvd_api_key: Optional[str] = None,
    enable_enrichment: bool = True,
    compliance_enabled: bool = False,
    show_scan_banner: bool = True,
    options: ScanOptions | None = None,
) -> list[BlastRadius]:
    """Scan agents and enrich vulnerabilities with NVD/EPSS/KEV data."""
    scan_options = options or default_scan_options(compliance_enabled=compliance_enabled)
    # First, do normal OSV scan
    blast_radii = await scan_agents(
        agents,
        compliance_enabled=scan_options.compliance_enabled,
        show_scan_banner=show_scan_banner,
        options=scan_options,
    )

    # Then enrich with external data
    if enable_enrichment and blast_radii:
        from agent_bom.enrichment import enrich_vulnerabilities
        from agent_bom.resolver import enrich_supply_chain_metadata

        # Collect all vulnerabilities
        all_vulns = []
        all_pkgs: list[Package] = []
        for agent in agents:
            for server in agent.mcp_servers:
                for pkg in server.packages:
                    all_pkgs.append(pkg)
                    all_vulns.extend(pkg.vulnerabilities)

        if all_vulns:
            await enrich_vulnerabilities(
                all_vulns,
                nvd_api_key=nvd_api_key,
                enable_nvd=True,
                enable_epss=True,
                enable_kev=True,
                offline=offline_mode,
            )

            # Refresh CVE-level compliance tags now that CWE/KEV/EPSS data is populated
            for agent in agents:
                for server in agent.mcp_servers:
                    for pkg in server.packages:
                        for v in pkg.vulnerabilities:
                            v.compliance_tags = _tag_vuln(v, pkg)

        # Supply-chain metadata enrichment — feeds Scorecard repo resolution
        try:
            async with create_client(timeout=10.0) as client:
                await enrich_supply_chain_metadata(all_pkgs, client)
        except Exception as exc:  # noqa: BLE001
            _logger.warning("Supply chain metadata enrichment failed (scorecard coverage may be incomplete): %s", exc)
            _emit_scan_warning("supply-chain metadata enrichment failed")

        # Scorecard enrichment — adds supply-chain quality signal
        try:
            from agent_bom.scorecard import enrich_packages_with_scorecard

            if all_pkgs:
                await enrich_packages_with_scorecard(all_pkgs)
        except Exception as exc:  # noqa: BLE001
            _logger.warning("Scorecard auto-enrichment failed (risk scores may be understated): %s", exc)
            _emit_scan_warning("OpenSSF Scorecard enrichment failed")

        # Recalculate blast radius with all enriched data
        for br in blast_radii:
            br.calculate_risk_score()
            apply_effective_blast_radius_tags(br)

        # Re-sort by updated risk scores
        blast_radii.sort(key=lambda br: br.risk_score, reverse=True)

    return blast_radii


def scan_agents_sync(
    agents: list[Agent],
    enable_enrichment: bool = False,
    nvd_api_key: Optional[str] = None,
    blast_radius_depth: int = 1,
    compliance_enabled: bool = False,
    resolve_transitive: bool = False,
    show_scan_banner: bool = True,
    offline: bool | None = None,
    prefer_local_db: bool | None = None,
    demo_advisories: bool = False,
    project_dir: str | None = None,
    options: ScanOptions | None = None,
) -> list[BlastRadius]:
    """Synchronous wrapper for scan_agents."""
    scan_options = options or default_scan_options(
        compliance_enabled=compliance_enabled,
        resolve_transitive=resolve_transitive,
        prefer_local_db=prefer_local_db,
        offline=offline,
        demo_advisories=demo_advisories,
        project_dir=project_dir,
    )
    if enable_enrichment:
        blast_radii = asyncio.run(
            scan_agents_with_enrichment(
                agents,
                nvd_api_key,
                enable_enrichment,
                compliance_enabled=scan_options.compliance_enabled,
                show_scan_banner=show_scan_banner,
                options=scan_options,
            )
        )
    else:
        blast_radii = asyncio.run(
            scan_agents(
                agents,
                compliance_enabled=scan_options.compliance_enabled,
                resolve_transitive=scan_options.resolve_transitive,
                show_scan_banner=show_scan_banner,
                options=scan_options,
            )
        )
        join_default_kev_catalog(blast_radii, offline=scan_options.offline)
    if blast_radius_depth > 1:
        if show_scan_banner:
            console.print(
                "[yellow]--blast-radius-depth retains direct scanner scope: shared configuration does not prove delegation. "
                "Use typed graph paths to inspect recorded relationships.[/yellow]"
            )
        expand_blast_radius_hops(blast_radii, agents, max_depth=blast_radius_depth)
    return blast_radii


def __getattr__(name: str) -> Any:
    value = resolve_legacy_export(name)
    globals()[name] = value
    return value
