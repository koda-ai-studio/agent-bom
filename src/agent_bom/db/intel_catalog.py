"""Threat intelligence source catalog and cache freshness labels."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class IntelSource:
    source_id: str
    display_name: str
    source_tier: int
    kind: str
    source_url: str
    homepage_url: str
    license_or_terms_url: str
    license: str
    robots_policy: str
    crawl_delay_seconds: int | None
    connector_type: str
    enabled: bool
    owner: str
    parser_version: str
    validation_status: str
    support_status: str
    redistribution: str
    sync_meta_source: str
    description: str


CANONICAL_INTEL_SOURCES: tuple[IntelSource, ...] = (
    IntelSource(
        source_id="osv",
        display_name="OSV",
        source_tier=1,
        kind="vulnerability",
        source_url="https://osv.dev/list",
        homepage_url="https://osv.dev/",
        license_or_terms_url="https://github.com/google/osv.dev/blob/master/LICENSE",
        license="CC-BY-4.0",
        robots_policy="structured_api",
        crawl_delay_seconds=None,
        connector_type="structured_api",
        enabled=True,
        owner="agent-bom",
        parser_version="osv-db-sync.v1",
        validation_status="structured_feed",
        support_status="supported",
        redistribution="structured_records",
        sync_meta_source="osv",
        description="Ecosystem-native vulnerability advisories keyed by purl-like package coordinates.",
    ),
    IntelSource(
        source_id="ghsa",
        display_name="GitHub Security Advisories",
        source_tier=1,
        kind="vulnerability",
        source_url="https://github.com/advisories",
        homepage_url="https://github.com/advisories",
        license_or_terms_url="https://docs.github.com/en/site-policy/github-terms/github-terms-of-service",
        license="GitHub advisory database terms",
        robots_policy="api_or_osv_mirror",
        crawl_delay_seconds=None,
        connector_type="structured_api",
        enabled=True,
        owner="agent-bom",
        parser_version="ghsa-sync.v1",
        validation_status="structured_feed",
        support_status="supported",
        redistribution="structured_records",
        sync_meta_source="ghsa",
        description="GitHub Security Advisory records for package ecosystems supported by the local DB syncer.",
    ),
    IntelSource(
        source_id="nvd",
        display_name="NVD",
        source_tier=1,
        kind="enrichment",
        source_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        homepage_url="https://nvd.nist.gov/",
        license_or_terms_url="https://nvd.nist.gov/general/terms-of-use",
        license="public_domain_us_government",
        robots_policy="structured_api",
        crawl_delay_seconds=None,
        connector_type="structured_api",
        enabled=True,
        owner="agent-bom",
        parser_version="nvd-enrichment.v1",
        validation_status="structured_feed",
        support_status="supported",
        redistribution="structured_enrichment",
        sync_meta_source="nvd",
        description="CVSS, CWE, and CVE enrichment used to explain impact and remediation priority.",
    ),
    IntelSource(
        source_id="epss",
        display_name="FIRST EPSS",
        source_tier=1,
        kind="exploitability",
        source_url="https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        homepage_url="https://www.first.org/epss/",
        license_or_terms_url="https://www.first.org/epss/",
        license="FIRST EPSS terms",
        robots_policy="published_bulk_feed",
        crawl_delay_seconds=None,
        connector_type="bulk_file",
        enabled=True,
        owner="agent-bom",
        parser_version="epss-sync.v1",
        validation_status="structured_feed",
        support_status="supported",
        redistribution="structured_enrichment",
        sync_meta_source="epss",
        description="Exploit Prediction Scoring System probability and percentile enrichment.",
    ),
    IntelSource(
        source_id="cisa_kev",
        display_name="CISA KEV",
        source_tier=1,
        kind="exploitation",
        source_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        homepage_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        license_or_terms_url="https://www.cisa.gov/about/website-policies",
        license="public_domain_us_government",
        robots_policy="published_bulk_feed",
        crawl_delay_seconds=None,
        connector_type="bulk_json",
        enabled=True,
        owner="agent-bom",
        parser_version="kev-sync.v1",
        validation_status="structured_feed",
        support_status="supported",
        redistribution="structured_enrichment",
        sync_meta_source="kev",
        description="Known-exploited vulnerability signal for prioritizing active exploitation risk.",
    ),
    IntelSource(
        source_id="alpine_secdb",
        display_name="Alpine SecDB",
        source_tier=1,
        kind="os_package",
        source_url="https://secdb.alpinelinux.org",
        homepage_url="https://secdb.alpinelinux.org",
        license_or_terms_url="https://gitlab.alpinelinux.org/alpine/security/secdb",
        license="Alpine Linux SecDB terms",
        robots_policy="published_bulk_feed",
        crawl_delay_seconds=None,
        connector_type="bulk_json",
        enabled=True,
        owner="agent-bom",
        parser_version="alpine-secdb-sync.v1",
        validation_status="structured_feed",
        support_status="supported",
        redistribution="structured_records",
        sync_meta_source="alpine",
        description="Alpine package security database records for container and OS image matching.",
    ),
    IntelSource(
        source_id="nvidia_csaf",
        display_name="NVIDIA CSAF",
        source_tier=2,
        kind="vendor_psirt",
        source_url="https://api.github.com/repos/NVIDIA/product-security/contents",
        homepage_url="https://www.nvidia.com/en-us/security/",
        license_or_terms_url="https://github.com/NVIDIA/product-security",
        license="vendor product-security repository terms",
        robots_policy="structured_repository_api",
        crawl_delay_seconds=None,
        connector_type="csaf_json",
        enabled=True,
        owner="agent-bom",
        parser_version="nvidia-csaf.v1",
        validation_status="supported_structured_vendor_feed",
        support_status="supported",
        redistribution="source_links_and_structured_findings",
        sync_meta_source="nvidia_csaf",
        description="Structured CSAF advisory matching for known AI infrastructure package mappings.",
    ),
    IntelSource(
        source_id="amd_psirt",
        display_name="AMD PSIRT",
        source_tier=3,
        kind="vendor_psirt",
        source_url="https://www.amd.com/en/resources/product-security.html",
        homepage_url="https://www.amd.com/en/resources/product-security.html",
        license_or_terms_url="https://www.amd.com/en/legal/copyright.html",
        license="vendor website terms",
        robots_policy="manual_seed_with_guarded_refresh",
        crawl_delay_seconds=None,
        connector_type="vendor_json_seed",
        enabled=True,
        owner="agent-bom",
        parser_version="amd-psirt-seed.v1",
        validation_status="experimental_seed_plus_guarded_refresh",
        support_status="experimental",
        redistribution="source_links_and_structured_findings",
        sync_meta_source="amd_psirt",
        description="ROCm and AMD GPU advisory matching from a curated seed with guarded refresh fallback.",
    ),
    IntelSource(
        source_id="intel_psirt",
        display_name="Intel PSIRT",
        source_tier=3,
        kind="vendor_psirt",
        source_url="https://www.intel.com/content/www/us/en/security-center/default.html",
        homepage_url="https://www.intel.com/content/www/us/en/security-center/default.html",
        license_or_terms_url="https://www.intel.com/content/www/us/en/legal/terms-of-use.html",
        license="vendor website terms",
        robots_policy="manual_seed_only",
        crawl_delay_seconds=None,
        connector_type="curated_seed",
        enabled=True,
        owner="agent-bom",
        parser_version="intel-psirt-seed.v1",
        validation_status="experimental_seed_only",
        support_status="experimental",
        redistribution="source_links_and_structured_findings",
        sync_meta_source="intel_psirt",
        description="GPU and oneAPI advisory matching from curated seed data; no automated webpage scraping is shipped.",
    ),
)


VENDOR_ADVISORY_SOURCE_IDS = {"nvidia_csaf", "amd_psirt", "intel_psirt"}


# Display labels for the local-cache sync_meta source ids, keyed by the value
# stored in ``sync_meta.source``. Single source of truth for freshness labels.
SYNC_META_SOURCE_LABELS: dict[str, str] = {
    "osv": "OSV",
    "ghsa": "GHSA",
    "nvd": "NVD",
    "epss": "EPSS",
    "kev": "KEV",
}


def sync_meta_source_label(source_id: str) -> str:
    """Map a ``sync_meta.source`` id to its human display label (OSV/GHSA/…)."""
    return SYNC_META_SOURCE_LABELS.get(source_id.strip().lower(), source_id.upper())
