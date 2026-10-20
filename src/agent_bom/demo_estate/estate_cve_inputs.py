"""The scored blast radius behind one estate CVE occurrence.

Built the way a live package scan builds it — framework tags stamped, risk
scored — from the inventoried package row and the curated advisory, so the
estate's vulnerability lane carries the same lineage, KEV dates, EPSS and risk
a real scan would, not converter defaults.
"""

from __future__ import annotations

from agent_bom.demo_advisories import DemoAdvisory, demo_epss, demo_epss_percentile
from agent_bom.demo_estate.enterprise import EstateAsset
from agent_bom.models import BlastRadius, Package, Severity, Vulnerability
from agent_bom.scanners.package_scan import apply_framework_tags


def estate_package(asset: EstateAsset) -> Package:
    """The package with the lineage the graph's package node records (not a direct, depth-0 default)."""
    tags = asset.tags
    return Package(
        name=tags.get("package_name", ""),
        version=tags.get("package_version", ""),
        ecosystem=tags.get("ecosystem", ""),
        is_direct=tags.get("is_direct", "true") == "true",
        dependency_depth=int(tags.get("dependency_depth", "0") or 0),
        parent_package=tags.get("parent_package") or None,
    )


def estate_vulnerability(advisory: DemoAdvisory) -> Vulnerability:
    return Vulnerability(
        id=advisory.vuln_id,
        summary=advisory.summary,
        severity=Severity(advisory.severity),
        cvss_score=advisory.cvss_score,
        cwe_ids=[advisory.cwe] if advisory.cwe else [],
        fixed_version=advisory.fixed,
        is_kev=advisory.is_kev,
        kev_status="listed" if advisory.is_kev else None,
        kev_date_added=advisory.kev_date_added or None,
        kev_due_date=advisory.kev_due_date or None,
        epss_score=demo_epss(advisory),
        epss_percentile=demo_epss_percentile(advisory),
        # Network exploitability is a property of the advisory, not of the
        # host: a KEV entry with a network CVSS vector is exploitable wherever
        # it runs. Derived from the catalog, never from whether the estate
        # marked the workload internet-facing, so the two signals stay
        # independent when the graph fuses them.
        network_exploitable=advisory.cvss_score >= 7.0,
    )


def estate_blast_radius(asset: EstateAsset, advisory: DemoAdvisory) -> BlastRadius:
    """Tagged and scored exactly as a live package scan does before converting.

    Without the tags every framework list reached the converter empty; without
    the score every estate occurrence, KEV entries included, reported risk 0.
    """
    blast_radius = BlastRadius(
        vulnerability=estate_vulnerability(advisory),
        package=estate_package(asset),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    apply_framework_tags(blast_radius)
    blast_radius.calculate_risk_score()
    return blast_radius
