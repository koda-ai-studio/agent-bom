---
type: fixed
---

{
 "detail": "summary",
 "result_id": "Hq2v0x9bTc3mK7eL1pRwYs5uN8aZdF4g",
 "schema_version": "1.0",
 "document_type": "AI-BOM",
 "ai_bom_version": "0.111.0",
 "scan_id": "",
 "generated_at": "2026-10-24T15:02:41.118204+00:00",
 "scan_sources": [
  "container_image"
 ],
 "posture_grade": "A",
 "warnings": [],
 "coverage_warnings": [],
 "vuln_data_freshness": {
  "mode": "local",
  "sources": [
   "OSV",
   "ALPINE",
   "DEBIAN",
   "EPSS",
   "KEV",
   "NVD"
  ],
  "last_updated": "2026-10-24T06:10:12.402113+00:00",
  "age_hours": 9,
  "age_days": 0,
  "record_count": 914233,
  "stale": false,
  "danger": false,
  "max_age_hours": 24
 },
 "vulnerability_lookup": "local",
 "summary": {
  "total_agents": 1,
  "total_mcp_servers": 0,
  "total_packages": 143,
  "unique_packages": 143,
  "total_vulnerabilities": 0,
  "critical_findings": 0,
  "total_findings": 0,
  "unique_assets": 1,
  "critical_unified_findings": 0,
  "high_unified_findings": 0,
  "coverage_warnings": []
 },
 "counts": {
  "agents": 1,
  "mcp_servers": 0,
  "packages": 143,
  "unique_packages": 143,
  "vulnerabilities": 0,
  "findings": 0,
  "findings_by_severity": {
   "critical": 0,
   "high": 0,
   "medium": 0,
   "low": 0,
   "unknown": 0
  },
  "findings_by_type": {},
  "findings_by_category": {},
  "kev": 0,
  "suppressed": 0,
  "exposure_paths": 0
 },
 "posture": {
  "grade": "A",
  "score": 96.0,
  "summary": "No vulnerabilities found (A, 96.0%)"
 },
 "top_findings": [],
 "affected_paths": [],
 "possibly_affected": [
  {
   "id": "CVE-2026-109618",
   "verdict": "possibly_affected",
   "reason": "distro_backport_unverified",
   "detail": "distro package php8.2-cli 8.2.29-1~deb12u1 ships php; verify against the distribution's advisory",
   "cpe_product": "php:php",
   "upstream_version": "8.2.29",
   "upstream_fixed_version": "8.2.35",
   "severity": "critical",
   "cvss_score": 9.8,
   "summary": "PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).",
   "source": "nvd",
   "package": {
    "name": "php8.2-cli",
    "version": "8.2.29-1~deb12u1",
    "ecosystem": "deb",
    "purl": "pkg:deb/debian/php8.2-cli@8.2.29-1~deb12u1?distro=debian-12",
    "stable_id": "deb-php8.2-cli-8.2.29",
    "source_package": "php8.2",
    "distro_name": "debian",
    "distro_version": "12"
   },
   "agents": [
    "image:registry.example.com/shop/web:2.3"
   ],
   "images": [
    "docker://registry.example.com/shop/web:2.3"
   ]
  },
  {
   "id": "CVE-2026-109619",
   "verdict": "possibly_affected",
   "reason": "distro_backport_unverified",
   "detail": "distro package php8.2-cli 8.2.29-1~deb12u1 ships php; verify against the distribution's advisory",
   "cpe_product": "php:php",
   "upstream_version": "8.2.29",
   "upstream_fixed_version": "8.2.35",
   "severity": "high",
   "cvss_score": 8.1,
   "summary": "PHP has various global state that temporarily points into request memory; it may not be correctly reset and can lead to remote code execution.",
   "source": "nvd",
   "package": {
    "name": "php8.2-cli",
    "version": "8.2.29-1~deb12u1",
    "ecosystem": "deb",
    "purl": "pkg:deb/debian/php8.2-cli@8.2.29-1~deb12u1?distro=debian-12",
    "stable_id": "deb-php8.2-cli-8.2.29",
    "source_package": "php8.2",
    "distro_name": "debian",
    "distro_version": "12"
   },
   "agents": [
    "image:registry.example.com/shop/web:2.3"
   ],
   "images": [
    "docker://registry.example.com/shop/web:2.3"
   ]
  }
 ],
 "sections": {
  "packages": {
   "kind": "list",
   "total": 143
  },
  "findings": {
   "kind": "list",
   "total": 0
  },
  "possibly_affected": {
   "kind": "list",
   "total": 2
  }
 },
 "next": "Page a section with scan(result_id=..., section='possibly_affected', offset=0, limit=25)."
}
