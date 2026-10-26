---
type: fixed
---

{
 "detail": "summary",
 "result_id": "_gqt4yLIVtF-3oqDUdjlAEm2hb1hiDW3",
 "schema_version": "1.0",
 "document_type": "AI-BOM",
 "ai_bom_version": "0.111.0",
 "scan_id": "",
 "generated_at": "2026-10-26T05:25:28.091747+00:00",
 "scan_sources": [
  "repo_tree"
 ],
 "posture_grade": "D",
 "warnings": [],
 "coverage_warnings": [],
 "vuln_data_freshness": {
  "mode": "live",
  "sources": [
   "OSV",
   "GHSA",
   "NVD"
  ],
  "last_updated": null,
  "age_hours": null,
  "age_days": null,
  "record_count": 0,
  "stale": false,
  "danger": false,
  "max_age_hours": 24
 },
 "vulnerability_lookup": "online",
 "summary": {
  "total_agents": 1,
  "total_mcp_servers": 0,
  "total_packages": 5,
  "unique_packages": 5,
  "total_vulnerabilities": 34,
  "critical_findings": 2,
  "total_findings": 34,
  "unique_assets": 5,
  "critical_unified_findings": 2,
  "high_unified_findings": 14,
  "coverage_warnings": []
 },
 "counts": {
  "agents": 1,
  "mcp_servers": 0,
  "packages": 5,
  "unique_packages": 5,
  "vulnerabilities": 34,
  "findings": 34,
  "findings_by_severity": {
   "critical": 2,
   "high": 14,
   "medium": 17,
   "low": 1,
   "unknown": 0
  },
  "findings_by_type": {
   "CVE": 34
  },
  "findings_by_category": {
   "vulnerability": 34
  },
  "kev": 1,
  "suppressed": 0,
  "exposure_paths": 34
 },
 "posture": {
  "grade": "D",
  "score": 65.5,
  "summary": "Weak best-practice/config posture (D, 65.5%) \u2014 immediate attention required"
 },
 "top_findings": [
  {
   "id": "e5f874a4-c57e-532b-8b4b-6986863c76d1",
   "title": "CVE-2021-44906: minimist@1.2.5",
   "severity": "critical",
   "finding_category": "vulnerability",
   "finding_type": "CVE",
   "cve_id": "CVE-2021-44906",
   "risk_score": 8.5,
   "cvss_score": 9.8,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": "1.2.6",
   "remediation_guidance": "Upgrade minimist to 1.2.6.",
   "reachability": "unknown",
   "is_direct": true,
   "dependency_depth": 0,
   "introduced_via": null,
   "asset": "pkg:npm/minimist@1.2.5",
   "affected_agents": [
    "repo-deps:root"
   ],
   "affected_servers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "fe30490d-00ef-5a02-af4c-a96d61437e0d",
   "title": "GHSA-mh6f-8j2x-4483: event-stream@3.3.6",
   "severity": "critical",
   "finding_category": "vulnerability",
   "finding_type": "CVE",
   "cve_id": "GHSA-mh6f-8j2x-4483",
   "risk_score": 8.5,
   "cvss_score": 9.8,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": "4.0.0",
   "remediation_guidance": "Remove event-stream from all environments immediately (Known malicious package (GHSA-mh6f-8j2x-4483)).",
   "reachability": "unknown",
   "is_direct": true,
   "dependency_depth": 0,
   "introduced_via": null,
   "asset": "pkg:npm/event-stream@3.3.6",
   "affected_agents": [
    "repo-deps:root"
   ],
   "affected_servers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "be44d979-011a-5370-b10b-00479467d369",
   "title": "CVE-2021-23337: lodash@4.17.20",
   "severity": "high",
   "finding_category": "vulnerability",
   "finding_type": "CVE",
   "cve_id": "CVE-2021-23337",
   "risk_score": 6.5,
   "cvss_score": 7.2,
   "epss_score": null,
   "is_kev": true,
   "kev_due_date": "2026-11-14",
   "fixed_version": "4.17.21",
   "remediation_guidance": "Upgrade lodash to 4.17.21.",
   "reachability": "unknown",
   "is_direct": true,
   "dependency_depth": 0,
   "introduced_via": null,
   "asset": "pkg:npm/lodash@4.17.20",
   "affected_agents": [
    "repo-deps:root"
   ],
   "affected_servers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "d515fc65-e6b9-59b1-9af4-2f21f138f8ac",
   "title": "CVE-2026-4800: lodash@4.17.20",
   "severity": "high",
   "finding_category": "vulnerability",
   "finding_type": "CVE",
   "cve_id": "CVE-2026-4800",
   "risk_score": 6.5,
   "cvss_score": 8.1,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": "4.18.0",
   "remediation_guidance": "Upgrade lodash to 4.18.0.",
   "reachability": "unknown",
   "is_direct": true,
   "dependency_depth": 0,
   "introduced_via": null,
   "asset": "pkg:npm/lodash@4.17.20",
   "affected_agents": [
    "repo-deps:root"
   ],
   "affected_servers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "97584cfe-c11d-50ee-97fd-fa1017c810c4",
   "title": "CVE-2021-3749: axios@0.21.0",
   "severity": "high",
   "finding_category": "vulnerability",
   "finding_type": "CVE",
   "cve_id": "CVE-2021-3749",
   "risk_score": 6.5,
   "cvss_score": 7.5,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": "0.21.2",
   "remediation_guidance": "Upgrade axios to 0.21.2.",
   "reachability": "unknown",
   "is_direct": true,
   "dependency_depth": 0,
   "introduced_via": null,
   "asset": "pkg:npm/axios@0.21.0",
   "affected_agents": [
    "repo-deps:root"
   ],
   "affected_servers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "6002a288-f020-5e24-842a-45f0870f0a16",
   "title": "CVE-2025-27152: axios@0.21.0",
   "severity": "high",
   "finding_category": "vulnerability",
   "finding_type": "CVE",
   "cve_id": "CVE-2025-27152",
   "risk_score": 6.5,
   "cvss_score": 7.7,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": "0.30.0",
   "remediation_guidance": "Upgrade axios to 0.30.0.",
   "reachability": "unknown",
   "is_direct": true,
   "dependency_depth": 0,
   "introduced_via": null,
   "asset": "pkg:npm/axios@0.21.0",
   "affected_agents": [
    "repo-deps:root"
   ],
   "affected_servers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "f4a6e8ab-df64-56a8-9d83-ddf15657658f",
   "title": "CVE-2026-25639: axios@0.21.0",
   "severity": "high",
   "finding_category": "vulnerability",
   "finding_type": "CVE",
   "cve_id": "CVE-2026-25639",
   "risk_score": 6.5,
   "cvss_score": 7.5,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": "0.30.3",
   "remediation_guidance": "Upgrade axios to 0.30.3.",
   "reachability": "unknown",
   "is_direct": true,
   "dependency_depth": 0,
   "introduced_via": null,
   "asset": "pkg:npm/axios@0.21.0",
   "affected_agents": [
    "repo-deps:root"
   ],
   "affected_servers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "1a7b4810-7161-5bc9-b2f3-9e93bed189cf",
   "title": "CVE-2026-42033: axios@0.21.0",
   "severity": "high",
   "finding_category": "vulnerability",
   "finding_type": "CVE",
   "cve_id": "CVE-2026-42033",
   "risk_score": 6.5,
   "cvss_score": 7.4,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": "0.31.1",
   "remediation_guidance": "Upgrade axios to 0.31.1.",
   "reachability": "unknown",
   "is_direct": true,
   "dependency_depth": 0,
   "introduced_via": null,
   "asset": "pkg:npm/axios@0.21.0",
   "affected_agents": [
    "repo-deps:root"
   ],
   "affected_servers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "75b7c54f-5c0c-5435-a07b-919ed96fefe5",
   "title": "CVE-2026-42035: axios@0.21.0",
   "severity": "high",
   "finding_category": "vulnerability",
   "finding_type": "CVE",
   "cve_id": "CVE-2026-42035",
   "risk_score": 6.5,
   "cvss_score": 7.4,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": "0.31.1",
   "remediation_guidance": "Upgrade axios to 0.31.1.",
   "reachability": "unknown",
   "is_direct": true,
   "dependency_depth": 0,
   "introduced_via": null,
   "asset": "pkg:npm/axios@0.21.0",
   "affected_agents": [
    "repo-deps:root"
   ],
   "affected_servers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "8766c1f9-283e-5cb7-9bb5-78a897da8a6d",
   "title": "CVE-2026-42039: axios@0.21.0",
   "severity": "high",
   "finding_category": "vulnerability",
   "finding_type": "CVE",
   "cve_id": "CVE-2026-42039",
   "risk_score": 6.5,
   "cvss_score": 7.5,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": "0.31.1",
   "remediation_guidance": "Upgrade axios to 0.31.1.",
   "reachability": "unknown",
   "is_direct": true,
   "dependency_depth": 0,
   "introduced_via": null,
   "asset": "pkg:npm/axios@0.21.0",
   "affected_agents": [
    "repo-deps:root"
   ],
   "affected_servers": [
    "repo-deps:root"
   ]
  }
 ],
 "affected_paths": [
  {
   "id": "blast:cve-2021-44906:npm:minimist:1.2.5",
   "rank": 1,
   "label": "minimist@1.2.5 -> CVE-2021-44906",
   "summary": "Code execution (CWE-1321) grants full server access.",
   "severity": "critical",
   "riskScore": 8.5,
   "fix": "Upgrade minimist to 1.2.6",
   "affectedAgents": [
    "repo-deps:root"
   ],
   "affectedServers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "blast:ghsa-mh6f-8j2x-4483:npm:event-stream:3.3.6",
   "rank": 2,
   "label": "event-stream@3.3.6 -> GHSA-mh6f-8j2x-4483",
   "summary": "Vulnerability (CWE-506) has unknown impact because CWE/advisory metadata is missing or unsupported. No credential or tool reach is asserted without evidence.",
   "severity": "critical",
   "riskScore": 8.5,
   "fix": "Upgrade event-stream to 4.0.0",
   "affectedAgents": [
    "repo-deps:root"
   ],
   "affectedServers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "blast:cve-2021-23337:npm:lodash:4.17.20",
   "rank": 3,
   "label": "lodash@4.17.20 -> CVE-2021-23337",
   "summary": "Code execution (CWE-77) grants full server access.",
   "severity": "high",
   "riskScore": 6.5,
   "fix": "Upgrade lodash to 4.17.21",
   "affectedAgents": [
    "repo-deps:root"
   ],
   "affectedServers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "blast:cve-2026-4800:npm:lodash:4.17.20",
   "rank": 4,
   "label": "lodash@4.17.20 -> CVE-2026-4800",
   "summary": "Code execution (CWE-94) grants full server access.",
   "severity": "high",
   "riskScore": 6.5,
   "fix": "Upgrade lodash to 4.18.0",
   "affectedAgents": [
    "repo-deps:root"
   ],
   "affectedServers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "blast:cve-2021-3749:npm:axios:0.21.0",
   "rank": 5,
   "label": "axios@0.21.0 -> CVE-2021-3749",
   "summary": "Denial of service (CWE-1333) may disrupt service availability. Does not expose credentials or tools.",
   "severity": "high",
   "riskScore": 6.5,
   "fix": "Upgrade axios to 0.21.2",
   "affectedAgents": [
    "repo-deps:root"
   ],
   "affectedServers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "blast:cve-2025-27152:npm:axios:0.21.0",
   "rank": 6,
   "label": "axios@0.21.0 -> CVE-2025-27152",
   "summary": "SSRF (CWE-918) enables internal service access.",
   "severity": "high",
   "riskScore": 6.5,
   "fix": "Upgrade axios to 0.30.0",
   "affectedAgents": [
    "repo-deps:root"
   ],
   "affectedServers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "blast:cve-2026-25639:npm:axios:0.21.0",
   "rank": 7,
   "label": "axios@0.21.0 -> CVE-2026-25639",
   "summary": "Code execution (CWE-1321) grants full server access.",
   "severity": "high",
   "riskScore": 6.5,
   "fix": "Upgrade axios to 0.30.3",
   "affectedAgents": [
    "repo-deps:root"
   ],
   "affectedServers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "blast:cve-2026-42033:npm:axios:0.21.0",
   "rank": 8,
   "label": "axios@0.21.0 -> CVE-2026-42033",
   "summary": "Code execution (CWE-1321) grants full server access.",
   "severity": "high",
   "riskScore": 6.5,
   "fix": "Upgrade axios to 0.31.1",
   "affectedAgents": [
    "repo-deps:root"
   ],
   "affectedServers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "blast:cve-2026-42035:npm:axios:0.21.0",
   "rank": 9,
   "label": "axios@0.21.0 -> CVE-2026-42035",
   "summary": "Code execution (CWE-113) grants full server access.",
   "severity": "high",
   "riskScore": 6.5,
   "fix": "Upgrade axios to 0.31.1",
   "affectedAgents": [
    "repo-deps:root"
   ],
   "affectedServers": [
    "repo-deps:root"
   ]
  },
  {
   "id": "blast:cve-2026-42039:npm:axios:0.21.0",
   "rank": 10,
   "label": "axios@0.21.0 -> CVE-2026-42039",
   "summary": "Denial of service (CWE-674) may disrupt service availability. Does not expose credentials or tools.",
   "severity": "high",
   "riskScore": 6.5,
   "fix": "Upgrade axios to 0.31.1",
   "affectedAgents": [
    "repo-deps:root"
   ],
   "affectedServers": [
    "repo-deps:root"
   ]
  }
 ],
 "agents": [
  {
   "name": "repo-deps:root",
   "agent_type": "custom",
   "mcp_servers": 1,
   "packages": 5
  }
 ],
 "sections": {
  "scan_run": {
   "kind": "object",
   "keys": 11
  },
  "scan_sources": {
   "kind": "list",
   "total": 1
  },
  "framework_catalogs": {
   "kind": "object",
   "keys": 1
  },
  "ai_bom_entities": {
   "kind": "object",
   "keys": 9
  },
  "packages": {
   "kind": "list",
   "total": 5
  },
  "summary": {
   "kind": "object",
   "keys": 11
  },
  "finding_summary": {
   "kind": "object",
   "keys": 5
  },
  "assets": {
   "kind": "list",
   "total": 5
  },
  "inventory_snapshot": {
   "kind": "object",
   "keys": 4
  },
  "agents": {
   "kind": "list",
   "total": 1
  },
  "blast_radius": {
   "kind": "list",
   "total": 34
  },
  "exposure_paths": {
   "kind": "list",
   "total": 34
  },
  "findings": {
   "kind": "list",
   "total": 34
  },
  "threat_framework_summary": {
   "kind": "object",
   "keys": 20
  },
  "scorecard_summary": {
   "kind": "object",
   "keys": 10
  },
  "remediation_plan": {
   "kind": "list",
   "total": 5
  },
  "enforcement": {
   "kind": "object",
   "keys": 8
  },
  "vuln_data_freshness": {
   "kind": "object",
   "keys": 9
  },
  "ai_inventory": {
   "kind": "object",
   "keys": 2
  },
  "posture_scorecard": {
   "kind": "object",
   "keys": 6
  },
  "incident_correlation": {
   "kind": "list",
   "total": 1
  }
 },
 "next": {
  "result_id": "_gqt4yLIVtF-3oqDUdjlAEm2hb1hiDW3",
  "how": "Call scan again with result_id and a section name from 'sections' (for example section='findings', offset=0, limit=25) to page full-fidelity records, or pass detail='full' on a new scan for the whole document (bounded to the response budget).",
  "expires_in_seconds": 1800
 }
}
