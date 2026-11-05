---
type: fixed
---

{
 "detail": "summary",
 "result_id": "IZ4iED4YaZ389feBZQYAayMlh8T6O7NQ",
 "schema_version": "1.0",
 "document_type": "AI-BOM",
 "ai_bom_version": "0.113.2",
 "scan_id": "",
 "generated_at": "2026-11-05T21:57:55.864933+00:00",
 "scan_sources": [
  "agent_discovery",
  "repo_tree"
 ],
 "posture_grade": "N/A",
 "posture_grade_label": "N/A",
 "warnings": [
  "1 package(s) skipped due to unresolved versions"
 ],
 "coverage_warnings": [
  {
   "kind": "scope_exclusion",
   "ecosystem": "filesystem-discovery",
   "release": "filesystem-discovery:431e3c9e690e3f0a:directory_policy",
   "reason": "directory_policy",
   "detail": "Paths were excluded by scanner policy, linked-worktree or symlink rules; contents were not inspected.",
   "package_count": 0,
   "advisory_rows": 0,
   "excluded_count": 1,
   "source_labels": [
    "<path:agent-bom-review-demo>"
   ]
  },
  {
   "kind": "package_version_gap",
   "release": "unresolved-package-versions",
   "reason": "unresolved_version",
   "package_count": 1,
   "detail": "Package versions are unresolved or invalid; supply resolved lockfiles or valid release versions."
  }
 ],
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
  "total_agents": 2,
  "installed_unconfigured_agents": 0,
  "total_mcp_servers": 2,
  "total_packages": 2,
  "unique_packages": 2,
  "total_vulnerabilities": 2,
  "suppressed_vulnerabilities": 0,
  "vulnerability_occurrences": 2,
  "suppressed_unfixed_os_findings": 0,
  "critical_findings": 0,
  "total_findings": 6,
  "unique_assets": 3,
  "critical_unified_findings": 0,
  "high_unified_findings": 5,
  "coverage_warnings": [
   {
    "kind": "scope_exclusion",
    "ecosystem": "filesystem-discovery",
    "release": "filesystem-discovery:431e3c9e690e3f0a:directory_policy",
    "reason": "directory_policy",
    "detail": "Paths were excluded by scanner policy, linked-worktree or symlink rules; contents were not inspected.",
    "package_count": 0,
    "advisory_rows": 0,
    "excluded_count": 1,
    "source_labels": [
     "<path:agent-bom-review-demo>"
    ]
   },
   {
    "kind": "package_version_gap",
    "release": "unresolved-package-versions",
    "reason": "unresolved_version",
    "package_count": 1,
    "detail": "Package versions are unresolved or invalid; supply resolved lockfiles or valid release versions."
   }
  ]
 },
 "counts": {
  "agents": 2,
  "mcp_servers": 2,
  "packages": 2,
  "unique_packages": 2,
  "vulnerabilities": 2,
  "findings": 6,
  "findings_by_severity": {
   "critical": 0,
   "high": 5,
   "medium": 1,
   "low": 0,
   "unknown": 0
  },
  "findings_by_type": {
   "COMBINATION": 1,
   "CVE": 2,
   "PROMPT_SECURITY": 3
  },
  "findings_by_category": {
   "prompt_security": 3,
   "vulnerability": 2,
   "combination": 1
  },
  "kev": 0,
  "suppressed": 0,
  "exposure_paths": 2
 },
 "posture": {
  "grade": "N/A",
  "grade_label": "N/A",
  "partial": false,
  "score": 0.0,
  "summary": "Vulnerability coverage incomplete \u2014 posture grade unavailable. Re-run once vulnerability data is available."
 },
 "top_findings": [
  {
   "id": "026f7e4a-0213-57ad-a7f0-fd7094b8f8a3",
   "title": "No authentication observed in MCP server configuration",
   "severity": "high",
   "finding_category": "prompt_security",
   "finding_type": "PROMPT_SECURITY",
   "cve_id": null,
   "risk_score": 8.0,
   "cvss_score": null,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": null,
   "remediation_guidance": "Require OAuth 2.1 (or at minimum a verified bearer token) on the MCP server, or front it with the agent-bom gateway/proxy and bind authorized agents via bound_agents.",
   "reachability": null,
   "asset": "f75d1859-0a68-5acf-88a4-7fd53845a5b8",
   "affected_agents": [],
   "affected_servers": []
  },
  {
   "id": "501efaac-cbee-5917-885e-3e82ac32ac43",
   "title": "AI agent can reach a credential or privileged tool: project:agent-bom-review-demo \u2192 demo-notes \u2192 DEMO_API_TOKEN",
   "severity": "high",
   "finding_category": "combination",
   "finding_type": "COMBINATION",
   "cve_id": null,
   "risk_score": 7.5,
   "cvss_score": null,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": null,
   "remediation_guidance": "Broker credentials through a short-lived token issuer instead of exposing them to the agent, and scope the agent's tools to the minimum required.",
   "reachability": null,
   "asset": "59e47271-c62f-50f2-8818-507e570466b0",
   "affected_agents": [],
   "affected_servers": []
  },
  {
   "id": "8ba0bf65-8a66-5282-93f0-65b1c29d8520",
   "title": "Remote MCP server over non-TLS transport",
   "severity": "high",
   "finding_category": "prompt_security",
   "finding_type": "PROMPT_SECURITY",
   "cve_id": null,
   "risk_score": 7.0,
   "cvss_score": null,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": null,
   "remediation_guidance": "Serve the remote MCP endpoint over HTTPS/WSS (TLS) and reject plaintext connections.",
   "reachability": null,
   "asset": "f75d1859-0a68-5acf-88a4-7fd53845a5b8",
   "affected_agents": [],
   "affected_servers": []
  },
  {
   "id": "d45b1ae4-16c8-5c9f-8377-89d1d28233c5",
   "title": "No verified agent identity observed in MCP configuration",
   "severity": "high",
   "finding_category": "prompt_security",
   "finding_type": "PROMPT_SECURITY",
   "cve_id": null,
   "risk_score": 7.0,
   "cvss_score": null,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": null,
   "remediation_guidance": "Front the MCP server with the agent-bom gateway/proxy, bind the calling agent via bound_agents, and require a verified agent identity (require_agent_identity / OAuth).",
   "reachability": null,
   "asset": "f75d1859-0a68-5acf-88a4-7fd53845a5b8",
   "affected_agents": [],
   "affected_servers": []
  },
  {
   "id": "4252d098-6072-5bb1-b1f1-3785e9ad0adc",
   "title": "CVE-2024-3651: idna@3.6",
   "severity": "high",
   "finding_category": "vulnerability",
   "finding_type": "CVE",
   "cve_id": "CVE-2024-3651",
   "risk_score": 6.5,
   "cvss_score": 7.5,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": "3.7",
   "remediation_guidance": "Upgrade idna to 3.7.",
   "reachability": "unknown",
   "is_direct": true,
   "dependency_depth": 0,
   "introduced_via": null,
   "asset": "pkg:pypi/idna@3.6",
   "affected_agents": [
    "project dependencies"
   ],
   "affected_servers": [
    "project dependencies"
   ]
  },
  {
   "id": "d4434ca4-6412-526e-b0c6-a9bd96b6958b",
   "title": "CVE-2026-45409: idna@3.6",
   "severity": "medium",
   "finding_category": "vulnerability",
   "finding_type": "CVE",
   "cve_id": "CVE-2026-45409",
   "risk_score": 4.5,
   "cvss_score": 5.3,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": "3.15",
   "remediation_guidance": "Upgrade idna to 3.15.",
   "reachability": "unknown",
   "is_direct": true,
   "dependency_depth": 0,
   "introduced_via": null,
   "asset": "pkg:pypi/idna@3.6",
   "affected_agents": [
    "project dependencies"
   ],
   "affected_servers": [
    "project dependencies"
   ]
  }
 ],
 "affected_paths": [
  {
   "id": "blast:cve-2024-3651:pypi:idna:3.6",
   "rank": 1,
   "label": "idna@3.6 -> CVE-2024-3651",
   "summary": "Denial of service (CWE-1333) may disrupt service availability. Does not expose credentials or tools.",
   "severity": "high",
   "riskScore": 6.5,
   "fix": "Upgrade idna to 3.7",
   "affectedAgents": [
    "project dependencies"
   ],
   "affectedServers": [
    "project dependencies"
   ]
  },
  {
   "id": "blast:cve-2026-45409:pypi:idna:3.6",
   "rank": 2,
   "label": "idna@3.6 -> CVE-2026-45409",
   "summary": "Denial of service (CWE-1333) may disrupt service availability. Does not expose credentials or tools.",
   "severity": "medium",
   "riskScore": 4.5,
   "fix": "Upgrade idna to 3.15",
   "affectedAgents": [
    "project dependencies"
   ],
   "affectedServers": [
    "project dependencies"
   ]
  }
 ],
 "agents": [
  {
   "name": "project:agent-bom-review-demo",
   "agent_type": "custom",
   "mcp_servers": 2,
   "packages": 1
  },
  {
   "name": "project dependencies",
   "agent_type": "custom",
   "mcp_servers": 1,
   "packages": 1
  }
 ],
 "sections": {
  "scan_run": {
   "kind": "object",
   "keys": 11
  },
  "warnings": {
   "kind": "list",
   "total": 1
  },
  "scan_sources": {
   "kind": "list",
   "total": 2
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
   "total": 2
  },
  "summary": {
   "kind": "object",
   "keys": 15
  },
  "finding_summary": {
   "kind": "object",
   "keys": 5
  },
  "assets": {
   "kind": "list",
   "total": 3
  },
  "coverage_warnings": {
   "kind": "list",
   "total": 2
  },
  "inventory_snapshot": {
   "kind": "object",
   "keys": 4
  },
  "agents": {
   "kind": "list",
   "total": 2
  },
  "blast_radius": {
   "kind": "list",
   "total": 2
  },
  "exposure_paths": {
   "kind": "list",
   "total": 2
  },
  "findings": {
   "kind": "list",
   "total": 6
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
   "total": 1
  },
  "enforcement": {
   "kind": "object",
   "keys": 8
  },
  "toxic_combinations_graph": {
   "kind": "object",
   "keys": 4
  },
  "vuln_data_freshness": {
   "kind": "object",
   "keys": 9
  },
  "ai_inventory": {
   "kind": "object",
   "keys": 11
  },
  "posture_scorecard": {
   "kind": "object",
   "keys": 10
  },
  "credential_risk_ranking": {
   "kind": "list",
   "total": 1
  },
  "incident_correlation": {
   "kind": "list",
   "total": 1
  }
 },
 "next": {
  "result_id": "IZ4iED4YaZ389feBZQYAayMlh8T6O7NQ",
  "how": "Call scan again with result_id and a section name from 'sections' (for example section='findings', offset=0, limit=25) to page full-fidelity records, or pass detail='full' on a new scan for the whole document (bounded to the response budget).",
  "expires_in_seconds": 1800
 }
}
