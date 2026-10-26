---
type: fixed
---

{
 "detail": "summary",
 "result_id": "_IQsPp77PAJ_ipC8D_QYaj2JwrnsGBMK",
 "schema_version": "1.0",
 "document_type": "AI-BOM",
 "ai_bom_version": "0.109.0",
 "scan_id": "",
 "generated_at": "2026-10-20T13:50:10.204708+00:00",
 "scan_sources": [
  "agent_discovery",
  "repo_tree"
 ],
 "posture_grade": "C",
 "warnings": [
  "1 secret or credential pattern(s) found in repository files",
  "SAST skipped: semgrep_unavailable",
  "No .tf files found in /home/dev/proj"
 ],
 "coverage_warnings": [],
 "vuln_data_freshness": {
  "mode": "local",
  "sources": [
   "EPSS",
   "KEV",
   "ALPINE",
   "DEBIAN"
  ],
  "last_updated": "2026-08-19T04:05:01.471624+00:00",
  "age_hours": 1497,
  "age_days": 62,
  "record_count": 902048,
  "stale": true,
  "danger": true,
  "max_age_hours": 24
 },
 "vulnerability_lookup": "online",
 "summary": {
  "total_agents": 1,
  "total_mcp_servers": 4,
  "total_packages": 3,
  "unique_packages": 3,
  "total_vulnerabilities": 1,
  "critical_findings": 0,
  "total_findings": 6,
  "unique_assets": 3,
  "critical_unified_findings": 0,
  "high_unified_findings": 5,
  "coverage_warnings": []
 },
 "counts": {
  "agents": 1,
  "mcp_servers": 4,
  "packages": 3,
  "unique_packages": 3,
  "vulnerabilities": 1,
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
   "PROMPT_SECURITY": 3,
   "CVE": 1,
   "MALICIOUS_PACKAGE": 1
  },
  "findings_by_category": {
   "prompt_security": 3,
   "combination": 1,
   "vulnerability": 1,
   "malicious": 1
  },
  "kev": 0,
  "suppressed": 0,
  "exposure_paths": 0
 },
 "posture": {
  "grade": "C",
  "score": 78.7,
  "summary": "No vulnerabilities found; config/best-practice improvements recommended (C, 78.7%)"
 },
 "top_findings": [
  {
   "id": "bc6610b9-c345-5e20-b560-f4201132d810",
   "title": "CVE-2025-53109: @modelcontextprotocol/server-filesystem@2.0.0",
   "severity": "high",
   "finding_category": "vulnerability",
   "finding_type": "CVE",
   "cve_id": "CVE-2025-53109",
   "risk_score": 7.9,
   "cvss_score": 8.4,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": "2025.7.1",
   "remediation_guidance": "Upgrade @modelcontextprotocol/server-filesystem to 2025.7.1.",
   "reachability": "unknown",
   "is_direct": true,
   "dependency_depth": 0,
   "introduced_via": null,
   "asset": "pkg:npm/@modelcontextprotocol/server-filesystem@2.0.0",
   "affected_agents": [
    "project:proj"
   ],
   "affected_servers": [
    "fs-tools"
   ]
  },
  {
   "id": "b2ac4374-7eb3-587b-94ce-3d54df30d0fc",
   "title": "No authentication observed in MCP server configuration",
   "severity": "high",
   "finding_category": "prompt_security",
   "finding_type": "PROMPT_SECURITY",
   "cve_id": null,
   "risk_score": 8.0,
   "cvss_score": null,
   "epss_score": null,
   "is_kev": false,
   "fixed_version": null,
   "remediation_guidance": "***REDACTED***",
   "reachability": null,
   "asset": "2d2c55b2-4cd1-580f-ad31-65cfb9def6a6",
   "affected_agents": [],
   "affected_servers": []
  },
  {
   "id": "b889fca9-50c1-58b2-a2f9-d3cd9d88e113",
   "title": "AI agent can reach a credential or privileged tool: project:proj",
   "severity": "high",
   "finding_category": "combination",
   "finding_type": "COMBINATION",
   "cve_id": null,
   "risk_score": 7.5,
   "cvss_score": null,
   "epss_score": null,
   "is_kev": false,
   "fixed_version": null,
   "remediation_guidance": "Broker credentials through a short-lived token issuer instead of exposing them to the agent, and scope the agent's tools to the minimum required.",
   "reachability": null,
   "asset": "7a10cb45-4a31-519f-8689-468ed94bdbe4",
   "affected_agents": [],
   "affected_servers": []
  },
  {
   "id": "bea310a5-b602-5b5c-bac4-e6ffe269e766",
   "title": "Remote MCP server over non-TLS transport",
   "severity": "high",
   "finding_category": "prompt_security",
   "finding_type": "PROMPT_SECURITY",
   "cve_id": null,
   "risk_score": 7.0,
   "cvss_score": null,
   "epss_score": null,
   "is_kev": false,
   "fixed_version": null,
   "remediation_guidance": "Serve the remote MCP endpoint over HTTPS/WSS (TLS) and reject plaintext connections.",
   "reachability": null,
   "asset": "2d2c55b2-4cd1-580f-ad31-65cfb9def6a6",
   "affected_agents": [],
   "affected_servers": []
  },
  {
   "id": "17a91410-8f6b-5909-9e78-33c6b441e6d1",
   "title": "No verified agent identity observed in MCP configuration",
   "severity": "high",
   "finding_category": "prompt_security",
   "finding_type": "PROMPT_SECURITY",
   "cve_id": null,
   "risk_score": 7.0,
   "cvss_score": null,
   "epss_score": null,
   "is_kev": false,
   "fixed_version": null,
   "remediation_guidance": "Front the MCP server with the agent-bom gateway/proxy, bind the calling agent via bound_agents, and require a verified agent identity (require_agent_identity / OAuth).",
   "reachability": null,
   "asset": "2d2c55b2-4cd1-580f-ad31-65cfb9def6a6",
   "affected_agents": [],
   "affected_servers": []
  },
  {
   "id": "2fd2f87e-ce9e-5e53-a642-f31f2f478ce4",
   "title": "Malicious package: postmark-mcp@1.0.16",
   "severity": "medium",
   "finding_category": "malicious",
   "finding_type": "MALICIOUS_PACKAGE",
   "cve_id": "MAL-2025-47604",
   "risk_score": 10.0,
   "cvss_score": null,
   "epss_score": null,
   "is_kev": false,
   "kev_due_date": null,
   "fixed_version": null,
   "remediation_guidance": "Remove postmark-mcp from all environments immediately (Known malicious package (MAL-2025-47604)).",
   "reachability": "unknown",
   "is_direct": true,
   "dependency_depth": 0,
   "introduced_via": null,
   "asset": "pkg:npm/postmark-mcp@1.0.16",
   "affected_agents": [
    "project:proj"
   ],
   "affected_servers": [
    "mail"
   ]
  }
 ],
 "affected_paths": [],
 "agents": [
  {
   "name": "project:proj",
   "agent_type": "custom",
   "mcp_servers": 4,
   "packages": 3
  }
 ],
 "sections": {
  "scan_run": {
   "kind": "object",
   "keys": 11
  },
  "warnings": {
   "kind": "list",
   "total": 3
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
   "keys": 11
  },
  "finding_summary": {
   "kind": "object",
   "keys": 5
  },
  "assets": {
   "kind": "list",
   "total": 2
  },
  "inventory_snapshot": {
   "kind": "object",
   "keys": 4
  },
  "agents": {
   "kind": "list",
   "total": 1
  },
  "exposure_paths": {
   "kind": "list",
   "total": 0
  },
  "findings": {
   "kind": "list",
   "total": 4
  },
  "threat_framework_summary": {
   "kind": "object",
   "keys": 20
  },
  "scorecard_summary": {
   "kind": "object",
   "keys": 10
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
  "posture_scorecard": {
   "kind": "object",
   "keys": 6
  },
  "credential_risk_ranking": {
   "kind": "list",
   "total": 2
  }
 },
 "next": {
  "result_id": "_IQsPp77PAJ_ipC8D_QYaj2JwrnsGBMK",
  "how": "Call scan again with result_id and a section name from 'sections' (for example section='findings', offset=0, limit=25) to page full-fidelity records, or pass detail='full' on a new scan for the whole document (bounded to the response budget).",
  "expires_in_seconds": 1800
 }
}
