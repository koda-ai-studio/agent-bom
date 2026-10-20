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
  "total_mcp_servers": 3,
  "total_packages": 2,
  "unique_packages": 2,
  "total_vulnerabilities": 0,
  "critical_findings": 0,
  "total_findings": 4,
  "unique_assets": 2,
  "critical_unified_findings": 0,
  "high_unified_findings": 4,
  "coverage_warnings": []
 },
 "counts": {
  "agents": 1,
  "mcp_servers": 3,
  "packages": 2,
  "unique_packages": 2,
  "vulnerabilities": 0,
  "findings": 4,
  "findings_by_severity": {
   "critical": 0,
   "high": 4,
   "medium": 0,
   "low": 0,
   "unknown": 0
  },
  "findings_by_type": {
   "COMBINATION": 1,
   "PROMPT_SECURITY": 3
  },
  "findings_by_category": {
   "prompt_security": 3,
   "combination": 1
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
  }
 ],
 "affected_paths": [],
 "agents": [
  {
   "name": "project:proj",
   "agent_type": "custom",
   "mcp_servers": 3,
   "packages": 2
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
