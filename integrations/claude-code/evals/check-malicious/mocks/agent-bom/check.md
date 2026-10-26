---
type: fixed
---

{
 "package": "event-stream",
 "version": "3.3.6",
 "ecosystem": "npm",
 "ecosystems": [
  "npm"
 ],
 "package_canonical_id": "ad51c8cf-bb5a-5333-99c1-146866cef928",
 "purl": null,
 "canonical_verdict": "malicious",
 "message": "MALICIOUS package event-stream@3.3.6 \u2014 Known malicious package (GHSA-mh6f-8j2x-4483). Do not install.",
 "lookup_mode": "online",
 "is_malicious": true,
 "malicious_reason": "Known malicious package (GHSA-mh6f-8j2x-4483)",
 "vulnerability_count": 1,
 "vulnerability_details": [
  {
   "id": "GHSA-mh6f-8j2x-4483",
   "summary": "Critical severity vulnerability that affects event-stream and flatmap-stream",
   "severity": "critical",
   "fixed_version": "4.0.0",
   "match_confidence_tier": "osv_range",
   "is_kev": false,
   "kev_date_added": null,
   "kev_due_date": null,
   "upstream_ids": [],
   "epss_cve_id": null,
   "kev_cve_id": null,
   "cvss_score": 9.8,
   "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
   "attack_vector": "network",
   "attack_complexity": "low",
   "privileges_required": "none",
   "user_interaction": "none",
   "network_exploitable": true,
   "epss_score": null,
   "epss_percentile": null,
   "nvd_status": null,
   "published_at": "2018-11-26T23:58:21Z",
   "modified_at": "2021-09-15T20:08:26Z",
   "cwe_ids": [
    "CWE-506"
   ],
   "aliases": [],
   "references": [
    "https://github.com/advisories/GHSA-mh6f-8j2x-4483",
    "https://github.com/dominictarr/event-stream",
    "https://github.com/dominictarr/event-stream/issues/116"
   ],
   "advisory_sources": [
    "osv"
   ],
   "compliance_tags": {
    "nist_ai_rmf": [
     "GOVERN-6.1",
     "MANAGE-1.3",
     "MAP-4.1"
    ],
    "nist_csf": [
     "GV.SC-05",
     "GV.SC-07",
     "ID.RA-05",
     "RS.AN-03"
    ],
    "nist_800_53": [
     "CM-6",
     "SI-2",
     "SI-4",
     "SR-3"
    ],
    "fedramp": [
     "FedRAMP-CM-6",
     "FedRAMP-SI-2",
     "FedRAMP-SI-4",
     "FedRAMP-SR-3"
    ],
    "cis": [
     "CIS-02.3",
     "CIS-07.4"
    ],
    "iso_27001": [
     "A.5.19",
     "A.5.20",
     "A.5.21",
     "A.8.28",
     "A.8.8"
    ],
    "soc2": [
     "CC8.1",
     "CC9.1",
     "CC9.2"
    ],
    "eu_ai_act": [
     "ART-15",
     "ART-17",
     "ART-9"
    ],
    "owasp_mcp": [
     "MCP04"
    ],
    "owasp_agentic": [
     "ASI04"
    ]
   }
  }
 ],
 "scan_warnings": [],
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
 "completeness": {
  "status": "complete",
  "reason": ""
 },
 "status": "malicious",
 "vulnerabilities": 1,
 "details": [
  {
   "id": "GHSA-mh6f-8j2x-4483",
   "summary": "Critical severity vulnerability that affects event-stream and flatmap-stream",
   "severity": "critical",
   "fixed_version": "4.0.0",
   "match_confidence_tier": "osv_range",
   "is_kev": false,
   "kev_date_added": null,
   "kev_due_date": null,
   "upstream_ids": [],
   "epss_cve_id": null,
   "kev_cve_id": null,
   "cvss_score": 9.8,
   "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
   "attack_vector": "network",
   "attack_complexity": "low",
   "privileges_required": "none",
   "user_interaction": "none",
   "network_exploitable": true,
   "epss_score": null,
   "epss_percentile": null,
   "nvd_status": null,
   "published_at": "2018-11-26T23:58:21Z",
   "modified_at": "2021-09-15T20:08:26Z",
   "cwe_ids": [
    "CWE-506"
   ],
   "aliases": [],
   "references": [
    "https://github.com/advisories/GHSA-mh6f-8j2x-4483",
    "https://github.com/dominictarr/event-stream",
    "https://github.com/dominictarr/event-stream/issues/116"
   ],
   "advisory_sources": [
    "osv"
   ],
   "compliance_tags": {
    "nist_ai_rmf": [
     "GOVERN-6.1",
     "MANAGE-1.3",
     "MAP-4.1"
    ],
    "nist_csf": [
     "GV.SC-05",
     "GV.SC-07",
     "ID.RA-05",
     "RS.AN-03"
    ],
    "nist_800_53": [
     "CM-6",
     "SI-2",
     "SI-4",
     "SR-3"
    ],
    "fedramp": [
     "FedRAMP-CM-6",
     "FedRAMP-SI-2",
     "FedRAMP-SI-4",
     "FedRAMP-SR-3"
    ],
    "cis": [
     "CIS-02.3",
     "CIS-07.4"
    ],
    "iso_27001": [
     "A.5.19",
     "A.5.20",
     "A.5.21",
     "A.8.28",
     "A.8.8"
    ],
    "soc2": [
     "CC8.1",
     "CC9.1",
     "CC9.2"
    ],
    "eu_ai_act": [
     "ART-15",
     "ART-17",
     "ART-9"
    ],
    "owasp_mcp": [
     "MCP04"
    ],
    "owasp_agentic": [
     "ASI04"
    ]
   }
  }
 ]
}
