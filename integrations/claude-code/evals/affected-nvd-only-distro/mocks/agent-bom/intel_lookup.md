---
type: fixed
---

{
 "schema_version": "intel.lookup.v1",
 "found": true,
 "query": "CVE-2026-109618",
 "advisory": {
  "id": "CVE-2026-109618",
  "canonical_ids": {
   "cves": [
    "CVE-2026-109618"
   ],
   "ghsas": [],
   "osv": [],
   "cwes": [
    "CWE-1325",
    "CWE-416",
    "CWE-755",
    "CWE-824"
   ]
  },
  "summary": "PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).",
  "severity": "critical",
  "cvss_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "fixed_version": null,
  "source": "nvd",
  "published_at": "2026-10-21T14:17:09.357",
  "modified_at": "2026-10-23T16:26:54.713",
  "epss_probability": null,
  "epss_percentile": null,
  "is_kev": false,
  "kev_date_added": null,
  "affected": [],
  "matched_by": "id_or_alias",
  "match_method": "id_or_alias",
  "match_confidence": "high",
  "match_reason": "Matched advisory identifier or alias exactly.",
  "source_policy": {
   "source_id": "nvd",
   "support_status": "supported",
   "redistribution": "structured_enrichment",
   "license_or_terms_url": "https://nvd.nist.gov/general/terms-of-use",
   "validation_status": "structured_feed"
  },
  "evidence_links": [
   {
    "kind": "cve",
    "id": "CVE-2026-109618",
    "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-109618"
   },
   {
    "kind": "epss",
    "id": "CVE-2026-109618",
    "url": "https://api.first.org/data/v1/epss?cve=CVE-2026-109618"
   },
   {
    "kind": "cwe",
    "id": "CWE-1325",
    "url": "https://cwe.mitre.org/data/definitions/1325.html"
   },
   {
    "kind": "cwe",
    "id": "CWE-416",
    "url": "https://cwe.mitre.org/data/definitions/416.html"
   },
   {
    "kind": "cwe",
    "id": "CWE-755",
    "url": "https://cwe.mitre.org/data/definitions/755.html"
   },
   {
    "kind": "cwe",
    "id": "CWE-824",
    "url": "https://cwe.mitre.org/data/definitions/824.html"
   }
  ]
 }
}
