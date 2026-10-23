---
type: fixed
---

{
  "schema_version": "intel.lookup.v1",
  "found": true,
  "query": "CVE-2024-3651",
  "advisory": {
    "id": "CVE-2024-3651",
    "canonical_ids": {
      "cves": [
        "CVE-2024-3651"
      ],
      "ghsas": [
        "GHSA-JJG7-2V4V-X38H"
      ],
      "osv": [
        "PYSEC-2024-60"
      ],
      "cwes": [
        "CWE-1333"
      ]
    },
    "summary": "Denial of Service via Quadratic Complexity in kjd/idna",
    "severity": "medium",
    "cvss_score": 6.2,
    "cvss_vector": "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
    "fixed_version": null,
    "source": "osv",
    "published_at": "2024-07-07T17:22:10.032Z",
    "modified_at": "2026-08-12T03:51:09.898544479Z",
    "epss_probability": 0.01386,
    "epss_percentile": 0.69919,
    "is_kev": false,
    "kev_date_added": null,
    "affected": [
      {
        "ecosystem": "alpine:v3.19",
        "package_name": "py3-idna",
        "introduced": "0",
        "fixed": "3.7-r0",
        "last_affected": ""
      },
      {
        "ecosystem": "alpine:v3.20",
        "package_name": "py3-idna",
        "introduced": "0",
        "fixed": "3.7-r0",
        "last_affected": ""
      },
      {
        "ecosystem": "alpine:v3.21",
        "package_name": "py3-idna",
        "introduced": "0",
        "fixed": "3.7-r0",
        "last_affected": ""
      },
      {
        "ecosystem": "alpine:v3.22",
        "package_name": "py3-idna",
        "introduced": "0",
        "fixed": "3.7-r0",
        "last_affected": ""
      },
      {
        "ecosystem": "alpine:v3.23",
        "package_name": "py3-idna",
        "introduced": "0",
        "fixed": "3.7-r0",
        "last_affected": ""
      }
    ],
    "matched_by": "id_or_alias",
    "match_method": "id_or_alias",
    "match_confidence": "high",
    "match_reason": "Matched advisory identifier or alias exactly.",
    "source_policy": {
      "source_id": "osv",
      "support_status": "supported",
      "redistribution": "structured_records",
      "license_or_terms_url": "https://github.com/google/osv.dev/blob/master/LICENSE",
      "validation_status": "structured_feed"
    },
    "evidence_links": [
      {
        "kind": "cve",
        "id": "CVE-2024-3651",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-3651"
      },
      {
        "kind": "epss",
        "id": "CVE-2024-3651",
        "url": "https://api.first.org/data/v1/epss?cve=CVE-2024-3651"
      },
      {
        "kind": "ghsa",
        "id": "GHSA-JJG7-2V4V-X38H",
        "url": "https://github.com/advisories/GHSA-JJG7-2V4V-X38H"
      },
      {
        "kind": "osv",
        "id": "PYSEC-2024-60",
        "url": "https://osv.dev/vulnerability/PYSEC-2024-60"
      },
      {
        "kind": "cwe",
        "id": "CWE-1333",
        "url": "https://cwe.mitre.org/data/definitions/1333.html"
      }
    ]
  }
}
