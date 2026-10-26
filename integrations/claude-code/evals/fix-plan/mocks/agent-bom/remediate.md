---
type: fixed
---

{
 "generated_at": "2026-10-26T05:25:33.257852+00:00",
 "package_fixes": [
  {
   "package": "minimist",
   "ecosystem": "npm",
   "current_version": "1.2.5",
   "fixed_version": "1.2.6",
   "command": "npm install minimist@1.2.6",
   "vulns": [
    "CVE-2021-44906"
   ],
   "total_vulns": 1,
   "agents": [
    "repo-deps:root"
   ],
   "total_agents": 1,
   "references": [
    "https://github.com/Marynk/JavaScript-vulnerability-detection/blob/main/minimist%20PoC.zip",
    "https://github.com/minimistjs/minimist/commit/34e20b8461118608703d6485326abbb8e35e1703",
    "https://github.com/minimistjs/minimist/commit/bc8ecee43875261f4f17eb20b1243d3ed15e70eb",
    "https://github.com/minimistjs/minimist/commit/c2b981977fa834b223b408cfb860f933c9811e4d",
    "https://github.com/minimistjs/minimist/commit/ef9153fc52b6cea0744b2239921c5dcae4697f11"
   ],
   "total_references": 5
  },
  {
   "package": "axios",
   "ecosystem": "npm",
   "current_version": "0.21.0",
   "fixed_version": "0.33.0",
   "command": "npm install axios@0.33.0",
   "vulns": [
    "CVE-2020-28168",
    "CVE-2021-3749",
    "CVE-2023-45857",
    "CVE-2025-27152",
    "CVE-2025-62718"
   ],
   "total_vulns": 25,
   "agents": [
    "repo-deps:root"
   ],
   "total_agents": 1,
   "references": [
    "https://access.redhat.com/errata/RHSA-2026:20889",
    "https://access.redhat.com/errata/RHSA-2026:20938",
    "https://access.redhat.com/errata/RHSA-2026:26234",
    "https://access.redhat.com/errata/RHSA-2026:27044",
    "https://access.redhat.com/errata/RHSA-2026:27063",
    "https://cert-portal.siemens.com/productcert/html/ssa-876049.html",
    "https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf",
    "https://datatracker.ietf.org/doc/html/rfc1034",
    "https://datatracker.ietf.org/doc/html/rfc3986",
    "https://github.com/axios/axios"
   ],
   "total_references": 71
  },
  {
   "package": "lodash",
   "ecosystem": "npm",
   "current_version": "4.17.20",
   "fixed_version": "4.18.0",
   "command": "npm install lodash@4.18.0",
   "vulns": [
    "CVE-2020-28500",
    "CVE-2021-23337",
    "CVE-2025-13465",
    "CVE-2026-2950",
    "CVE-2026-4800"
   ],
   "total_vulns": 5,
   "agents": [
    "repo-deps:root"
   ],
   "total_agents": 1,
   "references": [
    "https://cert-portal.siemens.com/productcert/html/ssa-253495.html",
    "https://cert-portal.siemens.com/productcert/pdf/ssa-637483.pdf",
    "https://cna.openjsf.org/security-advisories.html",
    "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
    "https://github.com/github/advisory-database/pull/6139",
    "https://github.com/lodash/lodash",
    "https://github.com/lodash/lodash/blob/ddfd9b11a0126db2302cb70ec9973b66baec0975/lodash.js",
    "https://github.com/lodash/lodash/blob/npm/trimEnd.js%23L8",
    "https://github.com/lodash/lodash/commit/3469357cff396a26c363f8c1b5a91dde28ba4b1c",
    "https://github.com/lodash/lodash/commit/c4847ebe7d14540bb28a8b932a9ce1b9ecbfee1a"
   ],
   "total_references": 17
  },
  {
   "package": "express",
   "ecosystem": "npm",
   "current_version": "4.17.1",
   "fixed_version": "4.20.0",
   "command": "npm install express@4.20.0",
   "vulns": [
    "CVE-2024-29041",
    "CVE-2024-43796"
   ],
   "total_vulns": 2,
   "agents": [
    "repo-deps:root"
   ],
   "total_agents": 1,
   "references": [
    "https://expressjs.com/en/4x/api.html",
    "https://github.com/expressjs/express",
    "https://github.com/expressjs/express/commit/0867302ddbde0e9463d0564fea5861feb708c2dd",
    "https://github.com/expressjs/express/commit/0b746953c4bd8e377123527db11f9cd866e39f94",
    "https://github.com/expressjs/express/commit/54271f69b511fea198471e6ff3400ab805d6b553",
    "https://github.com/expressjs/express/pull/5539",
    "https://github.com/expressjs/express/security/advisories/GHSA-qw6h-vgh9-j6wx",
    "https://nvd.nist.gov/vuln/detail/CVE-2024-43796"
   ],
   "total_references": 8
  }
 ],
 "credential_fixes": [],
 "total_unfixable": 1,
 "unfixable": [
  {
   "package": "event-stream",
   "ecosystem": "npm",
   "current_version": "3.3.6",
   "reason": "known malicious package",
   "vulns": [
    "GHSA-mh6f-8j2x-4483"
   ],
   "agents": [
    "repo-deps:root"
   ],
   "references": [
    "https://github.com/advisories/GHSA-mh6f-8j2x-4483",
    "https://github.com/dominictarr/event-stream",
    "https://github.com/dominictarr/event-stream/issues/116"
   ]
  }
 ]
}
