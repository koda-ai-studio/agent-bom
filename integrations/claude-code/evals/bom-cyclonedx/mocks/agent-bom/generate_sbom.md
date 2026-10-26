---
type: fixed
---

{
 "bomFormat": "CycloneDX",
 "specVersion": "1.7",
 "serialNumber": "urn:uuid:46cac782-0f5f-4d7f-b2cb-34c678aec7eb",
 "version": 1,
 "metadata": {
  "timestamp": "2026-10-26T05:25:37.190043+00:00",
  "tools": {
   "components": [
    {
     "type": "application",
     "name": "agent-bom",
     "version": "0.110.0",
     "description": "Security scanner for AI infrastructure \u2014 from agent to runtime"
    }
   ]
  },
  "properties": [
   {
    "name": "agent-bom:total-agents",
    "value": "1"
   },
   {
    "name": "agent-bom:canonical-id-schema-version",
    "value": "3"
   },
   {
    "name": "agent-bom:total-mcp-servers",
    "value": "0"
   },
   {
    "name": "agent-bom:total-vulnerabilities",
    "value": "34"
   },
   {
    "name": "agent-bom:ml-models",
    "value": "0"
   },
   {
    "name": "agent-bom:scan-outcome",
    "value": "complete"
   },
   {
    "name": "agent-bom:scan-issue-count",
    "value": "0"
   }
  ]
 },
 "components": [
  {
   "type": "application",
   "bom-ref": "agent-f4e42863-da9e-5eed-92fe-d753d2846add",
   "name": "repo-deps:root",
   "version": "unknown",
   "description": "AI Agent (custom)",
   "properties": [
    {
     "name": "agent-bom:type",
     "value": "ai-agent"
    },
    {
     "name": "agent-bom:canonical-id-schema-version",
     "value": "3"
    },
    {
     "name": "agent-bom:config-path",
     "value": "<path:shop-api>"
    },
    {
     "name": "agent-bom:status",
     "value": "configured"
    },
    {
     "name": "agent-bom:previous-canonical-id",
     "value": "93b96d4a-58b2-56e4-8e38-ec0a2f7d45b1"
    },
    {
     "name": "agent-bom:previous-canonical-id",
     "value": "ecbab8ee-5551-58c9-860c-ea1c4ff6f3ee"
    },
    {
     "name": "agent-bom:discovery-provenance:collector",
     "value": "manifest_parser"
    },
    {
     "name": "agent-bom:discovery-provenance:confidence",
     "value": "high"
    },
    {
     "name": "agent-bom:discovery-provenance:observed-via",
     "value": "[\"repo_lockfile\"]"
    },
    {
     "name": "agent-bom:discovery-provenance:source",
     "value": "repo-lockfiles"
    },
    {
     "name": "agent-bom:discovery-provenance:source-type",
     "value": "unknown"
    }
   ]
  },
  {
   "type": "application",
   "bom-ref": "mcp-server-167db7ea-4ebf-5b24-8a2b-75872ec99e0a",
   "name": "repo-deps:root",
   "description": "Dependency surface (filesystem)",
   "properties": [
    {
     "name": "agent-bom:inventory-members",
     "value": "[\"pkg-47162878-3ffc-5954-832d-809465b1cb86\", \"pkg-63150a0f-6db4-5d35-b26d-45ff141e19cd\", \"pkg-ad51c8cf-bb5a-5333-99c1-146866cef928\", \"pkg-e0e865f6-8076-51c5-951b-56ff0150eaa2\", \"pkg-e9968e25-23c5-54fb-a7f8-784beb5517d0\"]"
    },
    {
     "name": "agent-bom:type",
     "value": "dependency-surface"
    },
    {
     "name": "agent-bom:surface",
     "value": "filesystem"
    },
    {
     "name": "agent-bom:command",
     "value": ""
    },
    {
     "name": "agent-bom:transport",
     "value": "stdio"
    },
    {
     "name": "agent-bom:discovery-provenance:collector",
     "value": "manifest_parser"
    },
    {
     "name": "agent-bom:discovery-provenance:confidence",
     "value": "high"
    },
    {
     "name": "agent-bom:discovery-provenance:observed-via",
     "value": "[\"repo_lockfile\"]"
    },
    {
     "name": "agent-bom:discovery-provenance:source",
     "value": "repo-lockfiles"
    },
    {
     "name": "agent-bom:discovery-provenance:source-type",
     "value": "unknown"
    }
   ]
  },
  {
   "type": "library",
   "bom-ref": "pkg-e0e865f6-8076-51c5-951b-56ff0150eaa2",
   "name": "lodash",
   "version": "4.17.20",
   "properties": [
    {
     "name": "agent-bom:ecosystem",
     "value": "npm"
    },
    {
     "name": "agent-bom:is-direct",
     "value": "true"
    },
    {
     "name": "agent-bom:dependency-depth",
     "value": "0"
    },
    {
     "name": "agent-bom:dependency-scope",
     "value": "runtime"
    },
    {
     "name": "agent-bom:reachability-evidence",
     "value": "declaration_only"
    },
    {
     "name": "agent-bom:resolved-from-registry",
     "value": "false"
    },
    {
     "name": "agent-bom:version-source",
     "value": "manifest"
    },
    {
     "name": "agent-bom:version-provenance-source",
     "value": "command_pin"
    },
    {
     "name": "agent-bom:version-provenance-confidence",
     "value": "exact"
    },
    {
     "name": "agent-bom:floating-reference",
     "value": "false"
    },
    {
     "name": "agent-bom:discovery-provenance:collector",
     "value": "manifest_parser"
    },
    {
     "name": "agent-bom:discovery-provenance:confidence",
     "value": "high"
    },
    {
     "name": "agent-bom:discovery-provenance:observed-via",
     "value": "[\"repo_lockfile\"]"
    },
    {
     "name": "agent-bom:discovery-provenance:resolved-from-registry",
     "value": "false"
    },
    {
     "name": "agent-bom:discovery-provenance:source",
     "value": "repo-lockfiles"
    },
    {
     "name": "agent-bom:discovery-provenance:source-type",
     "value": "unknown"
    },
    {
     "name": "agent-bom:discovery-provenance:version-provenance",
     "value": "{\"confidence\":\"exact\",\"declared_name\":\"lodash\",\"declared_version\":\"4.17.20\",\"evidence\":[{\"line\":1,\"source_file\":\"<path:package.json>\",\"type\":\"manifest\"}],\"legacy_version_source\":\"manifest\",\"pinned\":true,\"pinned_version\":\"4.17.20\",\"resolved_from_registry\":false,\"resolved_version\":\"4.17.20\",\"source_precedence\":30,\"version_source\":\"command_pin\"}"
    },
    {
     "name": "agent-bom:discovery-provenance:version-source",
     "value": "manifest"
    }
   ],
   "purl": "pkg:npm/lodash@4.17.20"
  },
  {
   "type": "library",
   "bom-ref": "pkg-63150a0f-6db4-5d35-b26d-45ff141e19cd",
   "name": "minimist",
   "version": "1.2.5",
   "properties": [
    {
     "name": "agent-bom:ecosystem",
     "value": "npm"
    },
    {
     "name": "agent-bom:is-direct",
     "value": "true"
    },
    {
     "name": "agent-bom:dependency-depth",
     "value": "0"
    },
    {
     "name": "agent-bom:dependency-scope",
     "value": "runtime"
    },
    {
     "name": "agent-bom:reachability-evidence",
     "value": "declaration_only"
    },
    {
     "name": "agent-bom:resolved-from-registry",
     "value": "false"
    },
    {
     "name": "agent-bom:version-source",
     "value": "manifest"
    },
    {
     "name": "agent-bom:version-provenance-source",
     "value": "command_pin"
    },
    {
     "name": "agent-bom:version-provenance-confidence",
     "value": "exact"
    },
    {
     "name": "agent-bom:floating-reference",
     "value": "false"
    },
    {
     "name": "agent-bom:discovery-provenance:collector",
     "value": "manifest_parser"
    },
    {
     "name": "agent-bom:discovery-provenance:confidence",
     "value": "high"
    },
    {
     "name": "agent-bom:discovery-provenance:observed-via",
     "value": "[\"repo_lockfile\"]"
    },
    {
     "name": "agent-bom:discovery-provenance:resolved-from-registry",
     "value": "false"
    },
    {
     "name": "agent-bom:discovery-provenance:source",
     "value": "repo-lockfiles"
    },
    {
     "name": "agent-bom:discovery-provenance:source-type",
     "value": "unknown"
    },
    {
     "name": "agent-bom:discovery-provenance:version-provenance",
     "value": "{\"confidence\":\"exact\",\"declared_name\":\"minimist\",\"declared_version\":\"1.2.5\",\"legacy_version_source\":\"manifest\",\"pinned\":true,\"pinned_version\":\"1.2.5\",\"resolved_from_registry\":false,\"resolved_version\":\"1.2.5\",\"source_precedence\":30,\"version_source\":\"command_pin\"}"
    },
    {
     "name": "agent-bom:discovery-provenance:version-source",
     "value": "manifest"
    }
   ],
   "purl": "pkg:npm/minimist@1.2.5"
  },
  {
   "type": "library",
   "bom-ref": "pkg-ad51c8cf-bb5a-5333-99c1-146866cef928",
   "name": "event-stream",
   "version": "3.3.6",
   "properties": [
    {
     "name": "agent-bom:ecosystem",
     "value": "npm"
    },
    {
     "name": "agent-bom:is-direct",
     "value": "true"
    },
    {
     "name": "agent-bom:dependency-depth",
     "value": "0"
    },
    {
     "name": "agent-bom:dependency-scope",
     "value": "runtime"
    },
    {
     "name": "agent-bom:reachability-evidence",
     "value": "declaration_only"
    },
    {
     "name": "agent-bom:resolved-from-registry",
     "value": "false"
    },
    {
     "name": "agent-bom:version-source",
     "value": "manifest"
    },
    {
     "name": "agent-bom:version-provenance-source",
     "value": "command_pin"
    },
    {
     "name": "agent-bom:version-provenance-confidence",
     "value": "exact"
    },
    {
     "name": "agent-bom:floating-reference",
     "value": "false"
    },
    {
     "name": "agent-bom:discovery-provenance:collector",
     "value": "manifest_parser"
    },
    {
     "name": "agent-bom:discovery-provenance:confidence",
     "value": "high"
    },
    {
     "name": "agent-bom:discovery-provenance:observed-via",
     "value": "[\"repo_lockfile\"]"
    },
    {
     "name": "agent-bom:discovery-provenance:resolved-from-registry",
     "value": "false"
    },
    {
     "name": "agent-bom:discovery-provenance:source",
     "value": "repo-lockfiles"
    },
    {
     "name": "agent-bom:discovery-provenance:source-type",
     "value": "unknown"
    },
    {
     "name": "agent-bom:discovery-provenance:version-provenance",
     "value": "{\"confidence\":\"exact\",\"declared_name\":\"event-stream\",\"declared_version\":\"3.3.6\",\"legacy_version_source\":\"manifest\",\"pinned\":true,\"pinned_version\":\"3.3.6\",\"resolved_from_registry\":false,\"resolved_version\":\"3.3.6\",\"source_precedence\":30,\"version_source\":\"command_pin\"}"
    },
    {
     "name": "agent-bom:discovery-provenance:version-source",
     "value": "manifest"
    },
    {
     "name": "agent-bom:is-malicious",
     "value": "true"
    },
    {
     "name": "agent-bom:malicious-reason",
     "value": "Known malicious package (GHSA-mh6f-8j2x-4483)"
    }
   ],
   "purl": "pkg:npm/event-stream@3.3.6"
  },
  {
   "type": "library",
   "bom-ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86",
   "name": "axios",
   "version": "0.21.0",
   "properties": [
    {
     "name": "agent-bom:ecosystem",
     "value": "npm"
    },
    {
     "name": "agent-bom:is-direct",
     "value": "true"
    },
    {
     "name": "agent-bom:dependency-depth",
     "value": "0"
    },
    {
     "name": "agent-bom:dependency-scope",
     "value": "runtime"
    },
    {
     "name": "agent-bom:reachability-evidence",
     "value": "declaration_only"
    },
    {
     "name": "agent-bom:resolved-from-registry",
     "value": "false"
    },
    {
     "name": "agent-bom:version-source",
     "value": "manifest"
    },
    {
     "name": "agent-bom:version-provenance-source",
     "value": "command_pin"
    },
    {
     "name": "agent-bom:version-provenance-confidence",
     "value": "exact"
    },
    {
     "name": "agent-bom:floating-reference",
     "value": "false"
    },
    {
     "name": "agent-bom:discovery-provenance:collector",
     "value": "manifest_parser"
    },
    {
     "name": "agent-bom:discovery-provenance:confidence",
     "value": "high"
    },
    {
     "name": "agent-bom:discovery-provenance:observed-via",
     "value": "[\"repo_lockfile\"]"
    },
    {
     "name": "agent-bom:discovery-provenance:resolved-from-registry",
     "value": "false"
    },
    {
     "name": "agent-bom:discovery-provenance:source",
     "value": "repo-lockfiles"
    },
    {
     "name": "agent-bom:discovery-provenance:source-type",
     "value": "unknown"
    },
    {
     "name": "agent-bom:discovery-provenance:version-provenance",
     "value": "{\"confidence\":\"exact\",\"declared_name\":\"axios\",\"declared_version\":\"0.21.0\",\"legacy_version_source\":\"manifest\",\"pinned\":true,\"pinned_version\":\"0.21.0\",\"resolved_from_registry\":false,\"resolved_version\":\"0.21.0\",\"source_precedence\":30,\"version_source\":\"command_pin\"}"
    },
    {
     "name": "agent-bom:discovery-provenance:version-source",
     "value": "manifest"
    }
   ],
   "purl": "pkg:npm/axios@0.21.0"
  },
  {
   "type": "library",
   "bom-ref": "pkg-e9968e25-23c5-54fb-a7f8-784beb5517d0",
   "name": "express",
   "version": "4.17.1",
   "properties": [
    {
     "name": "agent-bom:ecosystem",
     "value": "npm"
    },
    {
     "name": "agent-bom:is-direct",
     "value": "true"
    },
    {
     "name": "agent-bom:dependency-depth",
     "value": "0"
    },
    {
     "name": "agent-bom:dependency-scope",
     "value": "runtime"
    },
    {
     "name": "agent-bom:reachability-evidence",
     "value": "declaration_only"
    },
    {
     "name": "agent-bom:resolved-from-registry",
     "value": "false"
    },
    {
     "name": "agent-bom:version-source",
     "value": "manifest"
    },
    {
     "name": "agent-bom:version-provenance-source",
     "value": "command_pin"
    },
    {
     "name": "agent-bom:version-provenance-confidence",
     "value": "exact"
    },
    {
     "name": "agent-bom:floating-reference",
     "value": "false"
    },
    {
     "name": "agent-bom:discovery-provenance:collector",
     "value": "manifest_parser"
    },
    {
     "name": "agent-bom:discovery-provenance:confidence",
     "value": "high"
    },
    {
     "name": "agent-bom:discovery-provenance:observed-via",
     "value": "[\"repo_lockfile\"]"
    },
    {
     "name": "agent-bom:discovery-provenance:resolved-from-registry",
     "value": "false"
    },
    {
     "name": "agent-bom:discovery-provenance:source",
     "value": "repo-lockfiles"
    },
    {
     "name": "agent-bom:discovery-provenance:source-type",
     "value": "unknown"
    },
    {
     "name": "agent-bom:discovery-provenance:version-provenance",
     "value": "{\"confidence\":\"exact\",\"declared_name\":\"express\",\"declared_version\":\"4.17.1\",\"legacy_version_source\":\"manifest\",\"pinned\":true,\"pinned_version\":\"4.17.1\",\"resolved_from_registry\":false,\"resolved_version\":\"4.17.1\",\"source_precedence\":30,\"version_source\":\"command_pin\"}"
    },
    {
     "name": "agent-bom:discovery-provenance:version-source",
     "value": "manifest"
    }
   ],
   "purl": "pkg:npm/express@4.17.1"
  }
 ],
 "dependencies": [
  {
   "ref": "agent-f4e42863-da9e-5eed-92fe-d753d2846add",
   "dependsOn": [
    "mcp-server-167db7ea-4ebf-5b24-8a2b-75872ec99e0a"
   ]
  },
  {
   "ref": "mcp-server-167db7ea-4ebf-5b24-8a2b-75872ec99e0a",
   "dependsOn": [
    "pkg-47162878-3ffc-5954-832d-809465b1cb86",
    "pkg-63150a0f-6db4-5d35-b26d-45ff141e19cd",
    "pkg-ad51c8cf-bb5a-5333-99c1-146866cef928",
    "pkg-e0e865f6-8076-51c5-951b-56ff0150eaa2",
    "pkg-e9968e25-23c5-54fb-a7f8-784beb5517d0"
   ]
  }
 ],
 "formulation": [
  {
   "components": [
    {
     "type": "application",
     "name": "agent-bom",
     "version": "0.110.0"
    }
   ]
  }
 ],
 "vulnerabilities": [
  {
   "id": "CVE-2020-28168",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2020-28168"
   },
   "ratings": [
    {
     "score": 5.9,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
    }
   ],
   "cwes": [
    918
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2020-28500",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2020-28500"
   },
   "ratings": [
    {
     "score": 5.3,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
    }
   ],
   "cwes": [
    1333,
    400
   ],
   "affects": [
    {
     "ref": "pkg-e0e865f6-8076-51c5-951b-56ff0150eaa2"
    }
   ]
  },
  {
   "id": "CVE-2021-23337",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2021-23337"
   },
   "ratings": [
    {
     "score": 7.2,
     "severity": "high",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
    }
   ],
   "cwes": [
    77,
    94
   ],
   "affects": [
    {
     "ref": "pkg-e0e865f6-8076-51c5-951b-56ff0150eaa2"
    }
   ]
  },
  {
   "id": "CVE-2021-3749",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2021-3749"
   },
   "ratings": [
    {
     "score": 7.5,
     "severity": "high",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    }
   ],
   "cwes": [
    1333,
    400
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2021-44906",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2021-44906"
   },
   "ratings": [
    {
     "score": 9.8,
     "severity": "critical",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    }
   ],
   "cwes": [
    1321
   ],
   "affects": [
    {
     "ref": "pkg-63150a0f-6db4-5d35-b26d-45ff141e19cd"
    }
   ]
  },
  {
   "id": "CVE-2023-45857",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2023-45857"
   },
   "ratings": [
    {
     "score": 6.5,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"
    }
   ],
   "cwes": [
    352
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2024-29041",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2024-29041"
   },
   "ratings": [
    {
     "score": 6.1,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    }
   ],
   "cwes": [
    1286,
    601
   ],
   "affects": [
    {
     "ref": "pkg-e9968e25-23c5-54fb-a7f8-784beb5517d0"
    }
   ]
  },
  {
   "id": "CVE-2024-43796",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2024-43796"
   },
   "ratings": [
    {
     "score": 5.0,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L"
    }
   ],
   "cwes": [
    79
   ],
   "affects": [
    {
     "ref": "pkg-e9968e25-23c5-54fb-a7f8-784beb5517d0"
    }
   ]
  },
  {
   "id": "CVE-2025-13465",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2025-13465"
   },
   "ratings": [
    {
     "score": 6.5,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"
    }
   ],
   "cwes": [
    1321
   ],
   "affects": [
    {
     "ref": "pkg-e0e865f6-8076-51c5-951b-56ff0150eaa2"
    }
   ]
  },
  {
   "id": "CVE-2025-27152",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2025-27152"
   },
   "ratings": [
    {
     "score": 7.7,
     "severity": "high",
     "method": "CVSSv4",
     "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:P"
    }
   ],
   "cwes": [
    918
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2025-62718",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2025-62718"
   },
   "ratings": [
    {
     "score": 4.8,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
    }
   ],
   "cwes": [
    441,
    918
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-25639",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-25639"
   },
   "ratings": [
    {
     "score": 7.5,
     "severity": "high",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    }
   ],
   "cwes": [
    1321,
    754
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-2950",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-2950"
   },
   "ratings": [
    {
     "score": 6.5,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L"
    }
   ],
   "cwes": [
    1321
   ],
   "affects": [
    {
     "ref": "pkg-e0e865f6-8076-51c5-951b-56ff0150eaa2"
    }
   ]
  },
  {
   "id": "CVE-2026-40175",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-40175"
   },
   "ratings": [
    {
     "score": 4.8,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
    }
   ],
   "cwes": [
    113,
    444,
    918
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-42033",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-42033"
   },
   "ratings": [
    {
     "score": 7.4,
     "severity": "high",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
    }
   ],
   "cwes": [
    1321
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-42034",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-42034"
   },
   "ratings": [
    {
     "score": 5.3,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
    }
   ],
   "cwes": [
    770
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-42035",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-42035"
   },
   "ratings": [
    {
     "score": 7.4,
     "severity": "high",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"
    }
   ],
   "cwes": [
    113,
    1321
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-42036",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-42036"
   },
   "ratings": [
    {
     "score": 5.3,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"
    }
   ],
   "cwes": [
    770
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-42038",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-42038"
   },
   "ratings": [
    {
     "score": 6.8,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N"
    }
   ],
   "cwes": [
    918
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-42039",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-42039"
   },
   "ratings": [
    {
     "score": 7.5,
     "severity": "high",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    }
   ],
   "cwes": [
    674
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-42040",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-42040"
   },
   "ratings": [
    {
     "score": 3.7,
     "severity": "low",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"
    }
   ],
   "cwes": [
    116,
    626
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-42041",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-42041"
   },
   "ratings": [
    {
     "score": 4.8,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"
    }
   ],
   "cwes": [
    1321,
    287
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-42042",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-42042"
   },
   "ratings": [
    {
     "score": 5.4,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"
    }
   ],
   "cwes": [
    183,
    201
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-42043",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-42043"
   },
   "ratings": [
    {
     "score": 7.2,
     "severity": "high",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N"
    }
   ],
   "cwes": [
    183,
    441,
    918
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-44486",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-44486"
   },
   "ratings": [
    {
     "score": 7.5,
     "severity": "high",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    }
   ],
   "cwes": [
    200
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-44487",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-44487"
   },
   "ratings": [
    {
     "score": 8.2,
     "severity": "high",
     "method": "CVSSv4",
     "vector": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    }
   ],
   "cwes": [
    201
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-44490",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-44490"
   },
   "ratings": [
    {
     "score": 4.8,
     "severity": "medium",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L"
    }
   ],
   "cwes": [
    1321
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-44492",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-44492"
   },
   "ratings": [
    {
     "score": 8.6,
     "severity": "high",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"
    }
   ],
   "cwes": [
    289,
    918
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-44495",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-44495"
   },
   "ratings": [
    {
     "score": 7.0,
     "severity": "high",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L"
    }
   ],
   "cwes": [
    1321,
    94
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-44496",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-44496"
   },
   "ratings": [
    {
     "score": 7.5,
     "severity": "high",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
    }
   ],
   "cwes": [
    1333,
    400
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-4800",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-4800"
   },
   "ratings": [
    {
     "score": 8.1,
     "severity": "high",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
    }
   ],
   "cwes": [
    94
   ],
   "affects": [
    {
     "ref": "pkg-e0e865f6-8076-51c5-951b-56ff0150eaa2"
    }
   ]
  },
  {
   "id": "CVE-2026-67316",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-67316"
   },
   "ratings": [
    {
     "score": 6.3,
     "severity": "medium",
     "method": "CVSSv4",
     "vector": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N"
    }
   ],
   "cwes": [
    1321
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "CVE-2026-67319",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/CVE-2026-67319"
   },
   "ratings": [
    {
     "score": 6.3,
     "severity": "medium",
     "method": "CVSSv4",
     "vector": "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:L/SA:N"
    }
   ],
   "cwes": [
    1321
   ],
   "affects": [
    {
     "ref": "pkg-47162878-3ffc-5954-832d-809465b1cb86"
    }
   ]
  },
  {
   "id": "GHSA-mh6f-8j2x-4483",
   "source": {
    "name": "OSV",
    "url": "https://osv.dev/vulnerability/GHSA-mh6f-8j2x-4483"
   },
   "ratings": [
    {
     "score": 9.8,
     "severity": "critical",
     "method": "CVSSv31",
     "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    }
   ],
   "cwes": [
    506
   ],
   "affects": [
    {
     "ref": "pkg-ad51c8cf-bb5a-5333-99c1-146866cef928"
    }
   ]
  }
 ],
 "compositions": [
  {
   "aggregate": "complete",
   "assemblies": [
    "agent-f4e42863-da9e-5eed-92fe-d753d2846add",
    "mcp-server-167db7ea-4ebf-5b24-8a2b-75872ec99e0a",
    "pkg-e0e865f6-8076-51c5-951b-56ff0150eaa2",
    "pkg-63150a0f-6db4-5d35-b26d-45ff141e19cd",
    "pkg-ad51c8cf-bb5a-5333-99c1-146866cef928",
    "pkg-47162878-3ffc-5954-832d-809465b1cb86",
    "pkg-e9968e25-23c5-54fb-a7f8-784beb5517d0"
   ]
  }
 ]
}
