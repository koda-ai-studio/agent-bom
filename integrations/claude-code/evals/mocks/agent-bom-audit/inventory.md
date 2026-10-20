---
type: fixed
---

{
 "schema_version": "1.0",
 "canonical_id_schema_version": "3",
 "agents": [
  {
   "name": "project:proj",
   "agent_type": "custom",
   "config_path": "/home/dev/proj/.mcp.json",
   "servers": [
    {
     "name": "fs-tools",
     "command": "npx",
     "transport": "stdio",
     "packages": [
      {
       "name": "@modelcontextprotocol/server-filesystem",
       "version": "2.0.0",
       "ecosystem": "npm",
       "pinned": false,
       "pinned_version": null,
       "observed_version": "2.0.0",
       "version_source": "tool_cache"
      }
     ]
    },
    {
     "name": "db-admin",
     "command": "uvx",
     "transport": "stdio",
     "packages": [
      {
       "name": "mcp-server-postgres",
       "version": "latest",
       "ecosystem": "pypi",
       "pinned": false,
       "pinned_version": null,
       "observed_version": null,
       "version_source": "registry_latest"
      }
     ]
    },
    {
     "name": "remote-notes",
     "command": "",
     "transport": "streamable-http",
     "packages": []
    }
   ]
  }
 ],
 "total_agents": 1,
 "ai_bom_entities": {
  "schema_version": "1.0",
  "summary": {
   "agents": 1,
   "servers": 3,
   "tools": 0,
   "resources": 0,
   "prompts": 0,
   "packages": 2,
   "relationships": 5
  },
  "agents": [
   {
    "id": "7a10cb45-4a31-519f-8689-468ed94bdbe4",
    "canonical_id": "7a10cb45-4a31-519f-8689-468ed94bdbe4",
    "previous_canonical_ids": [
     "02efdcb3-0443-5e03-9b4e-8e4b23a5822c",
     "d709ae8f-24e2-56a4-b633-5f64a2d9235f"
    ],
    "previous_graph_ids": [
     "agent:cfg-11c7be284939:project:proj",
     "agent:project:proj"
    ],
    "name": "project:proj",
    "agent_type": "custom",
    "type": "custom",
    "status": "configured",
    "discovered_at": "2026-10-20T14:18:40.935722Z",
    "last_seen": "2026-10-20T14:18:40.935722Z",
    "config_path": "<path:.mcp.json>",
    "discovery_provenance": {
     "source_type": "local_discovery",
     "observed_via": [
      "local_discovery"
     ],
     "source": "project-config",
     "confidence": "medium"
    },
    "server_ids": [
     "7b50a1a4-8890-52cf-afe4-bdb0f530419d",
     "c5649059-672c-5d7b-a631-2dba288185b3",
     "1da1cabd-bb28-581e-9e1c-48466031c8b1"
    ]
   }
  ],
  "servers": [
   {
    "id": "1da1cabd-bb28-581e-9e1c-48466031c8b1",
    "canonical_id": "2d2c55b2-4cd1-580f-ad31-65cfb9def6a6",
    "name": "remote-notes",
    "surface": "mcp-server",
    "fingerprint": "fe2c9d66-4605-5ee2-a92c-9b3b55f94b8d",
    "auth_mode": "network-no-auth-observed",
    "transport": "streamable-http",
    "command": "",
    "url": "http://notes.example.com/mcp",
    "tool_ids": [],
    "resource_ids": [],
    "prompt_ids": [],
    "package_ids": [],
    "discovery_provenance": {
     "source_type": "local_discovery",
     "observed_via": [
      "local_discovery"
     ],
     "source": "project-config",
     "confidence": "medium"
    }
   },
   {
    "id": "7b50a1a4-8890-52cf-afe4-bdb0f530419d",
    "canonical_id": "c800f74f-1a8c-5e34-97f3-625ac189f645",
    "name": "fs-tools",
    "surface": "mcp-server",
    "fingerprint": "5e45f2d7-9264-5c86-92ec-b9f46fe22f9e",
    "auth_mode": "local-stdio",
    "transport": "stdio",
    "command": "npx",
    "url": null,
    "tool_ids": [],
    "resource_ids": [],
    "prompt_ids": [],
    "package_ids": [
     "c87cc58b-742d-5f6e-b53a-d15201a9b108"
    ],
    "discovery_provenance": {
     "source_type": "local_discovery",
     "observed_via": [
      "local_discovery"
     ],
     "source": "project-config",
     "confidence": "medium"
    }
   },
   {
    "id": "c5649059-672c-5d7b-a631-2dba288185b3",
    "canonical_id": "fb261cbf-2862-57ee-b67f-14f777843e4f",
    "name": "db-admin",
    "surface": "mcp-server",
    "fingerprint": "ac55b235-73ef-5bef-8d35-586de055c11d",
    "auth_mode": "env-credentials",
    "transport": "stdio",
    "command": "uvx",
    "url": null,
    "tool_ids": [],
    "resource_ids": [],
    "prompt_ids": [],
    "package_ids": [
     "a12cb812-0b46-556a-b0d4-85d79e5d40f8"
    ],
    "discovery_provenance": {
     "source_type": "local_discovery",
     "observed_via": [
      "local_discovery"
     ],
     "source": "project-config",
     "confidence": "medium"
    }
   }
  ],
  "tools": [],
  "resources": [],
  "prompts": [],
  "packages": [
   {
    "id": "a12cb812-0b46-556a-b0d4-85d79e5d40f8",
    "canonical_id": "a12cb812-0b46-556a-b0d4-85d79e5d40f8",
    "name": "mcp-server-postgres",
    "version": "latest",
    "ecosystem": "pypi",
    "purl": "pkg:pypi/mcp-server-postgres@latest",
    "source_package": null,
    "distro_name": null,
    "distro_version": null,
    "floating_reference": true,
    "floating_reference_reason": "uvx command omitted an explicit package version",
    "is_malicious": false,
    "malicious_reason": null,
    "version_provenance": {
     "declared_name": "mcp-server-postgres",
     "declared_version": "latest",
     "version_source": "registry_latest",
     "confidence": "low",
     "legacy_version_source": "registry_fallback",
     "resolved_from_registry": true,
     "floating_reference": true,
     "pinned": false,
     "source_precedence": 20
    },
    "discovery_provenance": {
     "source_type": "registry_fallback",
     "observed_via": [
      "local_discovery",
      "registry_fallback"
     ],
     "source": "bundled_registry",
     "confidence": "medium",
     "version_source": "registry_fallback",
     "resolved_from_registry": true,
     "version_provenance": {
      "declared_name": "mcp-server-postgres",
      "declared_version": "latest",
      "version_source": "registry_latest",
      "confidence": "low",
      "legacy_version_source": "registry_fallback",
      "resolved_from_registry": true,
      "floating_reference": true,
      "pinned": false,
      "source_precedence": 20
     }
    },
    "occurrence_count": 0,
    "occurrences": [],
    "vulnerability_count": 0
   },
   {
    "id": "c87cc58b-742d-5f6e-b53a-d15201a9b108",
    "canonical_id": "c87cc58b-742d-5f6e-b53a-d15201a9b108",
    "name": "@modelcontextprotocol/server-filesystem",
    "version": "2.0.0",
    "ecosystem": "npm",
    "purl": "pkg:npm/%40modelcontextprotocol/server-filesystem@2.0.0",
    "source_package": null,
    "distro_name": null,
    "distro_version": null,
    "floating_reference": true,
    "floating_reference_reason": "npx command omitted an explicit package version",
    "is_malicious": false,
    "malicious_reason": null,
    "version_provenance": {
     "declared_name": "@modelcontextprotocol/server-filesystem",
     "declared_version": "latest",
     "resolved_version": "2.0.0",
     "version_source": "tool_cache",
     "confidence": "high",
     "version_resolved_at": "2026-10-20T14:18:40.940987+00:00",
     "resolved_from_registry": false,
     "floating_reference": true,
     "pinned": false,
     "source_precedence": 50,
     "evidence": [
      {
       "type": "tool_cache",
       "path": "<path:package.json>",
       "parser": "npx"
      }
     ]
    },
    "discovery_provenance": {
     "source_type": "local_discovery",
     "observed_via": [
      "local_discovery"
     ],
     "source": "project-config",
     "confidence": "medium",
     "version_source": "tool_cache",
     "resolved_from_registry": false,
     "version_provenance": {
      "declared_name": "@modelcontextprotocol/server-filesystem",
      "declared_version": "latest",
      "resolved_version": "2.0.0",
      "version_source": "tool_cache",
      "confidence": "high",
      "version_resolved_at": "2026-10-20T14:18:40.940987+00:00",
      "resolved_from_registry": false,
      "floating_reference": true,
      "pinned": false,
      "source_precedence": 50,
      "evidence": [
       {
        "type": "tool_cache",
        "path": "<path:package.json>",
        "parser": "npx"
       }
      ]
     }
    },
    "occurrence_count": 0,
    "occurrences": [],
    "vulnerability_count": 0
   }
  ],
  "relationships": [
   {
    "from": "7a10cb45-4a31-519f-8689-468ed94bdbe4",
    "to": "7b50a1a4-8890-52cf-afe4-bdb0f530419d",
    "type": "uses"
   },
   {
    "from": "7b50a1a4-8890-52cf-afe4-bdb0f530419d",
    "to": "c87cc58b-742d-5f6e-b53a-d15201a9b108",
    "type": "depends_on"
   },
   {
    "from": "7a10cb45-4a31-519f-8689-468ed94bdbe4",
    "to": "c5649059-672c-5d7b-a631-2dba288185b3",
    "type": "uses"
   },
   {
    "from": "c5649059-672c-5d7b-a631-2dba288185b3",
    "to": "a12cb812-0b46-556a-b0d4-85d79e5d40f8",
    "type": "depends_on"
   },
   {
    "from": "7a10cb45-4a31-519f-8689-468ed94bdbe4",
    "to": "1da1cabd-bb28-581e-9e1c-48466031c8b1",
    "type": "uses"
   }
  ]
 }
}
