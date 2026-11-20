### CI
- The daily surface-freshness monitor now checks every published image family — the API image on GHCR and Docker Hub plus the MCP stdio (`agent-bom-mcp`) and HTTP (`agent-bom-sse`) images — so a stale MCP image is reported instead of hidden behind a fresh API image.
- The reusable workflow (`agent-bom-reusable.yml`) and the GitLab, Azure Pipelines and Bitbucket examples pin the published release (0.115.4) instead of 0.110.0. The release pin sweep now covers them, and a commit-pinned Action ref must be the commit its `# vX.Y.Z` tag names; the post-release pin update rewrites both together.

### Fixed
- The release self-SBOM (`agent-bom-sbom.cdx.json`) declares agent-bom as its root `metadata.component` with name, version and `pkg:pypi` purl, and the release fails if it does not; the documented `jq` inspection no longer prints `null`.

### Security
- Container images move to CPython releases that include the `ssl` compromised-intermediate denylist (CVE-2026-115557, critical) and the `tarfile` extraction-filter fix (CVE-2026-87910): 3.12.16 for the MCP stdio, MCP HTTP, runtime, collector, public lookup and Glama images, 3.11.18 for the Snowflake images, and 3.14.10 for the CLI/API image, which no longer needs its hand-applied `tarfile` overlay. The MCP publish gate failed on this finding, so `agent-bom-mcp` and `agent-bom-sse` were not published for 0.115.4.

### Docs
- The privacy notice, terms and OpenAI plugin README state that the public lookup service (`agent-bom-lookup.up.railway.app`) is not yet deployed instead of describing it as running.
