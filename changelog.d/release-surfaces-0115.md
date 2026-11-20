### CI
- The daily surface-freshness monitor now checks every published image family — the API image on GHCR and Docker Hub plus the MCP stdio (`agent-bom-mcp`) and HTTP (`agent-bom-sse`) images — so a stale MCP image is reported instead of hidden behind a fresh API image.

### Security
- Container images move to CPython releases that include the `ssl` compromised-intermediate denylist (CVE-2026-115557, critical) and the `tarfile` extraction-filter fix (CVE-2026-87910): 3.12.16 for the MCP stdio, MCP HTTP, runtime, collector, public lookup and Glama images, 3.11.18 for the Snowflake images, and 3.14.10 for the CLI/API image, which no longer needs its hand-applied `tarfile` overlay. The MCP publish gate failed on this finding, so `agent-bom-mcp` and `agent-bom-sse` were not published for 0.115.4.
