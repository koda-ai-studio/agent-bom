### CI
- The daily surface-freshness monitor now checks every published image family — the API image on GHCR and Docker Hub plus the MCP stdio (`agent-bom-mcp`) and HTTP (`agent-bom-sse`) images — so a stale MCP image is reported instead of hidden behind a fresh API image.
