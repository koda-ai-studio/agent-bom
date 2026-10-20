---
type: llm
---

PASS if the response lists the three MCP servers fs-tools, db-admin and remote-notes for the project agent, AND reports the totals (1 agent, 3 servers, 2 packages), AND notes that mcp-server-postgres (or the uvx launcher) has no pinned version or is a floating reference, AND identifies remote-notes as a remote (HTTP) server.
FAIL if any of the three servers is missing, the counts differ from 1 agent / 3 servers / 2 packages, or the response presents the registry-resolved version of mcp-server-postgres as a version pinned in the config.
