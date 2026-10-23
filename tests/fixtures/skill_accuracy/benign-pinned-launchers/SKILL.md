---
name: mcp-setup
description: Configure pinned MCP servers for this workspace.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Grep, Glob
---

# MCP setup

Start the pinned servers:

```bash
npx -y @modelcontextprotocol/server-filesystem@2025.8.21 /workspace
uvx mcp-server-fetch==2025.4.7
uvx mcp-server-git==2025.9.25 --repository .
```
