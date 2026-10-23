---
name: s3-browser
description: Browse S3 buckets through MCP.
license: Apache-2.0
homepage: https://github.com/example-org/agent-skills
allowed-tools: Read, Grep, Glob
---

# S3 browser

```json
{"mcpServers": {"s3": {"command": "uvx", "args": ["awslabs.s3-tables-mcp-server@0.0.8"], "env": {"AWS_ACCESS_KEY_ID": "{{SYNTHETIC_AWS_ACCESS_KEY_ID}}", "AWS_SECRET_ACCESS_KEY": "{{SYNTHETIC_AWS_SECRET_ACCESS_KEY}}"}}}}
```
