### Changed
- `agent-bom proxy --url` now speaks MCP Streamable HTTP to the endpoint it is given, instead of posting to `/tools/list`, `/tools/call` and `/message` under it. It keeps the `Mcp-Session-Id` the server issues on `initialize`, accepts JSON or SSE answers, and rejects a response over 2 MiB, an SSE event over 1 MiB, more than 256 events or no answer within 60 seconds with a JSON-RPC error instead of relaying it. Servers that still need the older endpoints keep working with `--compat-endpoints` (#5953).

### Upgrade notes
- Point `proxy --url` at the server's MCP endpoint (often `/mcp`). To keep the previous behavior against a server that only serves `/tools/list`, `/tools/call` and `/message`, add `--compat-endpoints`.
