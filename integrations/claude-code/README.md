# agent-bom for Claude Code

A Claude Code plugin that runs the agent-bom MCP server locally (stdio, read-only)
and adds three skills.

```text
/plugin marketplace add koda-ai-studio/agent-bom
/plugin install agent-bom@agent-bom
```

| Skill | What it does |
|---|---|
| `/agent-bom:scan` | Discover the MCP clients on this machine and scan their servers and packages, or scan an image, SBOM or repository. |
| `/agent-bom:check <package>[@version] [ecosystem]` | Vet a package or MCP server before adding it: CVEs, KEV, typosquats, fixed version. |
| `/agent-bom:fix` | Ordered remediation plan: which upgrades clear the most risk, and what has no fix yet. |

The server starts with `uvx --from agent-bom==<release> agent-bom mcp server`, so it
needs [uv](https://docs.astral.sh/uv/) and fetches the published release from PyPI.
It uses the default `scan` profile (eight tools); see
[MCP profiles](../../docs/MCP_SERVER.md) for graph, cloud, runtime and audit work.
No API key or account is needed for local scanning.

To try a local checkout: `claude --plugin-dir integrations/claude-code`, and
`claude plugin validate integrations/claude-code --strict` before publishing changes.
