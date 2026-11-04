# Smithery retirement and direct MCP setup

Smithery shut down its proxy, accounts, API, CLI, and connection management on
**October 31, 2026**. Its remaining public directory is curated and uses direct
vendor URLs. See the [provider retirement notice](https://www.smithery.ai/future).
Agent-Bom no longer publishes to the retired Smithery API. Monitoring records
this surface as **retired**, never as verified fresh.

For a local MCP client, install Agent-Bom and configure its stdio command:

```bash
pip install 'agent-bom[mcp-server]'
agent-bom mcp server
```

The client receives the default scan-profile tools. Connect the client to the
stdio process, then call `check` on a package before installing it. See the
[MCP tools reference](../reference/mcp-tools.md) for arguments.

For the hosted OAuth service, use the direct endpoint
`https://agent-bom-mcp.up.railway.app/mcp` with an authorized client. Authentication
is required; the former `run.tools` and `server.smithery.ai` proxy URLs are retired.
For a customer-controlled deployment, follow the [deployment guide](../deployment/overview.md).

## Historical manifest compatibility

`integrations/smithery.yaml` is retained for existing configuration readers.
The mapping below describes that legacy contract; it is not a supported
Smithery publishing or provisioning path.

## Why two naming conventions exist

agent-bom standardises on `AGENT_BOM_*` snake-case environment variables across CLI,
API, Helm values, Docker Compose, and the runtime MCP server. Smithery's
`configSchema` follows the [JSON Schema](https://json-schema.org/) draft convention
used by the Smithery SDK and hosted UI, which expects camelCase property names. As a
result, the public Smithery integration manifest at `integrations/smithery.yaml`
declares config fields in camelCase, while the agent-bom code path that consumes them
expects snake-case env vars.

This is not a drift bug — it is the documented translation boundary between two
ecosystems. Smithery's runner is responsible for promoting session config values into
the process environment before invoking `agent_bom.mcp_server.create_smithery_server`.

## Mapping table

The current `integrations/smithery.yaml` schema declares two optional config fields.
The Smithery runner promotes each camelCase key into the corresponding env var before
the agent-bom MCP server starts.

| Smithery `configSchema` field | Type   | Promoted env var            | Read by                                    | Effect                                                                              |
| ----------------------------- | ------ | --------------------------- | ------------------------------------------ | ----------------------------------------------------------------------------------- |
| `nvdApiKey`                   | string | `NVD_API_KEY`               | `agent_bom.enrichment` (NVD CVSS lookup)    | Lifts NVD enrichment rate limit from 5 requests / 30s to 50 requests / 30s.         |
| `clickhouseUrl`               | string | `AGENT_BOM_CLICKHOUSE_URL`  | `agent_bom.cloud.clickhouse` and CLI flags  | Enables ClickHouse-backed vulnerability trend storage and posture history.          |

`NVD_API_KEY` is intentionally not prefixed with `AGENT_BOM_` because the value is the
NVD-issued key itself, not an agent-bom configuration knob — multiple tools in the
same workspace may share it.

## Self-hosting outside Smithery

When operating the MCP server yourself (Railway, Docker, Helm, Glama, OpenClaw, or any
non-Smithery runtime), set the snake-case environment variables directly. The
camelCase `configSchema` is purely a Smithery surface and has no effect on a
self-hosted deployment.

```bash
# Railway, Docker, Helm, etc.
export NVD_API_KEY="<your-nvd-api-key>"
export AGENT_BOM_CLICKHOUSE_URL="https://<host>:8443"
agent-bom serve mcp
```

```yaml
# Helm values.yaml
controlPlane:
  api:
    env:
      - name: NVD_API_KEY
        valueFrom:
          secretKeyRef:
            name: agent-bom-control-plane-auth
            key: nvd-api-key
      - name: AGENT_BOM_CLICKHOUSE_URL
        value: "http://clickhouse:8123"
```

## Related references

- [Smithery integration manifest](https://github.com/koda-ai-studio/agent-bom/blob/main/integrations/smithery.yaml)
- [agent-bom configuration reference](../reference/configuration.md)
- [MCP tools reference](../reference/mcp-tools.md)
- [Hosted MCP overview](../deployment/overview.md)
