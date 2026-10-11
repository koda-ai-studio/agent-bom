# MCP scanning and gateway compatibility

Agent-bom uses MCP SDK 2 for `2026-07-28` stateless requests and legacy
`2025-11-25` negotiation. The server, introspection client, proxy, and gateway
have separate responsibilities. The [compatibility matrix](../src/agent_bom/data/mcp_protocol_compatibility.json)
records executable evidence and unverified features separately; it is not an
upstream conformance certification.

## Scan an authenticated remote server

1. Run `agent-bom scan --no-scan -f json -o inventory.json` to find the server's
   `canonical_id` and endpoint. Discovery preserves header names, OAuth declarations,
   and configured sandbox restrictions without retaining credentials. Configured
   restrictions are evidence of intent, not proof that a client enforced them.
2. Create a private operator-owned authentication file outside the scanned project:

   ```json
   {
     "SERVER_CANONICAL_ID": {
       "url": "https://mcp.example.com/mcp",
       "header_env": {"Authorization": "MCP_SCAN_AUTHORIZATION"}
     }
   }
   ```

3. Set `MCP_SCAN_AUTHORIZATION` to the complete authorization value through your
   secret manager or shell environment, then run:

   ```bash
   AGENT_BOM_MCP_SCAN_AUTH_FILE=/private/path/mcp-scan-auth.json \
     agent-bom scan --introspect -f json -o inventory.json
   ```

The credential mapping must match both the server identity and exact endpoint.
Discovered client configuration cannot authorize reading a credential. Missing
credentials produce an incomplete introspection result, not an empty verified
inventory. Redirect handling stays within the SDK's origin boundary. No browser
login, token minting, or dynamic registration is started by a scan.

Introspection negotiates the protocol and lists tools, resources and prompts,
bounded to 20 pages and 5,000 entries per catalog. Failed or repeated-cursor
listings remain incomplete evidence. For
MCP Apps, it can read up to 16 linked `ui://` resources to record content hashes,
CSP declarations and permissions. Text over 1 MiB is excluded from hashing. HTML
is never executed or stored in the report.
Resource failures remain visible as unavailable evidence. Tool annotations and
UI permission declarations are untrusted metadata, not authorization grants.

## Gateway and proxy enforcement

Use a Streamable HTTP MCP endpoint in the upstream configuration. The gateway
accepts bounded JSON or SSE tool responses and correlates the final response ID.
Malformed, oversized, truncated and mismatched responses fail closed. A transport
failure after forwarding is not proof that the upstream did not execute a tool;
clients must not blindly retry side effects.

Modern routing headers are derived from the JSON request and incoming header/body
mismatches are rejected. Tool parameter headers are derived from an authenticated,
bounded upstream catalog; catalogs are not shared across credentials or tenants.
The gateway does not forward client-supplied authorization to the upstream.

Additional `inputResponses` in multi-round-trip requests pass through the same
inline DLP inspection as tool arguments. Upstream `input_required` responses are
recorded as awaiting input. Every retry passes authorization and policy again;
opaque `requestState` is preserved and its integrity remains the upstream server's
responsibility. Proxy and gateway response scanning includes structured results,
errors and additional input requests. Enable inline scanning in enforce mode to
block detected content.

The gateway rejects `subscriptions/listen` before forwarding: persistent streams,
revocation during delivery and resumability are not yet supported. Ordinary SSE
responses are bounded and reduced to their correlated response; progress
notifications are not relayed. The stdio proxy preserves MCP messages. The remote
`proxy --url` adapter still uses compatibility endpoints (`/tools/list`,
`/tools/call`, `/message`); use the gateway for a modern Streamable HTTP endpoint.

## OAuth configuration

Existing bearer and client-credentials upstreams remain supported. Bind an OAuth
client-credentials connection to its authorization server and resource:

```yaml
upstreams:
  - name: inventory
    url: https://mcp.example.com/mcp
    auth: oauth2_client_credentials
    oauth_issuer: https://identity.example.com
    oauth_token_url: https://identity.example.com/oauth/token
    oauth_resource: https://mcp.example.com/mcp
    oauth_client_id_env: MCP_CLIENT_ID
    oauth_client_secret_env: MCP_CLIENT_SECRET
    scopes: [inventory.read]
```

When `oauth_issuer` is set, discovery must return the exact issuer and configured
token endpoint before client credentials are sent. Token caching is isolated by
tenant, issuer, resource, endpoint, client, scopes and credential rotation.
Configurations without `oauth_issuer` retain their explicitly configured token
endpoint; they do not claim authorization-server discovery validation.

The SDK supports current OAuth discovery and Client ID Metadata Documents for
interactive clients. Agent-bom's scanner uses explicitly supplied credentials and
does not implement interactive CIMD registration. The MCP server can verify an
external issuer; it does not become an embedded authorization server. Tasks and
DPoP remain optional, unadvertised capabilities.

The registry factory returns the MCP SDK server directly. The legacy Smithery
Python decorator targets SDK 1 and is no longer installed by `agent-bom[mcp-server]`.
That install extra remains compatible as an alias for the base installation.
Hosted registry registration uses the authenticated HTTP endpoint described in
[Publishing](PUBLISHING.md); no decorator-based session configuration is promised.

## Verification

- `tests/test_mcp_protocol_compatibility.py`: legacy and modern wire behavior.
- `tests/test_mcp_modernization.py`: authenticated discovery, configuration privacy,
  SSE response handling, continuation DLP and issuer mismatch rejection.
- `tests/test_gateway_relay_contract.py`: bounded relay contract.

Keep unknown or untested extension behavior explicit. A green local test is not
an upstream certification or proof of interoperability with every MCP client.

Upstream references: [protocol changes](https://modelcontextprotocol.io/specification/2026-07-28/changelog),
[SDK migration guide](https://py.sdk.modelcontextprotocol.io/migration/), and
[MCP Apps metadata](https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/2026-01-26/apps.mdx).
