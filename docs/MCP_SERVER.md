# MCP Server — Connect agent-bom to AI Assistants

agent-bom starts with 8 focused MCP tools. Select a task profile for graph, cloud, runtime or audit work;
`--profile full` explicitly exposes the complete compatibility catalog of 94 MCP tools. Clients that negotiate the
MCP SDK's legacy `2025-11-25` handshake can connect over stdio or
Streamable HTTP. The `2026-07-28` protocol also supports stateless requests,
`server/discover`, per-request capabilities, required HTTP headers, and private
cache hints. SDK 2 retains legacy negotiation; legacy HTTP+SSE remains deprecated.

Executable wire tests cover modern discovery/inventory, legacy handshakes,
header mismatch rejection, and authenticated remote introspection. This is not
an official conformance certification. Optional tasks and DPoP are not advertised.
See [MCP scanning and gateway compatibility](MCP_COMPATIBILITY.md) for configuration,
limits, and the machine-readable evidence matrix.

See also:

- [Client configuration](#major-clients)
- [Claude Desktop / Claude Code guide](CLAUDE_INTEGRATION.md)
- [Cortex CoCo / Cortex Code guide](CORTEX_CODE.md)
- [Codex CLI guide](CODEX_CLI.md)
- [Runtime Monitoring](RUNTIME_REFERENCE.md)

## Quick Start

```bash
pip install agent-bom
agent-bom mcp server
```

Configure your client below to launch this stdio process. Tool responses carry
scan results and evidence; use the investigation workflows to save and inspect
the returned artifact. Select a task profile before granting broader tools.

For task-oriented prompts and a credential-free example with saved evidence,
start with [affected agents, exposure evidence and scan comparison](#investigation-workflows).

## Major clients

These clients are first-class today because `agent-bom` can both expose MCP
tools to them and discover their local MCP configuration during scans.

| Client | Primary config path(s) | Recommended setup | Notes |
|--------|-------------------------|-------------------|-------|
| Claude Desktop | macOS: `~/Library/Application Support/Claude/claude_desktop_config.json` Linux: `~/.config/Claude/claude_desktop_config.json` Windows: `~/AppData/Roaming/Claude/claude_desktop_config.json` | `agent-bom mcp server` or `uvx agent-bom mcp server` | Good fit for MCP server mode. Proxy wrapping works for JSON-configured stdio servers. |
| Claude Code | `~/.claude/settings.json`, `~/.claude.json` | `claude mcp add agent-bom -- uvx agent-bom mcp server` | `agent-bom` also discovers project-level MCP servers from `~/.claude.json`. |
| Cortex CoCo / Cortex Code | `~/.snowflake/cortex/mcp.json` plus `settings.json`, `permissions.json`, `hooks.json` in the same directory | `uvx agent-bom mcp server` in `mcp.json` | Best fit when you want both MCP discovery and Cortex-specific permission/hook audits. |
| Cursor | macOS: `~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` Linux: `~/.config/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` Windows: `~/AppData/Roaming/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` | `agent-bom mcp server` | Cursor uses standard JSON MCP config, so `proxy-configure` can wrap eligible stdio servers. |
| Windsurf | macOS: `~/.windsurf/mcp.json`, `~/Library/Application Support/Windsurf/User/globalStorage/windsurf.mcp/mcp.json` Linux: `~/.windsurf/mcp.json` Windows: `~/.windsurf/mcp.json` | `agent-bom mcp server` | Same `mcpServers` JSON shape as Claude/Cursor. |
| Codex CLI | `~/.codex/config.toml` on macOS, Linux, and Windows | `agent-bom mcp server` via `[mcp_servers.agent-bom]` | Codex uses TOML, not JSON. `proxy-configure` does not rewrite TOML configs; wrap manually when needed. |
| Gemini CLI | `~/.gemini/settings.json` on macOS, Linux, and Windows | `agent-bom mcp server` | Uses standard JSON MCP config. |

For agent-facing investigation, the most useful tools to start with are
`exposure_paths` for ranked graph context and `should_i_deploy` for
allow/warn/block deploy guidance. Both return evidence; neither mutates code,
cloud resources, or third-party systems.

## Snowflake and skills

There are two Snowflake paths, and they solve different problems:

- Use Cortex CoCo / Cortex Code MCP config when you want an assistant inside
  that workflow to call `agent-bom` tools.
- Use `agent-bom agents --snowflake` or the Snowflake Native App docs when you
  want account inventory, Cortex, Snowpark, notebook, Streamlit, package, and
  query-history evidence collected from Snowflake itself.

For instruction and skill files, use `agent-bom skills scan` and
`agent-bom skills verify`. Those commands audit `CLAUDE.md`, `AGENTS.md`,
`.cursorrules`, and supported `skills/*` surfaces independently of the MCP host.

## Config snippets

### JSON clients

Claude Desktop, Cortex CoCo, Cursor, Windsurf, and Gemini CLI all use JSON MCP config shapes that look like:

```json
{
  "mcpServers": {
    "agent-bom": {
      "command": "uvx",
      "args": ["agent-bom", "mcp", "server"]
    }
  }
}
```

If `agent-bom` is already installed locally, you can replace `uvx` with:

```json
{
  "mcpServers": {
    "agent-bom": {
      "command": "agent-bom",
      "args": ["mcp", "server"]
    }
  }
}
```

### Codex CLI

Codex CLI uses TOML:

```toml
[mcp_servers.agent-bom]
command = "uvx"
args = ["agent-bom", "mcp", "server"]
```

For a manual proxy-wrapped third-party server in Codex:

```toml
[mcp_servers.filesystem]
command = "agent-bom"
args = ["proxy", "--no-isolate", "--log", "~/.agent-bom/logs/filesystem.jsonl", "--", "npx", "@modelcontextprotocol/server-filesystem", "/workspace"]
```

### SSE Transport (Remote / Multi-Client)

```bash
agent-bom mcp server --transport sse --host 0.0.0.0 --port 8000 --bearer-token "$AGENT_BOM_MCP_BEARER_TOKEN"
```

Connect any SSE-capable MCP client to `https://your-server/sse`.
For non-loopback SSE or Streamable HTTP binds, `agent-bom` now fails closed unless you set
`--bearer-token` / `AGENT_BOM_MCP_BEARER_TOKEN` or explicitly pass
`--allow-insecure-no-auth`. Keep TLS at your proxy or ingress for remote deployments.
The regular bearer token is read-only. To enable audited Shield or identity
write tools, configure a distinct `AGENT_BOM_MCP_OPERATOR_TOKEN`; startup rejects
identical read and operator credential values. Write calls still need
`operator_role=admin`, the matching `operator_scopes` value, and an audit reason,
but those arguments no longer authorize the write by themselves.
Every configured HTTP/SSE token requires an absolute timezone-aware ISO-8601
expiry: `AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT` for read access and
`AGENT_BOM_MCP_OPERATOR_TOKEN_EXPIRES_AT` when an operator token is configured.
Startup rejects missing, malformed, expired, or more-than-one-hour deadlines;
requests are rejected at expiry before any read or write scope is returned.
Provision a fresh token and its deadline through your own credential-management
workflow; Agent-Bom does not issue or automatically rotate these credentials.
Supply both through the deployment's secure environment mechanism. The one-hour
bound limits remaining acceptance, not proof of when the token was created.
Local stdio does not use these HTTP credentials or require a token expiry.

By default, MCP HTTP authentication uses operator-provisioned bearer credentials.
For an external OAuth issuer with renewable credentials, see [Remote MCP OAuth](MCP_OAUTH.md). The MCP
server does not expose an embedded OAuth authorization server or accept tokens
previously minted by that embedded issuer. Embedded dynamic registration and
OAuth token issuance remain unavailable: PKCE alone does not establish permission
to read the server's private evidence. Configure the existing bearer credential
in the client through its supported secure credential mechanism. API SSO/OIDC
and gateway authentication are separate surfaces.

The public server card advertises `authentication.schemes: ["bearer"]` for
protected HTTP/SSE deployments. This describes the configured transport;
it does not establish OAuth compatibility for marketplace clients.

Rotate the token and its absolute deadline together, then restart the MCP
process to load the replacement. Environment changes do not hot-reload into a
running verifier. Preserve the same deadline across ordinary restarts; never
regenerate a deadline at boot for an unchanged token. A restart cannot extend an
expired configured credential. There is no embedded OAuth refresh flow. Existing
remote deployments must provision bounded credentials before upgrading; registry
clients must receive the replacement through their secure credential settings.


### Enterprise Control-Plane Contract

Local MCP server mode stays intentionally low-friction for workstation scans.
Enterprise MCP Gateway deployments should consume the same control-plane
contract as the API and UI: tenant identity, policy, audit, secret-manager
posture, and lifecycle state come from the control plane. Gateway credentials
belong in Helm/Kubernetes secrets or the operator secret manager, not in client
configs, and gateway audit events should flow back through the tenant-scoped
control-plane audit path.

### Docker

```bash
docker run -it --rm \
  -v ~/.config:/home/abom/.config:ro \
  -v ~/.agent-bom:/home/abom/.agent-bom \
  agentbom/agent-bom:latest mcp server
```

## Runtime proxy

Use the proxy when you want to inspect or enforce on MCP traffic between a client and a third-party server:

```bash
agent-bom proxy --no-isolate -- npx @modelcontextprotocol/server-filesystem /workspace
```

This keeps the real server behind `agent-bom` and enables runtime detectors for tool drift, credential leakage, injection patterns, sequence risk, and related policy decisions.

For JSON-configured clients like Claude Desktop or Cortex CoCo, use:

```bash
agent-bom proxy-configure --log-dir ~/.agent-bom/logs --detect-credentials
```

Add `--apply` to write the wrapped config back to compatible JSON MCP config files.

For IT-owned rollout across managed laptops, use:

```bash
agent-bom proxy-bootstrap \
  --bundle-dir ./endpoint-bundle \
  --control-plane-url https://agent-bom.example.com \
  --push-url https://agent-bom.example.com/v1/fleet/sync
```

`proxy-configure` is best for JSON MCP clients such as Claude Desktop, Cursor, Windsurf, and Cortex CoCo. TOML-based clients like Codex CLI need manual proxy wrapping.

For prerequisite checks and bounded identity paths, use [`consequence_assessment`](GRAPH_CONSEQUENCES.md) in the graph profile. It is experimental and read-only; missing session or exploitability evidence stays explicit.

For scoped historical permission receipts, use [`compromise_assessment`](MCP_SERVER.md#assess-an-assumed-compromise) in the graph profile.

## Tool Categories (94 tools)

These categories describe `--profile full`, not the default startup catalog.
The [profile guide](#choose-a-profile-for-other-work) lists the smaller task surfaces.

| Category | Tools | What They Do |
|----------|-------|-------------|
| **Scan** | `scan`, `code_scan`, `vector_db_scan`, `gpu_infra_scan`, `ai_inventory_scan` | Discover agents; execute Semgrep SAST with typed findings/clean/skipped/failed status; scan packages, vector stores, GPU infra, and AI usage |
| **Check** | `check`, `verify`, `marketplace_check`, `license_compliance_scan` | Pre-install CVE gate, integrity verification, marketplace trust, and license policy |
| **Blast Radius** | `blast_radius`, `exposure_paths`, `compromise_assessment`, `consequence_assessment`, `graph_correlate`, `graph_correlation_status`, `should_i_deploy`, `graph_reach`, `graph_diff`, `findings_query`, `finding_detail` | Map package → vulnerability finding → MCP server (tools + credential env names) → connected agents; correlate exact snapshot receipts; return ranked ExposurePath JSON and allow/warn/block deploy guidance for headless agents |
| **Registry** | `registry_lookup`, `inventory`, `where`, `fleet_scan` | Query the MCP registry, inspect discovery paths, and summarize fleet inventories |
| **Compliance** | `compliance`, `cis_benchmark`, `aisvs_benchmark` | Inspect framework applicability and evaluated controls; run CIS and AISVS benchmarks. MITRE technique associations are unscored |
| **Policy** | `policy_check`, `remediate` | Evaluate policies and generate guided remediation plans |
| **Inventory** | `inventory` | List agents/servers without CVE scanning |
| **Trust** | `marketplace_check`, `runtime_correlate`, `tool_risk_assessment` | Score package trust, correlate runtime usage, and assess live tool capability risk |
| **Skills** | `skill_scan`, `skill_verify`, `skill_trust` | Instruction-file trust, provenance, and tool-poisoning detection |
| **Graph / Runtime** | `exposure_paths`, `should_i_deploy`, `context_graph`, `graph_export`, `runtime_correlate`, `runtime_production_index`, `runtime_blueprints`, `runtime_blueprint_drift`, `proxy_status`, `proxy_alerts`, `gateway_status`, `shield_status`, `shield_start`, `shield_unblock`, `shield_break_glass`, `firewall_check`, `audit_query`, `audit_integrity`, `tool_risk_assessment` | Return ranked investigation paths, deploy decisions, graph exports, runtime posture, blueprints, drift checks, cursor-paged gateway activity, operator self-posture, audit-chain evidence, read-only firewall decisions, and audited Shield actions |
| **AI supply chain** | `dataset_card_scan`, `training_pipeline_scan`, `browser_extension_scan`, `model_provenance_scan`, `prompt_scan`, `model_file_scan`, `ingest_external_scan`, `runtime_evidence_ingest` | Scan AI artifacts, prompts, model files, and browser extensions; import tool-agnostic SARIF/SBOM/scanner evidence without executing its producer; merge CWPP runtime signals |

<details>
<summary>Complete current catalog (94 tools)</summary>

`scan`, `check`, `intel_lookup`, `intel_match`, `intel_sources`,
`intel_daily_brief`, `youcom_search`, `blast_radius`, `exposure_paths`, `compromise_assessment`, `consequence_assessment`, `graph_correlate`,
`graph_correlation_status`, `should_i_deploy`, `graph_reach`, `graph_diff`, `findings_query`, `finding_detail`,
`policy_check`, `registry_lookup`, `generate_sbom`, `compliance`, `remediate`,
`skill_scan`, `skill_verify`, `skill_trust`, `verify`, `inventory_summary`,
`inventory_list`, `inventory_asset`, `where`, `tool_risk_assessment`,
`inventory`, `diff`, `marketplace_check`, `code_scan`, `context_graph`,
`graph_export`, `analytics_query`, `cis_benchmark`, `kspm_cluster_posture`,
`fleet_scan`, `runtime_correlate`, `runtime_production_index`,
`runtime_blueprints`, `runtime_blueprint_drift`, `cost_report`, `anomaly_scan`,
`drift_incidents`, `proxy_status`, `proxy_alerts`, `gateway_status`,
`shield_status`, `shield_start`, `shield_unblock`, `shield_break_glass`,
`identity_issue`, `identity_rotate`, `identity_revoke`, `identity_grant_jit`,
`identity_revoke_jit`, `firewall_check`, `audit_query`, `audit_integrity`,
`vector_db_scan`, `aisvs_benchmark`, `gpu_infra_scan`, `registry_sweep_scan`,
`dataset_card_scan`, `training_pipeline_scan`, `browser_extension_scan`,
`model_provenance_scan`, `prompt_scan`, `model_file_scan`, `ai_inventory_scan`,
`license_compliance_scan`, `ingest_external_scan`, `runtime_evidence_ingest`,
`cost_forecast`, `cost_allocation`, `credential_expiry`, `nhi_discover`,
`cloud_inventory`, `access_review`, `create_ticket`, `sync_ticket_status`,
`findings_triage`, `list_exceptions`, `request_exception`,
`approve_exception`, `risk_campaign_workflow`, `cloud_side_scan`,
`endpoint_inventory`, `endpoint_sync`.

</details>

## Agent-facing decision tools

Two graph-native tools are the primary MCP entry points for headless security
agents:

- `exposure_paths` returns ranked `ExposurePath` JSON from the graph store so
  an agent can explain what is exposed, why it matters, which entities prove
  it, and what fix path is recommended.
- `should_i_deploy` returns allow/warn/block deploy guidance based on matched
  `ExposurePath` risk and caller-supplied thresholds.

`exposure_paths` ranks exactly as the dashboard attack-path queue and
`GET /v1/graph/attack-paths` do: `ranking.order` is evidence tier, KEV,
severity, evidence confidence, composite risk, then credential count, and every
path carries `rank`, `evidenceTier`, `isKev`, `severity`, `evidenceConfidence`
and `rankingFactors` (the same values with plain-language reasons; REST
attack paths carry them as `ranking_factors`). `composite_risk` is 0-100 and
keeps severity, KEV and exposure order; incomplete hop evidence is reported in
`reachability` / `reachabilityBasis` and `evidenceConfidence` (`verified`,
`likely`, `structural`, `unassessed`, `disproven`), never by lowering the
score. A path with no scored finding reports `severity: "unknown"`
(`severityScored: false`) and ranks after scored findings. Totals, server-side filters
(`min_severity`, `kev`, `has_credential`, `source_type`, `target_id`,
`finding_id`, `credential_id`, `node_id`, `min_risk`) and cursor pages match
that route. The default `view="summary"` keeps the default answer under 16 KB;
`view="full"` adds hops, relationships, nodes and edges. `should_i_deploy`
matches the candidate against every ranked path of the snapshot and reports
`searchedPaths` of `total`.

Four more read-only tools answer follow-up questions from the same evidence:

- `graph_reach(node_id, direction="in"|"out")` pages what can reach a node (the
  `GET /v1/graph/impact` walk) or what it reaches, with walk completeness.
- `graph_diff(from_scan_id, to_scan_id)` is `GET /v1/graph/diff`: by default a
  summary (counts per change kind by entity type and relationship, new critical
  findings, new credential reach, removed controls, new attack paths) of the
  latest two snapshots; `view="detail"` pages change rows with filters and a cursor.
  `view="estate"` is `GET /v1/graph/changes`: each current source (target scope)
  against its own previous completed snapshot, with first observations listed
  separately and never counted as additions.
- `findings_query` is `GET /v1/findings` (filters, sort, cursor, totals) with a
  compact row projection; `risk_score` is 0-10 and `effective_reach_score` 0-100.
- `finding_detail(finding_id)` returns the finding, the graph paths that carry
  it, who reaches it, its `exploit_story` (the `GET /v1/graph/exploit-story`
  payload: what the package puts at risk and how, from recorded fields) and its
  triage/VEX state.

`blast_radius` takes credentials, tools and reachability from those graph
paths. When the graph cannot be read they are `null` with a `graph.status`
reason, never an empty list. Its `holders` block is the `GET /v1/graph/impact`
walk for `vuln:<CVE>` (same pinned snapshot, alias resolution and reverse walk:
`affected_by_type`, `affected_nodes`, `completeness`) for the whole advisory,
while each row's `affected_servers` / `affected_agents` are its own
occurrence's, exactly as `/v1/findings` returns them. Rows are the open
occurrences only: `count` matches the open `/v1/findings` rows for the CVE and
`suppressed_count` names the occurrences an approved exception suppresses.
`risk_score` is 0-10 and `effective_reach_score` 0-100 (`risk_scale`). Each row carries `reachability`, derived by the same
verdict function as `/v1/findings` (`likely` for a recorded graph path,
`confirmed` only with function-level or runtime evidence). `compliance` returns the tenant's persisted
`/v1/compliance/summary` when completed scans exist (`source:
"persisted_tenant_compliance"`); pass `framework` and `control` to page the
driving finding ids. It scans local MCP configurations only with
`source="local_scan"` or when no persisted evidence exists, and labels that
result `source: "local_scan"`. `context_graph` reads one agent page (`offset`, `limit` up to 100) of the
tenant's current estate graph: the same agents `GET /v1/graph?entity_types=agent`
pages, with their servers, packages (transitive `depends_on` to the same holder
depth component paths use; a deeper chain marks the page incomplete), tools,
credential names and the advisories those packages hold
(`source: "current_estate_graph"`). It reports `pagination`,
`estate_coverage` (`agents_in_view` against `current_estate_agents`, the
`/v1/posture/counts` total) and a `completeness` that is `truncated` unless the
page holds the whole estate; the lateral-path status moves to
`path_completeness`. With `scan_id`, or when the estate graph holds no agents,
it reads the persisted scan reports (`source: "persisted_snapshot"`). It
discovers this MCP server host's agent configurations only with `live=true` or
a `config_path` (`source: "live_discovery"`); a tenant without a snapshot gets
a not-found error rather than a silent host scan.

Both tools are read-only decision aids. They do not modify repositories,
create tickets, deploy workloads, or mutate cloud resources. Use proxy,
gateway, Shield, or API audit evidence when a decision depends on selected
live runtime traffic rather than static reachability.

For a persisted scan, call `exposure_paths(scan_id="<scan-id>")` and inspect
`paths`, `count_metadata`, and `completeness`. Snapshots without precomputed
path rows use the same topology derivation as the dashboard. This fallback
loads at most the configured graph investigation node budget; a truncated
result reports a lower-bound total and cannot establish that no paths exist.
Static candidates retain unknown reachability. `should_i_deploy` matches the
candidate exactly against path identifiers (package name, `name@version`, purl
with or without version, CVE/finding id, node id or label); substrings do not
match. It returns `block` when a matched path reaches a CISA KEV finding from an
agent with credential exposure (unless reachability is `unlikely`) or when
`maxRisk` reaches `block_risk`; `warn` rather than `allow` when reachability is
unverified or the path read is incomplete; and `not_found` (with
`evidenceStatus: "not_evaluated"`, `maxRisk: null`) when no path names the
candidate. Inspect the linked findings and runtime evidence before deployment.

Continue a larger result with `exposure_paths(cursor="<pagination.next_cursor>")`,
keeping the same `min_risk`. Stop when `pagination.next_cursor` is null. The
cursor pins the snapshot; changing the tenant, snapshot, or risk filter requires
a new query. REST uses the same `cursor` query parameter on
`GET /v1/graph/exposure-paths`. A response may contain fewer than `limit` paths
to keep complete path objects within the transport budget. The dashboard's
**Next paths** and **Previous paths** controls navigate this same evidence.
The CLI accepts `agent-bom graph-paths exposure --cursor <cursor> --format json`;
the Python client accepts `exposure_paths(cursor=...)`, and the TypeScript
client accepts `exposurePaths({ cursor, scanId })`.

Exposure references use the same projection as REST graph investigations:
`role` is the canonical display role (for example, `finding` or `server`),
while `entityType` retains the precise graph type (`vulnerability`,
`misconfiguration`, `container`, and so on). Clients that previously inspected
an MCP reference's `role` for the graph type should use `entityType` instead.
Unassessed nodes omit `riskScore`; `risk_assessment` describes the unknown.
`findings` includes asset-scoped occurrence IDs when available, retaining
advisory aliases for compatibility. Relationships follow hop order and select
the recorded relationship for each hop; bidirectional edges retain their
stored endpoints and do not become directed evidence.

Inspect `evidenceDimensions` for reachability, exploitability, impact,
actionability, and completeness. Relationship `direction` and `traversable`
describe the recorded connection, not proof of exploitation. The dashboard
preserves those qualifications, displays unknown assessments explicitly, and
uses dashed lines where traversal is not established.

## Security Model

- **Read-mostly**: scanner, graph, audit, and posture tools are read-only.
  The 21 write-annotated tools cover scan-history diff, Shield, identity,
  external ingest, CWPP runtime-evidence ingest, access review, finding
  triage and exception approval, snapshot correlation, remediation campaigns,
  endpoint collection, and ticket workflows. One process-execution tool can launch a discovered
  local MCP server only with explicit authorization. These tools require an
  authenticated MCP operator token plus admin role, their specific write
  scope (`cloud:write`, `findings:write`, `identity:write`, `scan:write`, `shield:write`,
  `connectors:write`, or `ticketing:write`), and an audit reason; stdio cannot invoke them.
- Credentials belong in the operator secret environment. Remote calls authenticate through the configured transport; do not put secrets in prompts or tool arguments.
- Scans and explicit integrations use their documented egress and storage boundaries; see [permissions](PERMISSIONS.md). MCP server mode does not itself deploy endpoint agents.

## Resources

The server exposes six MCP resources:

- `registry://servers` — Browse the full 1185-entry server security metadata registry
- `policy://template` — Default security policy template
- `metrics://tools` — Bounded MCP tool execution metrics
- `schema://inventory-v1` — Canonical pushed-inventory schema contract
- `bestpractices://mcp-hardening` — NSA-informed MCP hardening control mapping
- `compliance://framework-controls` — Framework coverage and evidence mapping

## Workflow prompts

Use the task-profile table and investigation workflows below. Profiles select a tool surface; they do not grant permissions.



### Runtime ingestion credentials

`runtime_evidence_ingest` sends metadata to the configured control-plane API.
It accepts no credential arguments. Provision a source-bound, expiring API key
or OIDC bearer credential in the server environment; the API verifies its exact
source scope, tenant and lifetime (at most one hour). MCP write authorization
remains independently required. See [runtime producer authentication](CLOUD_CONNECT.md#runtime-producer-authentication)
for source registration, rotation and migration from shared-secret producers.

## External OAuth for remote clients

For renewable read-only access using an operator-owned issuer, see
[Remote MCP OAuth](MCP_OAUTH.md). This opt-in mode leaves API/UI SSO and SAML
unchanged and requires explicitly approved identities.

## Investigation workflows

Start with three questions: **Which agents are affected? What supports this
exposure path? What changed after the fix?** The recipes below use bounded
reads of retained snapshots and save the evidence behind each answer.

## Try all three with fictional data

With Git and `uv` installed, start from a source checkout:

```bash
git clone https://github.com/koda-ai-studio/agent-bom.git
cd agent-bom
OUT=$(mktemp -d /tmp/agent-bom-investigation.XXXXXX)
uv run --extra api --extra mcp-server python scripts/prove_first_workflows.py --output-dir "$OUT"
```

In an existing checkout, run only the last two commands from its root.

The command creates one fictional agent configuration, parses and scans a
Pillow dependency against the bundled advisory fixture, then changes that input
from 9.0.0 to 10.0.1 and scans again. It calls the real MCP server over stdio;
neither package is installed, no configured tool runs, and no deployment changes.
It requires no cloud credentials. Existing evidence is never overwritten.

Open the printed `workflow-proof.json` path. It records every tool call,
arguments, saved response, server version and local timing. The
`first_useful_result_seconds` measurement includes fixture creation, server
startup and the first affected-agent response; it excludes installation and
human review. It is a local receipt, not a performance benchmark. No usage
telemetry is sent.

### Installation and client setup for every recipe

For an installed MCP server, use:

```bash
python -m pip install 'agent-bom[api,mcp-server]'
```

Configure your [MCP client](#major-clients) to run `agent-bom` with arguments
`["mcp", "server", "--profile", "graph"]`. For the example, set the server's
environment to `AGENT_BOM_GRAPH_DB=/absolute/path/from-OUT/graph.db` and
`AGENT_BOM_MCP_TENANT_ID=first-workflows-example`. The standalone command is:

```bash
AGENT_BOM_GRAPH_DB="$OUT/graph.db" \
AGENT_BOM_MCP_TENANT_ID=first-workflows-example \
agent-bom mcp server --profile graph
```

Use the absolute output path in client configuration; clients do not inherit
the shell's `OUT` variable automatically. Reconnect after changing profiles or
environment. The graph profile reads saved evidence; it does not discover or
scan the estate merely because a client connects. Server-bound tenant identity
controls reads; a prompt or `tenant_id` argument cannot grant another tenant's
access. For real evidence, use your configured graph store and authorized
tenant, then obtain the exact snapshot and component IDs from inventory.

To check a separately installed version against this source-generated fixture,
pass its Python executable to the proof command with
`--server-python /absolute/path/to/installed-environment/bin/python`.

## 1. Find agents affected by a vulnerable component

**Example prompt:**

> In snapshot `first-before`, find agents connected to `vuln:CVE-2023-4863`.
> Use `graph_reach` with direction `in`, entity_types `["agent"]`, max_depth
> `4`, and limit `10`. Report unique agent IDs, snapshot generation, traversal
> completeness and collection limits. Do not equate recorded reach with execution.

**Expected result:** one fictional agent, `example-image-assistant`, in
`affected-agents.json`. Its scoped ID comes from the returned `items`; do not
construct an ID from the label. `total` counts matching unique nodes, while
`affected_count` includes other entity types visited by the walk. Neither is a
count of attacks, CVE occurrences or exposure paths.

**Next action:** inspect `pkg:pypi:pillow@9.0.0` with `inventory_asset`, the same
`scan_id`, and `limit=10`. The saved `before-component.json` contains the
component's recorded relationships and source evidence. Continue using a
returned cursor and snapshot generation if the relationship page is incomplete.
Unknown collection coverage remains unknown even when the bounded walk completes.

## 2. Explain an exposure path and its evidence

**Example prompt:**

> In `first-before`, call `exposure_paths` filtered to finding_id
> `CVE-2023-4863`, limit `1`, view `summary`. Then request view `full` with the
> same filter. Explain this path's direction and each relationship's receipt.
> Separate configured relationships, observed execution and exploitability;
> identify missing evidence before recommending an action.

**Expected result:** `exposure-summary.json` contains a ranked candidate;
`exposure-evidence.json` includes the selected path, scoped endpoint IDs, hop
metadata, relationships and exported edges. Join a relationship's `id` to the
matching edge's `evidence` and source snapshot. Preserve `reachabilityBasis`,
`hopEvidence`, `evidenceDimensions`, collection coverage and completeness in
the explanation. Counts and rankings apply to the selected snapshot and filter;
one returned path is not the entire estate. Use the returned cursor with
unchanged filters for another page.

This fixture records configuration and an advisory match. It does not prove
tool invocation, credential use, successful data access or exploitation.
Framework/technique mappings provide context, not attack evidence.

**Next action:** use the affected component's advisory and fixed-version
evidence to plan an upgrade, then verify the same collection scope. If a
dashboard is connected to this graph store and tenant, open
`/security-graph?scan=first-before&finding=CVE-2023-4863` on that authenticated
control plane to investigate the same snapshot. The local proof does not start
or authenticate a dashboard.

## 3. Compare scans after a remediation change

**Example prompt:**

> Compare `first-before` and `first-after` with `graph_diff`, view `summary`.
> Drill into view `detail`, kind `node`, entity_type `vulnerability`, change
> `removed`, limit `10`. Inspect `pkg:pypi:pillow@10.0.1` with `inventory_asset`
> in `first-after`. Explain changed findings, retained agents and evidence gaps.
> Distinguish a changed-input scan from a verified deployed fix.

**Expected result:** `comparison.json` records one removed advisory node and
replacement package identities; `removed-findings.json` gives the bounded
detail, and `after-component.json` shows the new component's relationships.
The fictional agent remains. The same tenant, agent configuration and scanner
fixture were used for both snapshots; the dependency input hash and version
differ in `workflow-proof.json`.
The matching `before-requirements.txt` and `after-requirements.txt` inputs are
retained alongside the fictional configuration and graph exports.

**Next action:** in a real environment, deploy the separately approved change,
repeat the same collection scope, check coverage and retain independent change
and runtime receipts. Missing records in an incomplete scan are not verified
fixes. This example changes dependency input only; it cannot close a deployed
remediation. For an installed Python dependency update, use
[Verify an installed package update](operations/PACKAGE_REMEDIATION_VERIFICATION.md).
For reviewed relationship comparisons, use
[Measure an investigation and rescan](operations/INVESTIGATION_MEASUREMENT.md).

To explain retained scan results to another reviewer, create a
[shareable impact brief](operations/IMPACT_BRIEF.md) with
`agent-bom report impact after.json --before before.json -o impact-change.html`.
This local command reads saved scan JSON. It does not run as an MCP tool or
turn missing findings into verified fixes.

## Choose a profile for other work

Start with `agent-bom mcp server`. The default `scan` profile exposes eight tools:
`scan`, `check`, `intel_lookup`, `exposure_paths`, `compliance`, `remediate`,
`generate_sbom` and `policy_check`. Ask for `quick-audit` to get findings, inspect
exposure and identify a next action; use `remediation-plan` to draft a fix without
changing files. A package check is not proof that a deployment is safe.

Choose one profile for the task. In an MCP client configuration, append
`"--profile", "graph"` to the `args` array to select graph work, for example.
Reconnect the client after changing profiles. Separate named client entries can
expose different profiles; connect only the entries needed for the task.

| Profile | Tools | Use it for | Workflow prompts |
|---|---:|---|---|
| `scan` (default) | 8 | Package/project scan, exposure and fix planning | quick-audit, pre-install-check, remediation-plan |
| `graph` | 15 | Inventory rollup, asset drill-down and scoped correlation | Use inventory_summary → inventory_list → inventory_asset, then inspect paths |
| `cloud` | 6 | Inventory, connection scope and CIS posture | cloud-connection-review |
| `runtime` | 7 | Gateway policy, alerts and incident evidence | incident-triage, gateway-fleet-live-demo |
| `audit` | 9 | Scan, agent inventory, descriptor and permission checks, skill/instruction and prompt inspection, framework mapping, policy and audit integrity | compliance-report |

For component inspection, call `inventory_asset` with the asset's exact graph
ID and the `scan_id` returned by inventory. The artifact contains attributes,
evidence source names, endpoint nodes, and at most 24 recorded relationships by
default (maximum 100). Continue with the returned `next_cursor`, `scan_id`, and
`snapshot_generation`; restart inspection if that snapshot has been replaced.
The REST equivalent is `GET /v1/inventory/assets/{asset_id}` with the same query
parameters. Both surfaces enforce tenant scope.

Completeness describes the relationship page, not source collection coverage.
`sources` contains incoming node IDs; `evidence_sources` contains collector
names. `impact_status` is `not_evaluated` and the compatibility `impact` object
is empty; use graph investigation for impact analysis. The inventory drawer
shows recorded parent/child and other relationships with links to their exact
endpoints in the selected snapshot.

In the dashboard, select an inventory component and open **Findings**. The
component view reads its exact recorded relationships in the retained snapshot,
instead of searching other assets by name. Load additional relationship pages
to inspect more linked finding records, then export the loaded evidence and
snapshot receipts as JSON. Direct associations are separate from findings
elsewhere in the component chain, exploitability, and collection coverage.

Open **Compliance** from the component or its findings to inspect control tags
and directly linked benchmark evidence in the same snapshot. Tags are mappings,
not evaluated controls. Newly projected failed benchmark checks retain explicit
`evaluation_status=fail` and `evaluation_scope` (`resource` or `account`) in
node attributes, available through REST, MCP inventory detail and graph exports.
Older records without those fields remain not evaluated in this view. Account
results are not inherited by child resources. Download the loaded control
records and snapshot receipts as JSON; collection coverage and freshness remain
unassessed. Missing scope never opens tenant-wide compliance implicitly.

Run the [connected component example](../examples/connected-bom/README.md)
to reproduce parsing, changed-input rescanning, retained snapshots, scoped
findings/control evidence, and REST/MCP parity without cloud credentials.

Read the `profiles://catalog` resource to discover profile names, tool names and
startup commands without loading every input schema. Selection is fixed for the
server instance; it does not silently expand during a session. Excluded tools
cannot be invoked. Profiles are not permissions: graph writes still require the
existing authenticated role, tenant scope and audit reason.

Existing clients that require the complete catalog can explicitly use
`agent-bom mcp server --profile full`. It retains all 94 tools. The previous
28-tool `--profile guided` option remains available for compatibility with all
eight workflow prompts. Neither is the recommended first-run configuration.
Third-party tool plugins remain separately opt-in and are exposed only by `full`.

The complete workflow catalog is below. Only compatible prompts appear in each
focused profile's `prompts/list` and server card.

| Workflow prompt | Primary user | Tool sequence | Evidence produced |
|---|---|---|---|
| `quick-audit` | Developer or security reviewer | `scan` -> `exposure_paths` -> `compliance` | Findings, blast radius, framework mapping |
| `pre-install-check` | Developer / CI assistant | `check` -> `intel_lookup` as needed | Package findings and evidence-qualified install recommendation |
| `compliance-report` | Security / audit | `scan` -> `compliance` -> `audit_integrity` | Framework summary, evidence IDs, audit status |
| `fleet-audit` | Endpoint / platform owner | `fleet_scan` -> `context_graph` -> `policy_check` | Agent inventory, graph-ready findings |
| `incident-triage` | SOC / appsec | `intel_lookup` -> `exposure_paths` -> `runtime_correlate` | KEV/EPSS/RCE context, affected agents/tools |
| `remediation-plan` | App owner | `remediate` -> `generate_sbom` -> `policy_check` | Fix plan, validation commands, rollback notes |
| `cloud-connection-review` | Cloud/security admin | connection evidence -> `cis_benchmark` -> `graph_export` | Read-only scope review, CIS posture, graph handoff |
| `gateway-fleet-live-demo` | Design partner / buyer | `gateway_status` -> `proxy_alerts` -> `fleet_scan` -> `firewall_check` | Gateway posture, live policy path, fleet action plan |

## Guardrails

- Treat user-supplied package names, finding IDs, provider names, and file paths
  as untrusted data.
- Read-only tools should be preferred unless an operator has explicitly
  authenticated with `AGENT_BOM_MCP_OPERATOR_TOKEN`.
- Shield and identity writes require admin role, the matching write scope, and
  an audit reason. Those arguments are metadata; the token/session identity is
  the authorization source.
- Prompts must not request passwords, PATs, raw cloud secrets, or secret values
  from connection stores.
- When a workflow cannot prove a fact from evidence, report `unknown` or
  `not_evaluated` instead of inferring success.

## Gateway/Fleet Live Demo

Use the demo when showing the platform loop:

1. Confirm the gateway is healthy and policies are loaded.
2. Show fleet state and discovered agents.
3. Pull recent gateway feed KPIs and runtime production posture.
4. Open the top exposure paths and explain why one path is fix-first.
5. Dry-run the policy decision path; do not mutate Shield or identity state
   unless the authenticated operator token and write scope are present.
6. Export or attach the evidence IDs used in the story.

For a read-only command-line walkthrough, use:

```bash
ABOM_URL=https://agent-bom.example.com \
ABOM_API_TOKEN=... \
scripts/demo/gateway-fleet-live-demo.sh
```

The script uses only read endpoints and exits non-zero if the API is not
reachable or authentication fails.

## Assess an assumed compromise

Select a persisted graph snapshot and node from inventory. In the graph MCP
profile with the `api` extra installed, call `compromise_assessment` with `scan_id`, `root_node_id`, and
`assume_control: true`. The server-bound tenant controls access; a caller's
`tenant_id` hint cannot change that boundary.

The equivalent CLI command produces an exportable artifact:

```bash
# Set AGENT_BOM_API_URL and AGENT_BOM_API_TOKEN through your secret manager.
agent-bom graph-paths compromise --scan-id SCAN_ID --node NODE_ID \
  --assume-control --format json > compromise-assessment.json
```

The API is `POST /v1/graph/compromise` with the same request fields. It requires
an authenticated principal with `graph:read` (viewer role or higher). The
browser graph entity drawer exposes **Assess assumed compromise**, requires the
explicit assumption, and can export the same assessment JSON. Finding roots
also require a linked `affected_node_id` and `assume_exploitation: true`.

Inspect each returned action, resource, permission receipt, timestamp, source
edge, binding, and reason code. These are historical authorization observations:
`current_access` remains `not_evaluated`, execution remains `not_established`,
and collection coverage remains `unknown`. An empty result does not prove
safety. This contract assesses direct outgoing relationships only; it does not
propagate compromise across multiple hops or perform exploitation.

The response includes `snapshot_generation`. Pass that revision on subsequent
requests to reject replacement evidence. Replacement returns HTTP 409; missing
snapshots or roots return 404; invalid assumptions return 422. Reads exceeding
the storage traversal budget return 413 instead of assessing partial evidence.
The traversal selects at most 1,024 nodes and 4,096 edges around the roots, with
a cooperative deadline; this is not a hard database query timeout. Assessment
output examines up to `max_relationships` (default 128, maximum 512), reports
truncation, and uses `max_evidence_age_seconds` (default 3,600, maximum 86,400).
Generation-pinned reads require SQLite or Postgres; unsupported backends return
501. No database migration or write is performed by this endpoint.

Next: inspect missing or stale receipts in the source system, collect a new
snapshot when appropriate, and rerun with that snapshot's identity. Retain the
original export when comparing assessments.

For recorded action/resource consequences with assumptions, blockers and gaps, use
`consequence_assessment` in the graph profile. See [graph consequences](GRAPH_CONSEQUENCES.md)
for the matching CLI command and evidence boundaries. Assessments are read-only.

## Which mode to use

| Goal | Use | Why |
|------|-----|-----|
| Ask an assistant to run `agent-bom` tools directly | `agent-bom mcp server` | Makes discovery, scan, blast-radius, compliance, and trust tools available in-chat |
| Inspect or block live MCP traffic to another server | `agent-bom proxy` | Adds inline JSON-RPC inspection, audit logs, and policy enforcement |
| Auto-wrap JSON-based stdio MCP configs | `agent-bom proxy-configure` | Rewrites eligible client configs so they point at the proxy wrapper |
| Generate managed endpoint rollout artifacts | `agent-bom proxy-bootstrap` | Writes shell/PowerShell bootstrap scripts plus fleet-sync artifacts for IT-owned rollout |

## Runtime proxy notes

- `agent-bom proxy` is best when the client talks to a third-party stdio server and you want runtime inspection.
- `agent-bom proxy-configure --apply` targets JSON MCP configs and can now
  stamp control-plane policy/audit settings into the wrapped proxy command.
  Generated configs include `--no-isolate` unless `--sandbox-image` is supplied,
  so process containment is never implied without an operator-provided
  Docker/Podman runtime image.
- `agent-bom proxy-bootstrap --bundle-dir ./endpoint-bundle --control-plane-url https://agent-bom.example.com --push-url https://agent-bom.example.com/v1/fleet/sync` writes managed rollout artifacts for macOS/Linux and Windows without hand-editing JSON on every machine.
- the bundle now also includes Jamf, Intune, and Kandji wrappers plus repo-shipped `.pkg` / `.msi` build scripts for IT-owned rollout
- stdio transports have no native HTTP header channel. When a client or upstream includes W3C trace context in JSON-RPC `_meta.traceparent`, `_meta.tracestate`, or `_meta.baggage`, the proxy preserves those fields and rehydrates them onto the paired response when the upstream does not echo them back.
- TOML clients like Codex CLI need manual proxy wrapping today.
- SSE / HTTP clients can use `agent-bom mcp server --transport sse --bearer-token "$AGENT_BOM_MCP_BEARER_TOKEN"` or `--transport streamable-http`.
- HTTP/SSE credentials require `AGENT_BOM_MCP_BEARER_TOKEN_EXPIRES_AT`, a timezone-aware absolute deadline within one hour. An optional operator credential requires its own `AGENT_BOM_MCP_OPERATOR_TOKEN_EXPIRES_AT`. Rotate token and deadline together; ordinary restarts do not renew them. Stdio does not use these credentials.
- Non-loopback remote transports fail closed unless you configure `--bearer-token` / `AGENT_BOM_MCP_BEARER_TOKEN` or explicitly pass `--allow-insecure-no-auth`.
- Keep TLS at your ingress or reverse proxy for remote deployments.

### VS Code configuration paths

VS Code supports `~/Library/Application Support/Code/User/mcp.json` on macOS
and project configuration at `.vscode/mcp.json`. See the client's MCP settings
for the platform-specific user path.
