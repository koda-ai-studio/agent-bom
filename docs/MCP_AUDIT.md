# Audit MCP security

Inspect a project's MCP configuration before connecting to its servers:

```bash
agent-bom mcp audit . --format json --output mcp-audit.json
```

The report contains descriptor injection checks, tool-input schema risk,
capability scope checks, authentication configuration findings and coverage.
It does not invoke tools, activate policies or test authorization bypass.
Default mode does not connect to or launch discovered servers. It uses the
configuration and descriptors available through project discovery.

Inspect `enforcement.coverage` before interpreting an empty finding list.
A configuration without tool descriptors has no tool-content assessment.
Unknown agent types require an explicit expected-capability profile before
permission scope can be assessed. Capabilities are inferred from descriptors;
they do not prove operating-system permissions or successful execution.

```bash
agent-bom mcp audit . --expected-capability read --format sarif --output mcp-audit.sarif
```

Repeat `--expected-capability` for the capabilities the application needs.
The explicit operator profile overrides the agent-type heuristic. Findings
retain expected, observed and excess capabilities. JSON uses the standard
scan finding stream; SARIF retains coverage in run properties under
`mcp_audit_coverage`. Review the flagged server and descriptor, restrict its
configuration or implementation, then repeat the same scoped audit.

## Live descriptors

```bash
agent-bom mcp audit . --live --format json --output mcp-live-audit.json
```

Live mode connects to configured HTTP/SSE servers. To launch project-configured
stdio commands as well, explicitly add `--allow-command-execution`. Review
those commands first. Live discovery may perform bounded linked MCP Apps
metadata reads; it never calls `tools/call`. Existing endpoint-bound scan-auth
configuration applies; discovery does not grant access to new credentials.

Each tool/resource/prompt listing retains its own outcome. One successful
listing does not erase another listing's failure. Configured and collected
live descriptor observations are inspected without replacing the original
inventory. Changed descriptors can contribute separate observations.

| Coverage | Meaning |
|---|---|
| `configuration_only` | Only the discovered configuration descriptors were inspected |
| `inspected` | Live listing completed; the collected descriptors were inspected |
| `failed` / `unsupported` / `unknown` | Live coverage is incomplete; retained descriptors may still produce findings |
| `skipped` | No matching live result, execution not enabled, or security policy blocked the connection |
| `resource_content: not_inspected` | No general resource-body injection assessment |
| `rendered_prompts: not_inspected` | Rendered prompt messages were not assessed |
| `authorization_bypass: not_assessed` | Authentication findings are configuration observations, not verified anonymous access or bypasses |

Exit `1` means a high/critical finding. Exit `2` means no discovered MCP servers,
an audit error, or incomplete requested live listing without a high/critical
finding. Exit `0` means no high/critical finding within the inspected scope;
it is not a claim that every attack surface is safe. No runtime policy is
changed, including when discovery fails.

## Through MCP

The existing `tool_risk_assessment` tool returns an `audit` block and
`authentication_findings` alongside its live inventory and risk scores.
Use the audit catalog to access it alongside `inventory`, `skill_scan`,
`skill_trust` and `prompt_scan`:

```bash
agent-bom mcp server --profile audit
```

Call with `{"config_path":"/path/to/project","live":false}` for a passive audit.
An optional `expected_capabilities` list defines the operator profile; an empty
list means no capabilities are expected. Live mode defaults to true for
compatibility and still requires `allow_command_execution: true` and the
existing authenticated operator authorization before launching stdio servers.
Catalog selection is not an authorization grant.

Regular `agent-bom scan`, API scans and the MCP `scan` tool also include passive
descriptor/permission findings and coverage when MCP servers are discovered.
API/MCP evaluation errors fail the scan rather than silently returning a clean
audit. Existing authentication and tenant boundaries remain in force. `--enforce` adds its existing
CVE, drift and capability-combination checks; it is not required for passive
injection and permission findings.

## Inspect and remediate in the dashboard

Open a completed scan to view MCP descriptor coverage and findings. Counts are
unique finding occurrences; server coverage is shown per agent configuration.
Use **Inspect asset** to open the recorded node in that scan, then traverse
its connections. Hop counts describe graph edges, not successful exploitation.
Unlinked observations remain visible as findings without an invented asset link.

The permission finding can show a **Proposed tool restriction** using its
recorded affected tools. This is a draft for a dedicated proxy bound to the
identified server. Review required application behavior before adopting it;
the dashboard never activates the policy. After changing a descriptor, server
configuration or reviewed policy, repeat the audit and compare the evidence.
