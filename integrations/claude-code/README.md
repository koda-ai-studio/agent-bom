# agent-bom for Claude Code

A Claude Code plugin that runs the agent-bom MCP server locally (stdio) and adds
six skills. Every skill is read-only by default: anything that would change a file
is proposed first and only applied after you confirm.

```text
/plugin marketplace add koda-ai-studio/agent-bom
/plugin install agent-bom@agent-bom
```

| Skill | What it does |
|---|---|
| `/agent-bom:scan` | Discover the MCP clients on this machine and scan their servers and packages, or scan an image, SBOM or repository. |
| `/agent-bom:check <package>[@version] [ecosystem]` | Vet a package or MCP server before adding it: CVEs, KEV, typosquats, fixed version. |
| `/agent-bom:fix` | Ordered remediation plan: which upgrades clear the most risk, and what has no fix yet. |
| `/agent-bom:inventory [dir]` | AI estate inventory: agents, MCP servers, tools, packages and how they connect. No CVE lookups. |
| `/agent-bom:audit-mcp [dir]` | Passive audit of MCP configs: credentials in config, unpinned launchers, unauthenticated or non-TLS remote servers, risky packages. |
| `/agent-bom:audit-skills [path]` | Audit skills and instruction files (SKILL.md, CLAUDE.md, AGENTS.md, rules files) for prompt injection, exfiltration, remote code execution and broad tool grants. |

## Examples

- `/agent-bom:inventory` -> "1 agent, 3 servers, 0 tools, 2 packages", a table per
  client, and call-outs such as `db-admin` launching `uvx mcp-server-postgres`
  with no pinned version, or `remote-notes` served over plain HTTP.
- `/agent-bom:audit-mcp ~/work/api` -> findings per server: `GITHUB_TOKEN` set in
  `.mcp.json` (name and file only, never the value), `npx -y` without a version,
  "no authentication observed" and "non-TLS transport" on a remote server, plus
  any critical CVE with its fixed version. It says when only configuration, not
  live tool descriptors, was inspected.
- `/agent-bom:audit-skills .claude/skills` -> a verdict per file, for example
  `deploy-helper: malicious - critical credential exfiltration (line 4)`, the
  lower-confidence findings it also saw, and the skill's `allowed-tools` grants.
  Instructions inside audited files are quoted as evidence, never followed.
- `/agent-bom:check left-pad@1.3.0 npm` -> safe to add, upgrade first, or do not
  install, with CVEs, KEV status and the fixed version.

The plugin starts two local servers from the same pinned release, each with a
bounded tool profile: `agent-bom` (the default `scan` profile: scan, check,
remediate and five more) and `agent-bom-audit` (`--profile audit`: inventory,
skill and descriptor audits, prompt checks, compliance, policy). See
[MCP profiles](../../docs/MCP_SERVER.md). Both start with
`uvx --from agent-bom==<release> agent-bom mcp server`, so they need
[uv](https://docs.astral.sh/uv/) and fetch the published release from PyPI. No API
key or account is needed. `inventory` and the skill audit tools join the audit
profile in the release after 0.109.0; on 0.109.0 those two skills fall back to
`scan` and `prompt_scan` and say so.

## What it runs, reads and sends

- **Runs** two local processes, `uvx --from agent-bom==<release> agent-bom mcp server`
  with and without `--profile audit`. uv downloads that exact release and its
  dependencies from PyPI on first use. No hooks, no background jobs, and nothing
  runs outside a skill or tool call. The skills never launch or connect to the MCP
  servers they audit: `audit-mcp` always calls `tool_risk_assessment` with
  `live: false`.
- **Reads** MCP client configuration files on this machine (Claude Code, Claude
  Desktop, Cursor and other supported clients) to find agents, servers and the
  packages they launch, skill and instruction files under a path you name, plus
  any image, SBOM or repository you name. Credential
  values found in configs are redacted in results; only their names and locations
  are reported.
- **Sends** package names and versions, never file contents or credentials, to
  public vulnerability and package sources. `inventory` and `audit-skills` make no
  network calls; `audit-mcp`, `scan`, `check` and `fix` use:
  - `api.osv.dev`: vulnerability lookups
  - `api.github.com`: GitHub security advisories
  - `pypi.org` and `registry.npmjs.org`: package metadata and typosquat checks
- **Never** writes to agent configs, installs packages, or sends telemetry. Live
  credential validation and cloud connectors are off unless you enable them
  through the CLI.
- **Stores** a local cache under `~/.agent-bom`.

To try a local checkout: `claude --plugin-dir integrations/claude-code`, and
`claude plugin validate integrations/claude-code --strict` before publishing changes.
`claude plugin eval integrations/claude-code` runs the eval suite in `evals/` against
recorded tool output (no real server starts), including safety cases where a
config or skill carries injected instructions.
