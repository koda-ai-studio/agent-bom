# agent-bom for Claude Code

A Claude Code plugin that runs the agent-bom MCP server locally (stdio) and adds
ten skills. Every skill is read-only by default: anything that would change a file
is proposed first and only applied after you confirm.

```text
/plugin marketplace add koda-ai-studio/agent-bom
/plugin install agent-bom@agent-bom
```

The same folder is also a Codex plugin (`.codex-plugin/plugin.json`), with the
same skills and the same pinned local MCP servers. Add this repository as a Codex
plugin marketplace, then install agent-bom from the Plugins Directory:

```text
codex plugin marketplace add koda-ai-studio/agent-bom
```

In Codex, skills are named without the `/agent-bom:` prefix (for example `scan`).

| Skill | What it does |
|---|---|
| `/agent-bom:checkup` | Start here: one screen with a verdict, totals, and the three fixes that matter most, from the inventory, a passive config audit and a scan. |
| `/agent-bom:affected <advisory>` | Am I affected? Looks up a CVE, GHSA or OSV id and says which packages, servers and agents on this machine carry it, with the fixed version. |
| `/agent-bom:bom [target]` | Write an AI-BOM (CycloneDX or SPDX) for this machine, a project, an image, a repository, or an AWS, Azure or GCP account: agents, MCP servers, tools, models and packages, with how they connect. |
| `/agent-bom:scan` | Discover the MCP clients on this machine and scan their servers and packages, or scan an image, SBOM or repository. |
| `/agent-bom:check <package>[@version] [ecosystem]` | Vet a package or MCP server before adding it: CVEs, KEV, typosquats, fixed version. |
| `/agent-bom:fix` | Ordered remediation plan: which upgrades clear the most risk, and what has no fix yet. |
| `/agent-bom:inventory [dir]` | AI estate inventory: agents, MCP servers, tools, packages and how they connect. No CVE lookups. |
| `/agent-bom:audit-mcp [dir]` | Passive audit of MCP configs: credentials in config, unpinned launchers, unauthenticated or non-TLS remote servers, risky packages. |
| `/agent-bom:activity [days] [dir]` | Review what Claude Code and Codex actually did: MCP servers and tools used, configured servers never used, risky actions (pipe-to-shell, force pushes, writes outside the project, secret-file reads) and packages installed. Local only. |
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
- `/agent-bom:activity` -> "Last 30 days: 53 tool calls in 6 sessions; 2 high-risk
  actions, 2 unused MCP servers", the unused servers with the config file to
  remove them from (edited only after you confirm), risky actions most severe
  first with redacted evidence, and the packages agents installed.
- `/agent-bom:check left-pad@1.3.0 npm` -> safe to add, upgrade first, or do not
  install, with CVEs, KEV status and the fixed version.

The plugin starts two local servers from the same pinned release, each with a
bounded tool profile: `agent-bom` (the default `scan` profile: scan, check,
remediate and five more) and `agent-bom-audit` (`--profile audit`: inventory,
agent activity, skill and descriptor audits, prompt checks, compliance, policy). See
[MCP profiles](../../docs/MCP_SERVER.md). Both start with
`uvx --from agent-bom==<release> agent-bom mcp server`, so they need
[uv](https://docs.astral.sh/uv/) and fetch the published release from PyPI. No API
key or account is needed. `inventory` and the skill audit tools join the audit
profile in the release after 0.109.0; on 0.109.0 those two skills fall back to
`scan` and `prompt_scan` and say so. `agent_activity` joins the audit profile in
the release after 0.110.0; on earlier releases the `activity` skill says it is
not available.

## Projects outside your home directory

The MCP server only reads paths under your home directory. A project somewhere
else, such as a container mount, `/srv` or `/Volumes/<disk>`, is refused with
"Path resolves outside home directory". To allow it, set
`AGENT_BOM_MCP_WORKSPACE_ROOTS` to the extra directories, separated by `:`
(`;` on Windows). Each entry must be an absolute path. A relative path, a path
containing `..`, or a filesystem root such as `/` is ignored, so the setting
cannot open the whole disk.

The plugin's bundled servers don't offer a setting for this variable. Add your
own server entry that sets it, next to the plugin's servers:

- **Claude Code.** Run this once, then restart Claude Code:

  ```bash
  claude mcp add --scope user --env AGENT_BOM_MCP_WORKSPACE_ROOTS=/srv/app:/Volumes/work \
    agent-bom-workspace -- uvx --from agent-bom==0.110.0 agent-bom mcp server
  ```

- **Codex.** Add this to `~/.codex/config.toml`:

  ```toml
  [mcp_servers.agent-bom-workspace]
  command = "uvx"
  args = ["--from", "agent-bom==0.110.0", "agent-bom", "mcp", "server"]

  [mcp_servers.agent-bom-workspace.env]
  AGENT_BOM_MCP_WORKSPACE_ROOTS = "/srv/app:/Volumes/work"
  ```

Instead of the variable, `agent-bom mcp server --workspace-root <dir>` takes one
directory per flag and can be repeated. Both forms can be used together.

## Privacy

agent-bom runs on your machine and has no account, server or telemetry. It
keeps no data about you: results stay in your session and in a local cache
under `~/.agent-bom`, which you can delete at any time. The only data that
leaves your machine is package names and versions, sent to the public
vulnerability and package sources listed below, plus the cloud API calls made
with your own credentials when you ask the `bom` skill for a cloud AI-BOM.
Prompts, responses, file contents and credential values are never sent.

### What it runs, reads and sends

- **Runs** two local processes, `uvx --from agent-bom==<release> agent-bom mcp server`
  with and without `--profile audit`. uv downloads that exact release and its
  dependencies from PyPI on first use. Claude Code and Codex start the same two
  servers from the same `.mcp.json`. No hooks, no background jobs, and nothing
  runs outside a skill or tool call. The skills never launch or connect to the MCP
  servers they audit: `audit-mcp` always calls `tool_risk_assessment` with
  `live: false`.
- **Reads** MCP client configuration files on this machine (Claude Code, Claude
  Desktop, Cursor and other supported clients) to find agents, servers and the
  packages they launch, skill and instruction files under a path you name, plus
  any image, SBOM or repository you name. To flag agents that can act with no
  prompts or no sandbox, it also reads coding-agent permission settings: Claude
  Code `~/.claude/settings.json` (or `$CLAUDE_CONFIG_DIR/settings.json`), the
  project's `.claude/settings.json` and `.claude/settings.local.json`, and the
  system `managed-settings.json` and `managed-settings.d/`; Codex
  `~/.codex/config.toml` (or `$CODEX_HOME`), its `<profile>.config.toml` files and
  the project's `.codex/config.toml`. Only mode names, flags and unscoped rule
  strings are reported, never other setting values. The `activity` skill reads local
  Claude Code (`~/.claude/projects/**/*.jsonl`) and Codex
  (`~/.codex/sessions/**/rollout-*.jsonl`) session history on this machine only,
  with file, line and byte caps; prompts, responses and file contents are never
  put in its results, and command and path evidence is redacted. Credential
  values found in configs are redacted in results; only their names and locations
  are reported.
- **Sends** package names and versions, never file contents or credentials, to
  public vulnerability and package sources. `inventory`, `activity` and `audit-skills`
  make no network calls and send nothing; `audit-mcp`, `checkup`, `affected`, `scan`, `check` and `fix` use:
  - `api.osv.dev`: vulnerability lookups
  - `api.github.com`: GitHub security advisories
  - `pypi.org` and `registry.npmjs.org`: package metadata and typosquat checks
- **Writes** only when you ask for an AI-BOM: `bom` runs the same pinned release
  from your shell to write the file you name. For a cloud BOM it uses the
  credentials already configured for that provider's CLI, makes read-only API
  calls to that provider, and never asks you to paste keys.
- **Never** writes to agent configs, installs packages, or sends telemetry. Live
  credential validation and cloud connectors are off unless you enable them
  through the CLI.
- **Stores** a local cache under `~/.agent-bom`.

To try a local checkout: `claude --plugin-dir integrations/claude-code`, and
`claude plugin validate integrations/claude-code --strict` before publishing changes.
`claude plugin eval integrations/claude-code` runs the eval suite in `evals/` against
recorded tool output (no real server starts), including safety cases where a
config or skill carries injected instructions.
