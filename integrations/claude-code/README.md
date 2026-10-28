# agent-bom for Claude Code

A Claude Code plugin that runs the agent-bom MCP server locally (stdio) and adds
ten skills. Every skill is read-only by default: anything that would change a file
is proposed first and only applied after you confirm.

```text
/plugin marketplace add koda-ai-studio/agent-bom
/plugin install agent-bom@agent-bom
```

## Skills

| Skill | What it does |
|---|---|
| `/agent-bom:checkup` | Start here: one screen with a verdict, totals, and the three fixes that matter most, from the inventory, a passive config audit and a scan. |
| `agent-bom-guard` (companion plugin) | Checks package installs before Claude runs them and blocks known-malicious packages and typosquatted npm and PyPI names. Install it with `/plugin install agent-bom-guard@agent-bom`; see [its README](../agent-bom-guard/README.md). |
| `/agent-bom:audit-skills [path]` | Audit skills and instruction files (SKILL.md, CLAUDE.md, AGENTS.md, rules files) for prompt injection, exfiltration, remote code execution and broad tool grants. |
| `/agent-bom:activity [days] [dir]` | Review what Claude Code and Codex actually did: MCP servers and tools used, configured servers never used, risky actions (pipe-to-shell, force pushes, writes outside the project, secret-file reads) and packages installed. Local only. |
| `/agent-bom:affected <advisory>` | Am I affected? Looks up a CVE, GHSA or OSV id (including NVD-only CVEs) and says which packages, servers and agents carry it with the version to patch to, which distro packages are possibly affected, and what was scanned. |
| `/agent-bom:scan` | Discover the MCP clients on this machine and scan their servers and packages, or scan an image, SBOM or repository. |
| `/agent-bom:check <package>[@version] [ecosystem]` | Vet a package or MCP server before adding it: CVEs, KEV, typosquats, fixed version. |
| `/agent-bom:fix` | Ordered remediation plan: which upgrades clear the most risk, and what has no fix yet. |
| `/agent-bom:inventory [dir]` | AI estate inventory: agents, MCP servers, tools, packages and how they connect. No CVE lookups. |
| `/agent-bom:audit-mcp [dir]` | Passive audit of MCP configs: credentials in config, unpinned launchers, unauthenticated or non-TLS remote servers, risky packages. |
| `/agent-bom:bom [target]` | Write an AI-BOM (CycloneDX or SPDX) for this machine, a project, an image, a repository, or an AWS, Azure or GCP account: agents, MCP servers, tools, models and packages, with how they connect. |

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
`uv run --frozen --isolated --project <plugin folder> agent-bom mcp server`, so
they need [uv](https://docs.astral.sh/uv/). `pyproject.toml` in this folder pins the
published release and `uv.lock` records every dependency's exact version, PyPI URL
and sha256 hash; uv installs exactly that, never resolves at launch, and writes
nothing into the plugin folder (the environment lives in uv's cache). The lock
covers Python 3.11 to 3.14 (uv downloads one if none is installed) on macOS,
Linux x86_64 and aarch64, and Windows x64 and ARM64. No API key or account is
needed. `inventory` and the skill audit tools join the audit
profile in the release after 0.109.0; on 0.109.0 those two skills fall back to
`scan` and `prompt_scan` and say so. `agent_activity` joins the audit profile in
the release after 0.110.0; on earlier releases the `activity` skill says it is
not available.

## Two ways to install in Codex

| | Repository marketplace | Public plugin directory |
|---|---|---|
| Package | this folder (`.codex-plugin/plugin.json`) | [`integrations/codex`](../codex/README.md), skills-only |
| How skills run agent-bom | the two locked local MCP servers (`uv run --frozen`, `uv.lock`) | the pinned CLI from the shell (`uvx --from agent-bom==<release> agent-bom … --agent-mode` or `-f json`) |
| Plugin name | `agent-bom-local` | `agent-bom` |
| Install | `codex plugin marketplace add koda-ai-studio/agent-bom`, then install agent-bom-local from the Plugins Directory | install agent-bom from the public directory |
| Needs | uv; Codex starts the MCP servers | uv; Codex runs shell commands, each shown to you first |

Both carry the same ten skills with the same safety rules, rendered from
`integrations/shared/skills.toml` by `scripts/render_plugin_skills.py`. The
public directory lists local plugins as skills-only, which is why that package
has no MCP server. What that costs: `affected` has no advisory lookup and matches
only findings on this machine, and on releases up to 0.110.0 the CLI has no
`activity` command and `mcp audit` reports no coding-agent permission
findings. The two have different plugin names, so Codex keeps their skills apart
(`agent-bom-local:scan` and `agent-bom:scan`), but each does the same jobs:
install one. In Claude Code this plugin is still `agent-bom`, with
`/agent-bom:` commands.

## Projects outside your home directory

The MCP server only reads paths under your home directory. A project somewhere
else, such as a container mount, `/srv` or `/Volumes/<disk>`, is refused with
"Path resolves outside home directory". To allow it, set
`AGENT_BOM_MCP_WORKSPACE_ROOTS` to the extra directories, separated by `:`
(`;` on Windows). Each entry must be an absolute path. A relative path, a path
containing `..`, or a filesystem root such as `/` is ignored, so the setting
cannot open the whole disk.

The Codex plugin passes `AGENT_BOM_MCP_WORKSPACE_ROOTS` from its launch
environment through `env_vars`; set explicit absolute roots before starting
Codex, then reconnect the plugin. An unset variable grants no additional roots.
For a persistent setting independent of the app's launch environment, add your
own server entry next to the plugin's servers:

- **Claude Code.** Run this once, then restart Claude Code:

  ```bash
  claude mcp add --scope user --env AGENT_BOM_MCP_WORKSPACE_ROOTS=/srv/app:/Volumes/work \
    agent-bom-workspace -- uvx --from agent-bom==0.111.0 agent-bom mcp server
  ```

- **Codex.** Add this to `~/.codex/config.toml`:

  ```toml
  [mcp_servers.agent-bom-workspace]
  command = "uvx"
  args = ["--from", "agent-bom==0.111.0", "agent-bom", "mcp", "server"]

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

- **Runs** two local processes, `uv run --frozen --isolated --project <plugin folder>
  agent-bom mcp server` with and without `--profile audit`. uv downloads the
  release and the dependencies locked in `uv.lock` from PyPI on first use and
  checks each file's hash. Claude Code starts them from `.mcp.json`; Codex starts
  the same two servers from the `mcpServers` block of `.codex-plugin/plugin.json`,
  which runs from the plugin folder because Codex expands no `${CLAUDE_PLUGIN_ROOT}`. No hooks, no background jobs, and nothing
  runs outside a skill or tool call. The skills never launch or connect to the MCP
  servers they audit: `audit-mcp` always calls `tool_risk_assessment` with
  `live: false`, and both servers start with `AGENT_BOM_MCP_LIVE_INTROSPECTION=0`,
  which refuses live connections and server launches even when a call asks for
  them. To allow live introspection, add your own server entry without that
  setting, as shown in [Projects outside your home directory](#projects-outside-your-home-directory).
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
  public vulnerability and package sources. `inventory`, `activity` and
  `audit-skills` make no network calls and send nothing. `audit-mcp`, `checkup`,
  `affected`, `scan`, `check`, `fix` and `bom` use:
  - `api.osv.dev`: vulnerability and malicious-package lookups
  - `api.github.com`: GitHub security advisories
  - `pypi.org` and `registry.npmjs.org`: package metadata, typosquat checks and
    the latest version of a package named without one
  - `www.cisa.gov`: the CISA Known Exploited Vulnerabilities (KEV) catalog

  Some hosts are reached only in a particular situation:
  - `files.pythonhosted.org`: uv downloads the pinned release and the
    dependencies locked in `uv.lock` on first use
  - `github.com`: uv downloads a managed Python when no Python 3.11 or later is
    installed, and a repository scan clones the repository you name
  - `api.first.org` and `epss.empiricalsecurity.com`: EPSS exploit-probability
    scores, when enrichment is on or for an advisory lookup
  - `services.nvd.nist.gov`: NVD CVSS data when enrichment is on, and lookups
    of CVEs only NVD has published
  - `api.securityscorecards.dev`: OpenSSF Scorecard results, when scorecard
    enrichment is on
  - `api.deps.dev`: license and project metadata a package registry does not
    provide
  - `proxy.golang.org` and `sum.golang.org`: Go module versions and checksums
  - container registries, git hosts and cloud provider APIs that you name, such
    as an image to scan or an account for a cloud AI-BOM

  The MCP servers make no update check; the CLI checks `pypi.org` for a newer
  release at most once a day, and never in quiet or JSON runs.
- **Writes** only when you ask for an AI-BOM: `bom` runs the same pinned release
  from your shell to write the file you name. For a cloud BOM it uses the
  credentials already configured for that provider's CLI, makes read-only API
  calls to that provider, and never asks you to paste keys.
- **Never** writes to agent configs, installs packages, or sends telemetry. Live
  credential validation and cloud connectors are off unless you enable them
  through the CLI.
- **Stores** a local cache under `~/.agent-bom`.

### Which paths the tools accept

The MCP tools take paths under your home directory and under the directories
named in `AGENT_BOM_MCP_WORKSPACE_ROOTS`. In Claude Code, `.mcp.json` sets that
variable to `${CLAUDE_PROJECT_DIR}`, so a project in `/tmp`, `/workspaces`
(devcontainers), `/srv` or `/Volumes` scans without setup. Codex expands no
variables in a plugin's MCP config. The `agent-bom-local` Codex plugin passes
an operator-set `AGENT_BOM_MCP_WORKSPACE_ROOTS` from the launch environment;
without it, only home-directory paths are accepted. Alternatively, declare
the server in `~/.codex/config.toml` with the root set:

```toml
[mcp_servers.agent-bom]
command = "uvx"
args = ["--from", "agent-bom==<release>", "agent-bom", "mcp", "server"]
env = { AGENT_BOM_MCP_WORKSPACE_ROOTS = "/workspaces/my-project" }
```

Separate several roots with `:` (`;` on Windows). Relative paths and `/` are
ignored.

To try a local checkout: `claude --plugin-dir integrations/claude-code`, and
`claude plugin validate integrations/claude-code --strict` before publishing changes.
`claude plugin eval integrations/claude-code` runs the eval suite in `evals/` against
recorded tool output (no real server starts), including safety cases where a
config or skill carries injected instructions.
