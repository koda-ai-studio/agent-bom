# agent-bom for Codex (skills-only)

This is the agent-bom package for the public Codex plugin directory. It has ten
skills and no MCP server: the directory lists local plugins as skills-only, so
each skill runs a pinned agent-bom release from your shell and reads its JSON
output. Every skill is read-only by default. Anything that would change a file
is proposed first and applied only after you confirm.

If you would rather have the local MCP servers as well, install the repository
plugin instead (see [Two ways to install in Codex](https://github.com/koda-ai-studio/agent-bom/blob/main/integrations/claude-code/README.md#two-ways-to-install-in-codex)).
That plugin is named `agent-bom-local`, so its skills (`agent-bom-local:scan`)
never shadow this package's (`agent-bom:scan`). Both do the same jobs, so
install one.

You need [uv](https://docs.astral.sh/uv/) on `PATH`. No account or API key is needed.

| Skill | What it does |
|---|---|
| `checkup` | Start here: one screen with a verdict, totals, and the three fixes that matter most, from the inventory, a configuration audit and a scan. |
| `affected` | Am I affected? Says which packages, servers and agents carry a CVE, GHSA or OSV id with the version to patch to, which distro packages are possibly affected (verify the distribution's advisory), and what was scanned. |
| `bom` | Write an AI-BOM (CycloneDX or SPDX) for this machine, a project, an image, or an AWS, Azure or GCP account. |
| `scan` | Scan this machine's MCP clients, or an image, SBOM or repository, for CVEs, malicious packages and credential reach. |
| `check` | Vet a package or MCP server before adding it: CVEs, KEV, typosquats, fixed version. |
| `fix` | Ordered remediation plan: which upgrades clear the most risk, and what has no fix yet. |
| `inventory` | AI estate inventory: agents, MCP servers, tools, packages and how they connect. No CVE lookups. |
| `audit-mcp` | Configuration audit of MCP servers: credentials in config, unpinned launchers, unauthenticated or non-TLS remote servers. |
| `audit-skills` | Audit skills and instruction files (SKILL.md, CLAUDE.md, AGENTS.md, rules files) for prompt injection, exfiltration and broad tool grants. |
| `activity` | Review what Claude Code and Codex did: MCP servers and tools used, unused servers, risky actions, installed packages. |

## What it can and cannot do compared with the MCP plugin

The skills cover the same jobs, with the same reporting rules, as the
[MCP plugin skills](https://github.com/koda-ai-studio/agent-bom/blob/main/integrations/claude-code/README.md). Both sets render their shared
rules from one spec, `integrations/shared/skills.toml`. The differences come
from the CLI of the pinned release:

- The skills never collect live tool listings, so MCP servers are judged from
  their configuration and package metadata only.
- `affected` matches the id against the scan's findings and their aliases,
  and against an advisory an operator declared with `db advisory add`; there
  is no separate advisory lookup, so it cannot describe an advisory that is not
  present on this machine. `db advisory match` and possibly-affected distro
  rows are available only on agent-bom releases after 0.110.0; on 0.110.0 the
  skill skips that step and says so.
- `audit-mcp` reports coding-agent permission findings, and `activity` works,
  only on agent-bom releases after 0.110.0. On 0.110.0, `activity` says the
  command is not available and stops.
- `scan` lists the ten highest-ranked findings from the bounded `--agent-mode`
  summary; the totals cover everything.

## What it runs, reads and sends

- **Runs** only `uvx --from agent-bom==<release> agent-bom <command>`, with the
  release pinned in each skill. uv downloads that exact release and its
  dependencies from `pypi.org` on first use and caches them. The commands are:
  - `scan` (`checkup`, `scan`, `audit-mcp`, `affected`, `bom`)
  - `mcp inventory` (`checkup`, `inventory`, `audit-mcp`, `scan`)
  - `mcp audit` without `--live` (`checkup`, `audit-mcp`)
  - `check` (`check`)
  - `remediate` without `--apply` (`fix`)
  - `skills scan` (`audit-skills`)
  - `activity` without `--check-packages` (`activity`)
  - `image` (`bom`)
  - `cloud aws`, `cloud azure` and `cloud gcp`, from the `agent-bom[aws]`,
    `[azure]` or `[gcp]` extra (`bom`, only when you ask for a cloud BOM)
  - `where` (`inventory`, only to show which paths were checked)
  - `db`, only as `db advisory match` (`affected`; it reads advisories an
    operator already declared and the scan result it just wrote, with no
    network calls)

  The skills tell you each command before running it. They never pass flags
  that write, connect or launch (`--apply`, `--open-pr`, `--live`,
  `--allow-command-execution`, `--introspect`, `--push-url`), never run a fix or
  install command that agent-bom suggests, and never launch or connect to the
  MCP servers they audit. No hooks, no background jobs, and nothing runs outside
  a skill.
- **Reads** MCP client configuration files on this machine (Claude Code, Claude
  Desktop, Cursor, Codex and other supported clients) to find agents, servers
  and the packages they launch; project manifests and lockfiles in a directory
  you name; skill and instruction files under a path you name; and any image,
  SBOM or repository you name. `activity` reads local Claude Code
  (`~/.claude/projects`) and Codex (`~/.codex/sessions`) session history, with
  file, line and byte caps; prompts, responses and file contents are never put
  in its output, and command and path evidence is redacted. Credential values
  found in configs are redacted; only their names and locations are reported.
- **Sends** package names and versions, never file contents or credentials, to
  public vulnerability and package sources. `inventory`, `audit-skills` and
  `activity` make no lookups of their own; `checkup`, `scan`, `check`,
  `affected`, `fix`, `audit-mcp` and `bom` use:
  - `api.osv.dev`: vulnerability lookups
  - `api.github.com`: GitHub security advisories
  - `pypi.org` and `registry.npmjs.org`: package metadata and typosquat checks

  `scan --repo` clones the public repository you name. A cloud BOM makes
  read-only API calls to that provider with the credentials already configured
  for its CLI; the skills never ask you to paste keys.
- **Writes** JSON results to a private temporary directory made with
  `mktemp -d`, and an AI-BOM file only when you ask for one. agent-bom keeps a
  local cache under `~/.agent-bom`, including its vulnerability database and
  the skills catalog that `skills scan` updates.
- **Never** writes to agent configs, installs packages, or sends telemetry.

## Privacy

agent-bom has no hosted service in this package and collects nothing. All
analysis runs on your machine. The only data that leaves it is listed above:
package names and versions sent to public advisory and package registries, the
uv download of the pinned release from PyPI, and, only when you ask, a public
repository clone or read-only calls to your own cloud account. Credential
values, file contents, prompts and session transcripts are never sent anywhere.
Results stay in local files you control.

## Building the directory ZIP

```text
python scripts/render_plugin_skills.py --check
python scripts/build_codex_plugin_zip.py
```

The builder writes `dist/agent-bom-codex-plugin.zip` with only `plugin.json`,
`.codex-plugin/plugin.json`, `README.md`, `LICENSE`, `skills/*/SKILL.md` and
`assets/icon.png`, and fails if the package carries hooks, `.app.json` or an
MCP configuration, or if a listing field is over its limit. Edit skills in
`integrations/shared/skills.toml`, not in `skills/`: the generated files are
overwritten.
