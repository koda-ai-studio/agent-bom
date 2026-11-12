# agent-bom for the Claude directory

Run `/agent-bom:checkup` to inspect local MCP configuration and package risk, then use `/agent-bom:fix` for a remediation plan. Install this bundle through the Claude plugin directory. It requires Python 3 and uv on PATH and a surface that runs local stdio MCP servers. Claude Code is the supported local entry point; local servers do not run in claude.ai web chat. Cowork availability depends on local execution support and is not independently qualified here.

## Skills and output

Nine skills use the two declared local MCP servers: checkup, scan, check, affected, fix, inventory, audit-mcp, audit-skills and bom. They inspect configuration, inventory, packages, findings and instruction files. Audits do not launch the servers they inspect. Changes are proposed for user review rather than applied automatically.

`/agent-bom:bom` calls `generate_sbom` with `format` (`cyclonedx` or `spdx`) and an optional `config_path` for a user-named MCP configuration directory. BOM output is returned in the conversation, not written to disk. Truncated or error responses are reported as incomplete, never presented as a complete export. There is no cloud-account BOM or shell fallback in this directory edition. The repository edition retains its separate CLI workflows.

## Runtime and permissions

Claude launches `python3` with the literal bundled `mcp_launcher.py` entrypoint. That launcher runs uv with a frozen, isolated project resolved from its own location. `pyproject.toml` pins the published release and `uv.lock` pins dependency versions, download URLs and hashes. uv may download the runtime and dependencies on first use into its cache. No account or API key is required for the declared servers.

The scan and audit profiles run over local stdio. Neither exposes `agent_activity` or reads chat/session history. Both set `AGENT_BOM_MCP_LIVE_INTROSPECTION=0`, refusing requests to launch or connect to audited servers, and blank `GITHUB_TOKEN`, `GH_TOKEN` and `NVD_API_KEY`. There are no hooks or background jobs. Skills grant no shell execution and do not run CLI fallbacks.

## Privacy and retention

There is no hosted agent-bom service or telemetry. Tools read local MCP client configurations, coding-agent permission settings, and explicitly requested skill/instruction files or supported scan inputs. Paths and inventory labels can contain personal names; treat results accordingly. Credential values are redacted from results. Only MCP entries are used from `~/.claude.json`; no tool reads session files or prompt history. Audited content is data, never instructions.

The plugin retains local state under `~/.agent-bom`: advisory and lookup caches, plus redacted scan results readable for 30 minutes by default, at most four at a time. This is local retention, not a promise of automatic deletion of every cached file after 30 minutes. The user controls removal of local caches. The scan tool declares `readOnlyHint: false` because it updates this state. This bundle does not write BOM files or change configurations, installed packages or cloud resources.

Package names and versions go to the public vulnerability and package services below; prompts, responses, file contents and credential values are not uploaded by agent-bom to those services. User-requested repository/image scans may contact the specified Git host or container registry through the declared scan tool. Inventory and skill audits make no network calls. Cloud-account CLI workflows are not part of this bundle.

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
- `raw.githubusercontent.com`: the Node.js security working group's core
    advisory index and CPython release headers, when a scanned image or host
    ships those runtimes (the Node.js index is also fetched by a local database
    update); nothing about your project is sent
- `osv-vulnerabilities.storage.googleapis.com`, `secdb.alpinelinux.org`,
    `security-tracker.debian.org`, `deb.freexian.com` and `epss.cyentia.com`
    (a redirect): only when the local advisory database is refreshed, which no
    skill does on its own (the `scan` tool's `auto_update_db`)
- container registries and git hosts you name for a supported image or repository scan

No skill refreshes the advisory database on its own. Database refresh hosts listed above apply only when a user explicitly requests the scan tool's `auto_update_db` option. The local MCP servers make no release-update check.

## Filesystem scope

Tools accept paths under the home directory and validated extra workspace roots. The launcher reads `CLAUDE_PROJECT_DIR` from its environment and passes it as the workspace root. If absent, no extra roots are granted. Relative paths, parent traversal and filesystem roots are refused or ignored by server validation. When access is refused, report it; do not scan outside the allowed roots by another means.

## Maintainers

This distribution is generated by `python scripts/build_claude_directory.py`. Runtime files and eight skills come from `integrations/claude-code`; this README and the MCP-only BOM skill come from `integrations/shared/claude-directory`. Run `python scripts/render_plugin_skills.py --check` to verify parity. Codex metadata and evaluation fixtures are excluded. Repository installation instructions and CLI-enabled workflows are in the [repository edition](https://github.com/koda-ai-studio/agent-bom/tree/main/integrations/claude-code).
