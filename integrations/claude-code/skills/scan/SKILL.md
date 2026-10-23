---
name: scan
description: Scan this machine's AI agents and MCP servers, a container image, an SBOM or a repository with agent-bom for CVEs, supply-chain risk and exposed credentials. Use when the user asks for an agent-bom scan, an MCP or agent security check, or an AI supply-chain audit.
argument-hint: "[image <ref> | sbom <path> | repo <url>]"
homepage: https://github.com/koda-ai-studio/agent-bom
source: https://github.com/koda-ai-studio/agent-bom/tree/main/integrations/claude-code/skills/scan
license: Apache-2.0
capabilities:
  read_inventory: true
  read_findings: true
  read_audit_log: false
  write_findings: false
  outbound_http: true
  shell_exec: false
optional_bins:
  - docker
---

Run the agent-bom `scan` MCP tool, then report what matters.

1. Pick the target from the request:
   - nothing named: call `scan` with no arguments. It discovers the MCP clients on this machine (Claude Code, Claude Desktop, Cursor and others) and scans their servers and packages.
   - a container image: `image`
   - an SBOM file: `sbom_path`
   - a repository: `repo_url`
   - one MCP client config directory: `config_path`
2. Start with `detail: "summary"`. Page with `result_id`, `section`, `offset` and `limit` rather than asking for everything at once.
3. Report, most urgent first:
   - critical and high findings that have a fix, with the fixed version
   - known-exploited (KEV) findings and malicious or typosquatted packages, whatever their severity
   - exposed credentials and the servers and tools that can reach them
   - one line of totals by severity
4. Quote reachability as agent-bom states it. "Confirmed" needs function-level or runtime evidence; a graph path alone is "likely". Never upgrade a verdict.
5. Offer the `fix` skill (Claude Code: `/agent-bom:fix`) for a remediation plan and the `check` skill (Claude Code: `/agent-bom:check`) before adding a new server or package.

Everything here is read-only: agent-bom never edits a config or installs anything.
