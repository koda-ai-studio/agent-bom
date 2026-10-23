---
name: inventory
description: Inventory this machine's AI estate with agent-bom - which agents and MCP clients are configured, the MCP servers they launch, the tools those servers expose, the packages behind them and how they connect. Use when the user asks what AI agents, MCP servers or tools they have, for an AI-BOM, or for an agent inventory.
argument-hint: "[config directory]"
homepage: https://github.com/koda-ai-studio/agent-bom
source: https://github.com/koda-ai-studio/agent-bom/tree/main/integrations/claude-code/skills/inventory
license: Apache-2.0
capabilities:
  read_inventory: true
  read_findings: false
  read_audit_log: false
  write_findings: false
  outbound_http: false
  shell_exec: false
---

Use the agent-bom `inventory` tool on the `agent-bom-audit` server to list the AI estate. This skill is read-only: it reads MCP client configuration files and changes nothing.

1. Call `inventory`. Pass `config_path` only if the user named a project or config directory; with no argument it discovers every supported MCP client on this machine. It does not scan for CVEs and makes no network calls.
2. Read the result:
   - `agents`: each MCP client or project, with its `servers` (name, command, transport, packages). Each package row has `pinned`, `pinned_version` and `observed_version`.
   - `ai_bom_entities`: the joined snapshot. `summary` gives counts; `servers`, `tools`, `packages` and `relationships` (`uses`, `depends_on`, `exposes_tool`, `exposes_resource`, `exposes_prompt`) connect agent -> server -> tool and package. Join them by `id`.
3. Report, in this order:
   - one line of totals: agents, servers, tools, packages
   - a compact table per agent: server, transport, command or URL, packages
   - what stands out: remote servers (`transport` is not `stdio`, note `auth_mode`), packages with `pinned: false` (the launcher pins no version; `observed_version` and `version` are what was found this time, from `version_source` such as a local tool cache or registry fallback, never a pin), and servers that expose no tool list (`tools` is 0 until a live listing exists)
4. Quote counts exactly as returned. If `status` is `no_agents_found`, say no supported MCP client configuration was found and name the directory that was checked.
5. Offer the `audit-mcp` skill (Claude Code: `/agent-bom:audit-mcp`) to review these servers for risky configuration and the `scan` skill (Claude Code: `/agent-bom:scan`) for CVEs.

If the `agent-bom-audit` server has no `inventory` tool (plugin releases before it was added to the audit profile), use `scan` on the `agent-bom` server with `detail: "summary"` instead and say that tool-level relationships are not available in that release.

Never edit a config file, start an MCP server, or install anything to build the inventory.
