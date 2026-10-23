---
name: fix
description: Build a prioritized remediation plan with agent-bom - which upgrades remove the most risk, in what order, and which findings have no fix yet. Use when the user asks how to fix agent-bom findings, what to upgrade first, or for a remediation plan.
argument-hint: "[image <ref>]"
---

Use the agent-bom `remediate` MCP tool to plan fixes.

1. Call `remediate` (pass `image` or `config_path` if the user named one; otherwise it covers the discovered agents and MCP servers).
2. Present the plan as a short ordered list. Group by the change to make (one package upgrade often clears several CVEs), and for each step give:
   - the exact change, such as `upgrade lodash 4.17.20 -> 4.17.21` and where it is declared
   - what it clears: count, worst severity, and any KEV findings
   - the agents, servers or credentials it protects, when agent-bom reports them
3. List findings with no available fix separately, with the mitigation agent-bom suggests.
4. For larger estates, `exposure_paths` ranks attack paths; offer it when the user asks "what is actually exploitable".

Propose the changes; only edit manifests or lockfiles if the user asks you to apply them, and re-run the `scan` skill (Claude Code: `/agent-bom:scan`) afterwards to confirm.
