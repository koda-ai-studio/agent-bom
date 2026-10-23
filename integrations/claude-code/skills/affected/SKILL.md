---
name: affected
description: Answer "am I affected by this CVE?" with agent-bom - look up a CVE, GHSA or OSV advisory and check whether any agent, MCP server or package on this machine carries it, with the fixed version. Use when the user names an advisory id or a vulnerability in the news and asks whether they are exposed.
argument-hint: "<CVE-…|GHSA-…|PYSEC-…>"
homepage: https://github.com/koda-ai-studio/agent-bom
source: https://github.com/koda-ai-studio/agent-bom/tree/main/integrations/claude-code/skills/affected
license: Apache-2.0
capabilities:
  read_inventory: true
  read_findings: true
  read_audit_log: false
  write_findings: false
  outbound_http: true
  shell_exec: false
---

Answer whether the named advisory is present on this machine. This skill is read-only.

1. Call `intel_lookup` on the `agent-bom` server with `advisory_id`. Note its summary, severity, KEV status, aliases (`canonical_ids`) and the affected packages and fixed versions it lists. The advisory record can be incomplete for an ecosystem; it describes the advisory, not this machine.
2. Call `scan` on the `agent-bom` server with `detail: "summary"` (pass `config_path`, `image` or `repo_url` if the user named one). Page `section: "findings"` with the returned `result_id` and keep findings whose `cve_id` or aliases match the advisory id or any of its `canonical_ids`.
3. Answer in one line first:
   - **Affected**: name each package and version, the agents and MCP servers that use it, and the first fixed version, for example "Yes: pillow 9.0.0 via the `image-tools` server, fixed in 10.0.1".
   - **Not found**: say the advisory was not found in what was scanned, and name what was scanned (agents, servers and package count). Do not say "safe" or "not affected" beyond that scope.
4. Add context in two or three lines: severity, KEV status and whether a fix exists. If `vuln_data_freshness.stale` is true, say the local vulnerability data is out of date and the answer may miss newer records.
5. If affected, offer the `fix` skill (Claude Code: `/agent-bom:fix`) for the upgrade plan. Propose edits only; change a manifest or lockfile only after the user confirms.

If `intel_lookup` finds no advisory, say so and still check the scan findings for the id the user gave.
