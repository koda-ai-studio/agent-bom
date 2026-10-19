---
name: check
description: Check a package or MCP server with agent-bom before installing or adding it - known CVEs, malicious or typosquatted names, and the fixed version. Use when the user is about to add an MCP server, install a dependency, or asks whether a package is safe.
argument-hint: "<package>[@version] [ecosystem]"
---

Use the agent-bom `check` MCP tool to vet one package before it is installed.

1. Parse the request into `package`, `ecosystem` (npm, pypi, go, cargo, maven, nuget, …) and `version` if given. An MCP server launched with `npx` is npm; one launched with `uvx` or `pip` is pypi.
2. Call `check`. If the user named no version, say that the latest published version was checked.
3. Answer in this order:
   - a verdict in one line: safe to add, upgrade first, or do not install
   - malicious or typosquat signals, if any, and the legitimate name it imitates
   - CVEs with severity, KEV status and the first fixed version
4. If the package is fine but the user is adding an MCP server, suggest running `/agent-bom:scan` afterwards to see what credentials and tools the new server can reach.

Do not install, download or run the package to check it.
