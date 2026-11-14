### Fixed
- A pushed scan whose report carries a scan note (for example a Maven transitive-dependency note) now keeps its grade on `/v1/posture` instead of reading N/A: ingest no longer re-counts the note's repeated string warning as a coverage gap. An unstructured legacy warning still marks coverage incomplete.
- `agent-bom secrets` and the runtime gateway no longer report any nine-digit number as a US SSN. A match needs a 3-2-4 value with one consistent separator, or nine digits under an SSN field.
- The generic password and secret rules no longer flag CSS class lists or snake_case/kebab-case enum values in source code. A connection string to a loopback host in a CI job definition is kept and lowered to low, with the reason recorded.
- A package declared with a version range (`anthropic>=0.30`) and imported in code is counted once, not as an `@unknown` and an `@latest` copy.
- The Agents page counts MCP servers with the same rule as its KPI strip and Asset inventory: a project's manifest and AI SDK inventory records are no longer counted as MCP servers in the per-agent column, the agent drawer, or the `/v1/agents` server sort.
- The executive posture summary says "on credential-bearing servers" for the findings it counts there, instead of "touch secrets".
