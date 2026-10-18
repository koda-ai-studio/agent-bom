# Scoped Supabase inventory and security advisors

Read project metadata and native Security Advisor results with an explicit
project scope. This collector uses the Supabase Management API, independently
of Agent-Bom's Supabase/Postgres persistence backend.

Create a project-scoped, time-limited management token with
`project_admin_read` and `advisors_read`. Store it in a private JSON file with a
`token` string field, then restrict the file to mode `0600`. Do not put the
value in shell arguments or commit it.

```bash
agent-bom cloud supabase \
  --project-ref abcdefghijklmnopqrst \
  --token-file /private/supabase-token.json \
  --output supabase-report.json
```

The JSON artifact contains allowlisted project configuration, native advisory
findings, and a receipt for each project/capability. Repeat `--project-ref` for
up to 50 explicitly authorized projects. `agent-cloud supabase` is an alias.

To retain a **complete** collection as a tenant-scoped SQLite graph snapshot,
add `--graph-db ./supabase-graph.db --tenant example`. Use a dedicated database
for the selected project scope. A changed project scope is rejected; use a
separate database for that scope. Project organization ownership and native
finding-to-project links carry modeled-infrastructure evidence; they do not
establish execution, effective permissions, or exploitability. The graph
contains project assets, configuration and advisor findings, without invented
MCP tools or agents.

Next, inspect `coverage`, then follow each finding's native advisor rule and
project reference in Supabase's Security Advisor. Fixes require operator
review; a later empty response does not automatically resolve prior findings.

## Evidence and failure behavior

- Only `GET /v1/projects/{ref}` and
  `GET /v1/projects/{ref}/advisors/security` are called. No project listing,
  SQL, customer rows, secrets, API keys, resume, or advisor-execution requests.
- Responses are bounded to 2 MiB per endpoint and 5,000 advisors per project;
  redirects are refused. Timeout, denied, rate-limited, oversized or invalid
  responses retain explicit partial coverage. Retry a rate-limited run after
  the provider allows further requests.
- An inactive project can return an empty advisor list. It remains `paused`
  and unevaluated. Empty active-project results mean only that this endpoint
  returned no advisors; they never establish clean posture.
- Native `cache_key`, rule name, severity and source observation time are
  retained in finding evidence. Missing source time and rule version stay
  unknown. ERROR/WARN/INFO map to high/medium/info; other native levels map to
  unknown while their original label is retained. No CVSS score is invented.
- Capability `evaluated` means native results from an active project were
  interpreted; it does not mean Agent-Bom ran SQL or independently evaluated
  all project settings. `persisted` means the optional graph write completed.
- A partial run exits **2**, writes its JSON receipt, and leaves the previous
  graph snapshot intact. Invalid credentials/configuration or a failed write
  exit **1**. Complete runs exit **0**. Incomplete collection never enables
  absent-finding reconciliation. Previously written snapshots remain
  available by scan ID. Rollback: stop invoking the collector; retain its
  receipts and graph database according to the operator's retention policy.
- Reports use atomic replacement and private file permissions. Their SHA-256
  covers the JSON object excluding `evidence_sha256`; it is a content digest,
  not an independent or provider-signed attestation.

The native advisor endpoint is experimental. See the official
[project contract](https://supabase.com/docs/reference/api/v1-get-project) and
[security advisor contract](https://supabase.com/docs/reference/api/v1-get-security-advisors).
This command does not register a hosted connection or schedule collection in
the dashboard. API connection onboarding and per-capability UI remain separate
integration work.
