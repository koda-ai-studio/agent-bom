# Vercel inventory and configuration evidence

Use an explicitly approved team and a token with access to its project and deployment metadata. Keep the token in a private JSON file with a `token` field (`chmod 600`). The collector uses only GET `/v10/projects` and GET `/v7/deployments` on `api.vercel.com`; it does not create deployments or retrieve environment-variable values, source files, logs, or bypass credentials.

```bash
agent-bom cloud vercel --team-id team_example \
  --token-file /private/vercel-token.json \
  --output /private/vercel-report.json \
  --graph-db /private/vercel-graph.db --tenant example
```

`agent-cloud vercel` is the equivalent entry point. The JSON artifact contains allowlisted project settings, deployment metadata, per-capability collection receipts, configuration checks, and canonical findings. The optional SQLite snapshot uses the same tenant boundary as other graph storage. Use a dedicated database for this team; changing the team against an existing snapshot is rejected.

## Send the inventory to a control plane

To see the team in the same graph the API and dashboard serve, push it to the control plane with `--push-url` (a base URL or the full `/v1/results/push` endpoint). Set the API key in `AGENT_BOM_PUSH_API_KEY` or pass `--push-api-key`. The control-plane tenant comes from that key; `--tenant` applies only to `--graph-db`.

```bash
AGENT_BOM_PUSH_API_KEY=... agent-bom cloud vercel --team-id team_example \
  --token-file /private/vercel-token.json \
  --output /private/vercel-report.json \
  --push-url https://agent-bom.example.com
```

The push identifies the team as source `connector:vercel:<team_id>` with its own replacement scope. On `/v1/graph`, the team's projects, deployments, and findings appear next to other scans and connectors in the current estate. A later push for the same team replaces only that team's evidence. A partial collection is still pushed, marked `partial`: the control plane keeps the team's earlier evidence and reports `collection_coverage.status: partial`. Receipts for each stored target are under `persistence.push` in the report. If the control plane does not accept the push, the command exits 1 and records `persistence.push.status: failed`. `--graph-db` and `--push-url` can be used together.

The disabled Git fork approval finding is tagged SOC 2 CC8.1 (change authorization). It carries no NIST 800-53 tag: the matching objective, CM-3, is not in the scoring catalog.

Next, inspect `coverage`, `configuration_checks`, and `persistence` in the report. A complete read can contain zero deployments. A missing Git integration field remains unknown; it is not treated as proof that no repository is connected. The current versioned check reports disabled Git fork approval only when a Git integration is explicitly present. Deployment protection mode is retained as configuration, without inferring effective access or internet exposure.

## Failure and evidence boundaries

- Deployment reads use a fixed window covering the last 24 hours, sent as `since`/`until` timestamps and retained in the deployment receipt. Older history is outside this collection scope. The [Vercel deployment API](https://github.com/vercel/sdk/blob/main/src/models/getdeploymentsop.ts) defines these timestamp filters.
- Pagination is bounded to 20 pages, 2,000 records per capability, and 2 MiB per response. Missing, repeated, or invalid continuation state is incomplete coverage.
- Projects must match the requested team. Deployments must identify a project in the collected inventory. Malformed or conflicting records cannot become a complete snapshot.
- Exit 0 means inventory collection completed. It does not establish clean security posture. Configuration checks can be `pass`, `fail`, `unknown`, or `not_applicable`.
- Exit 2 retains partial evidence and leaves the prior graph snapshot intact. Denied access and rate limiting are distinct receipt states. Credential, output, and storage errors exit 1 with sanitized text.
- Reports and newly created graph databases use private file permissions. Reports are published atomically; storage failure is recorded in the report.
- Relationships show recorded ownership and deployment membership. They do not prove runtime execution, package vulnerabilities, firewall coverage, reachability, effective authority, or exploitation. No absent-finding reconciliation is performed.
