# Qualify an authenticated vendor demo

Start with the [authenticated hosted instance](../../site-docs/deployment/authenticated-hosted-instance.md)
and its existing platform + product Compose stack. Keep real provider data in
that authenticated instance, with persistent PostgreSQL storage. The public
synthetic showcase is a separate deployment and cannot pass this gate.

## First command

Collect and ingest the approved vendor scopes into the primary tenant. Create a
second, isolated control tenant with an empty persisted graph snapshot. Supply
separate tenant-bound API keys that can read graph, findings, overview and system
health. The probe reads existing state; it does not create tenants, snapshots,
keys, workloads or infrastructure. An absent snapshot returning `503` is not proof
of tenant isolation.

Save each raw API key in a separate file outside the repository with mode `0600`.
Use the exact package version deployed to this instance:

```bash
python scripts/deploy/vendor_qualification_smoke.py \
  --url https://agent-bom.example.com --version YOUR_DEPLOYED_VERSION \
  --tenant YOUR_PRIMARY_TENANT --other-tenant YOUR_EMPTY_CONTROL_TENANT \
  --api-key-file /private/primary-key --other-tenant-key-file /private/control-key \
  --provider aws --provider azure --provider gcp \
  --output /private/vendor-before-restart.json
```

The stdlib-only probe requires HTTPS except for loopback validation. It sends
GET requests only, rejects redirects, bounds response sizes and never prints
credentials or response bodies. Use trusted deployment origins. Credentials go
in authorization headers, not command arguments or URL parameters.

## Artifact

Exit `0` writes a private JSON receipt with the expected version, tenant labels,
provider names, graph counts and an evidence digest. Exit `1` means qualification
failed; retain the command result and investigate before calling the demo ready.
The gate checks:

- Authentication is configured and required; anonymous and invalid-key graph
  reads are denied, as is anonymous system-health access.
- Each key resolves to the expected, distinct tenant. Forged tenant headers
  cannot switch the primary key's evidence. The control tenant's graph is empty.
- The control plane, graph, job and key stores report PostgreSQL backends.
- Every requested provider occurs in the primary graph. Conflicting duplicate rows,
  incomplete pagination and the known synthetic showcase are rejected. Node and
  incident-edge pages stay pinned to one snapshot and generation.
- Authenticated overview and findings endpoints respond successfully.

This is a bounded, paginated demo gate: at most 10,000 nodes, 100,000 edges,
2,000 requests per graph read and 2 MiB per response. Canvas pages enumerate the
estate; bounded incident-edge pages recover full node and relationship records
before computing the digest. The final counts must match the snapshot totals.
Missing endpoints, changing generations, repeated cursors, unknown truncation
and exhausted budgets fail closed. Provider labels are not proof of live
collection, and an empty findings response is not proof of clean posture.

## Restart comparison and next step

After an operator restarts the same private deployment, repeat the command with
`--baseline /private/vendor-before-restart.json` and a different `--output`, such
as `/private/vendor-after-restart.json`. The comparison requires the same origin,
version, tenants, providers and exact normalized node/edge evidence. It detects
evidence drift; a concurrent rescan can legitimately make it fail. The probe does
not perform or independently attest the restart. Preserve the restart receipt
alongside both probe receipts.

Then inspect the authenticated browser journey for every vendor: configuration,
resources, identities, grants, findings and graph evidence. Verify provider reads,
scoped multi-account coverage, lifecycle replays and persistence separately.
Configured access, explicit trust and observed communication need distinct
evidence; do not infer links merely because two platforms appear in one graph.
The receipt explicitly leaves browser, live-provider and finding-accuracy
qualification unverified.

## Supabase and Vercel directory evidence

For an approved organization or team, collect directory membership alongside
resource configuration. Credential files stay outside the checkout:

```bash
agent-bom cloud supabase --organization-slug ORGANIZATION_SLUG \
  --token-file /private/supabase.json --output /private/supabase-report.json \
  --graph-db /private/supabase.db --tenant demo
agent-bom cloud vercel --team-id TEAM_ID --include-members \
  --token-file /private/vercel.json --output /private/vercel-report.json \
  --graph-db /private/vercel.db --tenant demo
```

The JSON report retains read coverage; the graph contains account-scoped users
and configured roles. Membership edges are non-traversable and do not assert
effective permissions, cross-account trust or observed traffic. Pending Vercel
invitations remain identity inventory without accepted membership. Conflicting
or redacted native identifiers remain unresolved, with an incomplete projection
receipt on the account. Service identities, trust and communication remain
explicitly uncollected by these directory reads.

A complete organization snapshot can add or remove projects within that same
organization. Explicit project-ref scans retain their exact project boundary.
Incomplete collection exits `2` and preserves the previous local graph; this
includes paused Supabase advisors. Local snapshots use the report's observation
time, including subsecond precision, so a late older observation does not become
the latest snapshot. Snapshot history remains subject to configured retention.
These are full-snapshot semantics, not native incremental collection.

Next, push the report through the authenticated control-plane path and check
its scoped identities, findings and coverage in the browser. A successful member
read alone does not qualify the entire vendor.
