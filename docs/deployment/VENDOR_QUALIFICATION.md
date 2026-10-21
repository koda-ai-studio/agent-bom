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
- Every requested provider occurs in the primary graph. Duplicate node IDs,
  incomplete pages, bounded graphs and the known synthetic showcase are rejected.
- Authenticated overview and findings endpoints respond successfully.

This is a bounded demo gate: at most 5,000 nodes and 2 MiB per response, with no
truncated graph edges. A larger estate requires a separate paginated qualification
run; truncation cannot silently pass this check. Provider labels are not proof of
live collection, and an empty findings response is not proof of clean posture.

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
