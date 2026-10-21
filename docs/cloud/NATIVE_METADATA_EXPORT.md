# Modal and NVIDIA NGC native metadata export

These bounded, read-only exports collect account metadata into a private JSON
artifact. They are an inventory foundation: they do not yet ingest this metadata
into the control-plane graph, evaluate posture, or qualify a complete vendor demo.

## First command

Install Agent-Bom from the checkout containing these collectors and the provider's
official SDK in an isolated environment. The commands below use `uv` and have been
validated with Modal 1.6.2 and NGC SDK 4.37.0.

```bash
uv run --no-project --with-editable . --with modal==1.6.2 \
  python -m agent_bom.cloud.native_inventory_cli modal \
  --account YOUR_WORKSPACE --environment main \
  --credential-file /private/modal.json --output /private/modal-inventory.json

uv run --no-project --with-editable . --with ngcsdk==4.37.0 \
  python -m agent_bom.cloud.native_inventory_cli ngc \
  --account YOUR_ORGANIZATION \
  --credential-file /private/ngc.json --output /private/ngc-inventory.json
```

The credential file must have mode `0600` on POSIX systems. Modal credentials use
`workspace`, `token_id`, and `token_secret` fields. NGC credentials use
`organization` and `token` fields. The requested account must match both the file
and the authenticated provider response. Keep these files outside repositories.
An output path cannot replace its credential file.

The collector issues metadata reads only; it does not create workloads, invoke
functions, run inference, or change permissions. The underlying credential may
permit writes. Use the narrowest available credential and an explicit account.

## Artifact and evidence boundaries

The JSON report contains scoped resource identifiers, allowlisted attributes,
collection timestamps, per-capability completeness, and an evidence SHA-256 hash.
It is written atomically with private permissions. Exit status `0` means the
requested metadata reads completed; `2` means partial collection or an error.
An empty catalog is not a clean security assessment.

- **Modal:** workspace members, service users, environments, configured environment
  roles, recent apps, functions, and selected function configuration. App listing
  is the provider's recent inventory, not a full historical snapshot. Configured
  roles and network settings do not establish effective access or observed traffic.
- **NGC:** authenticated organization, teams, users where permitted, the caller's configured organization roles, and owned
  images/models. Public catalog entries are excluded from owned assets. NGC
  Catalog access does not demonstrate NVIDIA compute infrastructure access.
  Effective grants and service-identity enumeration remain unqualified.
- Reads have deadlines and output caps. `--limit` bounds each collection (default
  100, maximum 1,000). Denied, malformed, truncated, or conflicting results are
  incomplete. They cannot authorize deletion of absent assets. The report does
  not claim incremental collection, graph correlation, or a security finding.

## Next step

Review `coverage` and the resource metadata before configuring downstream
normalization. Graph ingestion, persistence, findings, multi-account qualification,
and the authenticated UI journey require separate validation. These exports do
not replace those gates.

CoreWeave Forge / Weights & Biases and CoreWeave Cloud / CKS are distinct access
surfaces. A Forge key is not evidence of Cloud or Kubernetes access.
