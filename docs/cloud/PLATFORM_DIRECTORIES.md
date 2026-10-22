# Supabase organization and Vercel team directory collection

Use an explicit organization or team to collect project inventory alongside
dashboard membership. These are read-only management API calls. Credentials may
permit writes; collection does not change roles, billing, workloads, or data.

## First command

Create a private JSON file containing a `token` string outside the checkout and
set its permissions to `0600`. With Agent-Bom installed from this checkout:

```bash
agent-bom cloud supabase --organization-slug YOUR_ORGANIZATION_SLUG \
  --token-file /private/supabase.json --output /private/supabase-directory.json

agent-bom cloud vercel --team-id team_YOUR_TEAM --include-members \
  --token-file /private/vercel.json --output /private/vercel-directory.json
```

Supabase organization mode requires organization metadata, member and project
list read permissions, plus project metadata and security-advisor reads for the
enumerated projects. Choose either `--organization-slug` or repeated
`--project-ref` values. Vercel requires access to the selected team's metadata,
members, projects and deployments. Repeat collection with separate output files
for each authorized organization or team; access to one does not prove access to
others.

## Artifact

The private JSON report contains allowlisted directory identities and configured
membership grants, scoped by provider and organization/team. It records MFA and
membership confirmation only when returned by the provider. A membership role
does not establish effective resource access, cross-account trust, or observed
communication. Service identities, trust and communication are explicitly
`not_collected` by these directory reads.

Organization identity is checked before subordinate reads. Pagination must prove
completion; denied, malformed, conflicting, truncated or changing results stay
incomplete. Collection is bounded to 20 pages, 2,000 members and 50 Supabase
projects. Exit `2` preserves a partial report; it does not assert clean posture or
authorize deleting absent resources. An inactive Supabase project can leave the
overall report partial even when its organization directory is complete.

## Next step

Review each `coverage` receipt and retry missing permissions or incomplete scopes.
Add `--graph-db /private/directory.db --tenant YOUR_TENANT` to save a complete
collection as a local graph snapshot. The graph retains account-scoped users and
configured roles, joined by non-traversable membership edges. Directory receipts
declare `graph_supported: true`; that capability flag alone does not prove a
snapshot was persisted. Pending Vercel invitations remain identity inventory
without accepted membership, and conflicting or redacted identities remain
unresolved. Membership never implies effective resource access.

Incomplete collection exits `2` and preserves the previous local graph. Complete
organization snapshots can add or remove projects within that organization;
explicit project-ref scans retain their project boundary. Supabase organization
and project pushes have separate target scopes so their replacement boundaries
cannot collide. See the [directory evidence verification workflow](../deployment/VENDOR_QUALIFICATION.md#supabase-and-vercel-directory-evidence)
for local persistence and authenticated control-plane checks.

Do not call the vendor finalized from this export alone. Validate graph identity
projection, findings, replay/deletion behavior, persistence, account isolation and
the authenticated browser journey before that claim. These collectors perform
bounded snapshots, not incremental change-feed collection.

Provider references: [Supabase organization projects](https://supabase.com/docs/reference/api/v1-get-all-projects-for-organization),
[Supabase organization members](https://supabase.com/docs/reference/api/v1-list-organization-members),
[Vercel team members](https://vercel.com/docs/rest-api/teams/list-team-members).
