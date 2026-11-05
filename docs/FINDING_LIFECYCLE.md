# Finding lifecycle

Every finding carries a status and dates driven by scans, on both ingest paths
and both stores. First command: `agent-bom scan -p . --push-url <control-plane>`,
then `GET /v1/findings?status=all`, or the Status filter on the Findings page.

## States

| API `status` | Meaning | Common name |
|---|---|---|
| `open` | Reported by a scan and not since disproved | new, active |
| `reopened` | Resolved earlier, then reported again | resurfaced |
| `resolved` | A later complete scan of the same scope no longer finds it, or a complete inventory shows its asset gone | fixed, deleted |

`scan_count` of 1 distinguishes a new finding from an active one, so no extra
state is stored. `GET /v1/findings` defaults to `status=open`, which includes
`reopened` and stale findings. `status=stale` narrows that to stale findings;
`resolved` and `all` retrieve the rest.

## What each event does

| What happens | Status | Reason or label | Dates |
|---|---|---|---|
| Finding seen again in a scan | `open` | none | `last_seen` moves, `first_seen` stays |
| Patched: asset scanned fully, finding gone | `resolved` | `no_longer_detected` | `resolved_at` set |
| Asset deleted: complete inventory scan shows it gone | `resolved` | `asset_deleted` | `resolved_at` set |
| Finding comes back, or a deleted asset returns | `reopened` | none | original `first_seen` kept, `reopened_at` set, `last_resolved_at` keeps the earlier fix |
| Asset simply stops being scanned | `open` | `stale: true` after 30 days | `last_seen` stops moving |
| Partial or failed scan | no change | none | no change; missing data proves nothing |

## Fields

| Field | Value |
|---|---|
| `first_seen` | Earliest observation. Never moves forward, including on reopen. |
| `last_seen` | Latest observation. An older observation cannot move it back. |
| `resolved_at` | When a resolution in force happened; `null` unless `status` is `resolved`. |
| `resolution_reason` | `no_longer_detected` or `asset_deleted`; `null` unless `status` is `resolved`. |
| `last_resolved_at` | The latest resolution, kept after a reopen. |
| `reopened_at` | The latest reopen. |
| `status_updated_at` | When the current status began. |
| `stale` | Open, but not observed within `AGENT_BOM_FINDING_STALE_DAYS` (default 30). Computed when read. |
| `package_version` | The version from the latest observation. |

A stale finding stays open and counts as open everywhere. It never resolves on
its own: only a scan can do that, and the label clears on the next observation.
The default read window does not hide an open finding; an explicit `window_days`
does.

Identity is vulnerability or rule + asset + location or package version + project,
so a new vulnerable version is a new finding and the old one resolves, and the
same version in two projects is two findings with separate dates and resolutions.
The project is the push's `target_scope`, or an API scan's target fields. It enters
a one-way hash: the scope itself never appears in a finding or a response. A scan
with neither keeps the id its report used. Because the CLI's `target_scope` covers
the scanned paths and collection options, changing either starts new findings.

Grouped rows (`group_occurrences=true`) fold their occurrences: an issue stays
open until every occurrence is resolved and reports `open_occurrence_count` and
`resolved_occurrence_count`. Those counts cover the requested view, so use
`status=all` to see fixed occurrences beside open ones. A group is `stale` only
when every open occurrence is, and `asset_deleted` only when every resolved
occurrence is.

## What can resolve a finding

Only a complete scan covering the same scope. Incomplete evidence resolves
nothing and the finding stays open.

| Evidence | Result |
|---|---|
| Complete rescan of the same scope without the finding | Resolved at that scan's time, `no_longer_detected` |
| Package removed or upgraded on a scanned asset | Resolved, `no_longer_detected` |
| Complete inventory proves the asset is gone (below) | Resolved, `asset_deleted` |
| Scan of another asset, source or scope | No change |
| Partial or failed scan, or an incomplete requested scope | No change; `observation_status` becomes `unreconfirmed` |
| `--no-scan`, dry run or skipped vulnerability scan | No change |
| Advisory data outage while the package is still inventoried | No change; `unreconfirmed` with `advisory_data_degraded` |
| Advisory data outage and the package is gone from inventory | Resolved, `no_longer_detected` |
| Asset never scanned again | Stays open, `last_seen` ages, labelled stale |

## Deleted assets

A finding resolves as `asset_deleted` only when all of these hold. If any cannot
be shown, nothing changes.

- The scan is complete: outcome `complete`, no coverage issues, no incomplete
  requested scope. The server recomputes this from the inventory, so a report
  cannot claim `complete` over a permission error.
- The finding's asset is named by an ARN, which gives its account, region and service.
- The report's `cloud_inventory` has an AWS entry for that account with status
  `ok`, no warnings, no missing permissions, that region in its regions, and that
  service in the permissions it used. S3, IAM and CloudFront are global.
- No string in that inventory names the asset, by ARN or by its resource name.
- The report comes from the same source and scope that reported the finding, in
  the same tenant.

Inside a cloud-inventory scan, a finding on an ARN its inventory did not fully
cover also stays open rather than resolving as `no_longer_detected`. A push with no
target identity resolves nothing except through this proof.

**Sources left out.** Only AWS records region and service coverage. Azure, GCP and
every other collector, plus `POST /v1/findings/bulk`, never produce `asset_deleted`.
A complete rescan of their scope still resolves as `no_longer_detected`. Bulk rows
on a removed asset resolve by a complete empty batch naming it in `scanned_assets`.

## Ingest paths

**Push** (`POST /v1/results/push`, used by `agent-bom scan --push-url`). A report
replaces earlier reports of the same `source_id` and `target_scope`, the opaque
hash the CLI derives from the scanned targets and collection options. A push with
no target scope is independent evidence: nothing identifies what it covered, so
only the deleted-asset proof above can resolve it. Cloud collectors whose account
depends on ambient credentials are in this group until they send a target receipt.

State lives in `finding_lifecycle`, one row per tenant, scope and finding, written
in the same transaction as the scan's job row, and outlives scan retention
(`AGENT_BOM_API_JOB_TTL`). A failed write fails the ingest, which the producer
retries. Writers of one scope serialize on a transaction lock. Dates and
resolutions merge by evidence time rather than arrival:

- Repeated delivery counts once: `finding_lifecycle_scans` records every job.
- A late scan moves `first_seen` earlier or `last_seen` later, and a late complete
  scan can move a resolution earlier. Neither can reopen a newer resolution or
  resolve a newer observation.
- A finding first reported by a late scan arrives resolved if a newer complete scan
  disproves it.
- There is no retention cutoff on this: a scan older than everything recorded
  follows the same rules, so it can only widen dates.
- A report time more than a day ahead of when it was stored counts as the stored time.

After an upgrade the control plane's cleanup tick seeds existing dates from retained
scans in small commits, about 20 seconds a minute, and replicas can share the work.
Until a tenant finishes, reads answer from the finding streams of its retained reports
and write nothing; a report with no stream, from an old producer, shows as open with
its reported dates until then. Deleting a scan explicitly removes findings only it reported; expiry
removes nothing.

**Bulk** (`POST /v1/findings/bulk`, `agent-bom findings push`). A batch resolves
only with `reconcile_absent: true`, only within its `source`, and only on the
assets it names or lists in `scanned_assets`. `reconcile_scope: "source"` widens
that to everything from the source; use it for a report whose findings are per
file, such as SARIF. A `scan_run` receipt that is not complete reconciles nothing
and the response lists why in `reconcile_skipped`. State is stored per tenant in
`hub_findings_current`. See [Evidence ingest paths](INGEST_PATHS.md).

## Exceptions, assignments and tickets

Manual exceptions apply at read time and manual SLA assignments carry through
history, so both survive a resolve and reopen. Exceptions and triage assignees
match on vulnerability, package and server, so one applies to that package in every
project. A ticket filed before project identity stays linked: the tick copies its
link to each project's finding when it finishes the tenant.

## Limits

- **A reopen date can be late.** A complete scan arriving after a newer sighting
  records the reopen at the newest sighting, since the sightings between are not kept.
- **Resolved rows in one read are capped.** A read serves the newest 50,000 resolved
  findings. `GET /v1/findings` warns when it reaches that; narrow `window_days`.
  Scheduled exports read through the same cap.
- **The warehouse findings feed** (ClickHouse and Snowflake) carries `status`,
  `first_seen` and `last_seen` but not `resolved_at`, `resolution_reason` or
  `stale`; its table shape is unchanged. Each run replaces the tenant's rows, so
  project ids appear there on the next run.
- **Pinned reads** (`scan_id=`) return that scan's rows as reported, under project ids.
- **Graph nodes and SARIF keep their own ids.** Graph nodes stay per snapshot and
  join to findings through `finding_node_id`. SARIF and `--delta` are per-scan CLI
  output and do not use the project.
- **A job store with no durable table** (in-memory, Snowflake) folds retained scans
  with the same rules, so its history ends with its retention.
