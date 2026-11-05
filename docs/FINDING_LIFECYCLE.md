# Finding lifecycle

Every finding carries a status and dates driven by scans, on both ingest paths
and both stores. First command: `agent-bom scan -p . --push-url <control-plane>`,
then `GET /v1/findings?status=all`, or the Status filter on the Findings page.

## States

| API `status` | Meaning | Common name |
|---|---|---|
| `open` | Reported by a scan and not since disproved | new, active |
| `reopened` | Resolved earlier, then reported again | resurfaced |
| `resolved` | A later complete scan of the same scope no longer finds it | fixed |

`scan_count` of 1 distinguishes a new finding from an active one, so no extra
state is stored. `GET /v1/findings` defaults to `status=open`, which includes
`reopened`; `resolved` and `all` retrieve the rest.

## Fields

| Field | Value |
|---|---|
| `first_seen` | Earliest observation. Never moves forward, including on reopen. |
| `last_seen` | Latest observation. An older observation cannot move it back. |
| `resolved_at` | When a resolution in force happened; `null` unless `status` is `resolved`. |
| `last_resolved_at` | The latest resolution, kept after a reopen. |
| `reopened_at` | The latest reopen. |
| `status_updated_at` | When the current status began. |
| `package_version` | The version from the latest observation. |

Identity is vulnerability or rule + asset + location or package version, so a
new vulnerable version is a new finding and the old one resolves.

Grouped rows (`group_occurrences=true`) fold their occurrences: an issue stays
open until every occurrence is resolved and reports `open_occurrence_count` and
`resolved_occurrence_count`. Those counts cover the requested view, so use
`status=all` to see fixed occurrences beside open ones.

## What can resolve a finding

Only a complete scan covering the same scope. Incomplete evidence resolves
nothing and the finding stays open.

| Evidence | Result |
|---|---|
| Complete rescan of the same scope without the finding | Resolved at that scan's time |
| Package removed or upgraded on a scanned asset | Resolved |
| Scan of another asset, source or scope | No change |
| Partial or failed scan, or an incomplete requested scope | No change; `observation_status` becomes `unreconfirmed` |
| `--no-scan`, dry run or skipped vulnerability scan | No change |
| Advisory data outage while the package is still inventoried | No change; `unreconfirmed` with `advisory_data_degraded` |
| Advisory data outage and the package is gone from inventory | Resolved |
| Asset never scanned again | Stays open and `last_seen` ages |

An asset that is decommissioned has no scan to report it clean, so its findings
stay open until an operator declares it: send a complete empty batch with
`scanned_assets` naming the asset. Age on `last_seen` shows stale coverage.

## Ingest paths

**Push** (`POST /v1/results/push`, used by `agent-bom scan --push-url`). A report
replaces earlier reports of the same `source_id` and `target_scope`, the opaque
hash the CLI derives from the scanned targets and collection options. A push with
no target scope is independent evidence: it never resolves anything, because
nothing identifies what it covered. Cloud collectors whose account depends on
ambient credentials are in this group until they send a target receipt.

Status is derived by replaying the retained scans of each scope in evidence-time
order, so late arrivals, replays and multiple workers give the same answer.

**Bulk** (`POST /v1/findings/bulk`, `agent-bom findings push`). A batch resolves
only with `reconcile_absent: true`, only within its `source`, and only on the
assets it names or lists in `scanned_assets`. `reconcile_scope: "source"` widens
that to everything from the source; use it for a report whose findings are per
file, such as SARIF. A `scan_run` receipt that is not complete reconciles nothing
and the response lists why in `reconcile_skipped`. State is stored per tenant in
`hub_findings_current`. See [Evidence ingest paths](INGEST_PATHS.md).

## Exceptions and SLA

Manual exceptions apply at read time and manual SLA assignments carry through
history, so both survive a resolve and reopen.

## Limits

- **Pushed history is bounded by scan retention.** Replay sees retained scans
  (`AGENT_BOM_API_JOB_TTL`, 90 days by default). Once the oldest scan of a
  continuously present finding expires, `first_seen` moves to the oldest retained
  scan unless the producer supplied an earlier one, and a resolved finding leaves
  the list when its scans expire. Bulk findings are stored and have no such limit.
- **The opt-in fast read** (`AGENT_BOM_SCAN_SNAPSHOT_FAST_READS`) loads only
  selected reports, so it serves the current snapshot without replayed status or
  resolved rows.
- **The warehouse findings feed** (ClickHouse and Snowflake) carries `status`,
  `first_seen` and `last_seen` but not `resolved_at`; its table shape is unchanged.
- **Pinned reads** (`scan_id=`) return that scan's rows as reported.
