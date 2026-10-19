# Findings lanes

Open **Findings** to start with Vulnerabilities. Select Cloud config, IaC,
Secrets, Identity, or Data to use that lane's evidence columns. Other retains
runtime, policy, and unclassified findings. All findings is the cross-lane queue
with links to Overview and Investigation. Vulnerabilities shows package versions,
reach/exploit evidence, and remediation by default. Its column preferences are
saved separately from All findings; Reset view restores the selected view.

Tabs show **issue groups**, under the current time window and filters. Package
advisories group their asset occurrences; cloud checks group by provider,
benchmark version, finding type, and control. Expand resource occurrences to
inspect the affected assets. The cloud row displays a representative resource;
use its evidence drawer for investigation. IaC uses repository evidence rather
than a declared cloud provider to identify code-side configuration findings.

A dash means a count is unavailable or refreshing. `≥` marks a bounded lower
count, not a complete total. Severity includes an explicit unrated bucket;
severity-source labels distinguish benchmark mappings, rule severity, and
collector-supplied ratings. Missing source metadata remains unreported.

## Query and export

Use the same tenant credentials as the dashboard:

```bash
curl -H "Authorization: Bearer $AGENT_BOM_API_KEY" \
  'http://localhost:8422/v1/findings?lane=iac&group_occurrences=true&include_facets=true'
```

The JSON response contains findings, pagination, and issue-group lane counts.
Follow `next_cursor` to continue; retain the same lane and other filters.
Available lane keys are `vulnerabilities`, `cloud`, `iac`, `secrets`, `identity`,
`data`, and `other`. Omit `lane` to query all findings. Existing `finding_class`
and posture-domain filters remain independent and intersect with the lane.

For headless use, pass `lane` to MCP `findings_query`. For a downloadable
NDJSON report, submit `{"lane":"iac"}` to `POST /v1/reports`, then follow the
returned job's status and authenticated download link. Reports retain individual
asset occurrences. The Findings page's OpenVEX export also retains its current
lane filter; only eligible triage decisions become VEX statements.

Lane selection and filters are encoded in the page URL. Existing finding,
framework, control, and scope deep links preserve their cross-lane scope unless
a lane is explicitly selected. Lane changes do not change the finding evidence
drawer's triage or control mappings.

Cloud config shows check results separately from severity: `CIS_FAIL` and
`CLOUD_BEST_PRACTICE_FAIL` display **Failed**; their `*_ERROR` counterparts display
**Not evaluated**. These are findings, not an inventory of all evaluated checks.
Passed checks are outside this queue, and an empty queue does not prove a pass.
A failed check is not itself a verdict on every GRC control mapped to it.

## Suppression approval and upgrade behavior

With `AGENT_BOM_DB` set to a SQLite file, exceptions persist across process
restarts. `AGENT_BOM_POSTGRES_URL` selects the shared Postgres store. Explicit
store overrides remain authoritative; configured storage failures propagate
instead of falling back to memory. Restart preserves approval metadata and
pending status; it does not approve a waiver or extend its expiry. SQLite
restart coverage is single-node evidence, not multi-replica qualification.

Create an exception with `POST /v1/exceptions` (fields `vuln_id`,
`package_name`, `reason`, and optionally `expires_at`). The returned
`exception_id` identifies a pending request: findings remain actionable.
False-positive feedback, accepted-risk feedback, triage and VEX imports follow
this same approval boundary. Investigation notes need no approval.

An authenticated admin must separately call
`PUT /v1/exceptions/{exception_id}/approve`, optionally supplying
`{"expires_at":"2026-12-31T00:00:00Z"}` as an example (choose the shortest
appropriate real expiry). Approval requires an exact non-wildcard vulnerability
and package plus a future ISO-8601 timestamp with a timezone. The equivalent MCP
`approve_exception` tool uses the same validation and authenticated admin boundary.

Expiries are bounded: create and approve reject an `expires_at` more than
`AGENT_BOM_EXCEPTION_MAX_EXPIRY_DAYS` days ahead (default 365, accepted range
1-3650) with a 422 (create) or 400 (approve). Approval also enforces four-eyes
review: the principal that requested the suppression cannot approve it (403).
When a triage decision is recorded later (`PUT /v1/findings/triage/{id}/decision`
or VEX ingest), its author is stored as `decided_by` and is also barred from
approving; triage responses keep the original requester in `created_by`.
Shared identities such as a single static API key, an unauthenticated local
server, or a trusted proxy without `X-Agent-Bom-Subject` all resolve to one
principal, so such single-operator deployments must opt out explicitly with
`AGENT_BOM_EXCEPTION_ALLOW_SELF_APPROVAL=1`. The MCP tools return the same
messages as `{"status": "rejected", "error": ...}`.
Review `suppression_active` and `approval_required` on exception responses;
historical `status` alone does not establish current suppression authority.

Approval fails closed if its required authorization audit receipt cannot be
written. The receipt records an authorized attempt; a separate backend write
can still fail, so it is not proof of an atomic cross-store commit. The stored
exception is the activation record. Expired or malformed approvals never hide
findings. Original scan receipts remain historical evidence; current finding
reads re-evaluate stored suppression flags against current tenant approvals.

On upgrade, SQLite adds an approval-generation column automatically. Postgres
operators must run the documented Alembic migration to head before starting the
new server. Existing rows remain in history but require explicit reapproval;
there is no automatic conversion of old active entries. Preserve a database
backup for rollback; downgrading this security boundary would restore older,
less restrictive suppression behavior.

Local `--vex` imports annotate vulnerability assertions but do not authorize
suppression or reduce CI severity gates. Import into the control plane, review
an exact request, and approve it with an expiry before excluding that finding
from actionable posture. VEX exports contain only currently approved decisions.

## Security-discipline counts

`GET /v1/overview` reports open findings per discipline over the same default
read window and current scan selection as `/v1/findings`. AISPM counts classified
AI-posture findings, not inventoried agents, models, or evaluated controls.
Disciplines overlap; their counts must not be added together.

Current bulk-ingested findings are folded into all five lanes in one bounded
keyset pass (at most 200 rows per page), cached at the tenant evidence revision.
The pass uses `AGENT_BOM_SCOPE_FILTER_SCAN_BUDGET` (default 20,000 rows) and
`AGENT_BOM_SCOPE_FILTER_DEADLINE_SECONDS` (default 1.5 seconds). The deadline is
checked between page reads; it does not interrupt a database query in progress.
Each lane carries `evidence_status` (`complete`, `partial`, or `unavailable`) and
`count_exact`. When the read is incomplete, count and severity are lower bounds;
the dashboard labels them accordingly. A complete zero means no open findings in
that discipline, not that the estate has been assessed or is secure. Existing
clients that consume only `count` must also read `count_exact` before treating it
as a total. Missing metadata on older servers means completeness is unknown.

The headline retains its independent current-state severity aggregate when lane
aggregation is partial. Exact domain totals at larger cardinalities require
persisted discipline aggregates; increasing the read budget trades latency for
completeness and does not establish a tested scale guarantee.

## Finding deadlines across rescans

Finding responses and structured exports carry `sla_due_at_source` with the
existing `sla_due_at` value. For findings retained in the compliance hub current
state, `severity-kev/v1` identifies the built-in severity
window (critical 7 days, high 30, medium 90, low 180), anchored to the persisted canonical
finding's earliest observation within its tenant. The built-in policy retains
a known earlier KEV target. Rescanning a hub finding does not restart that window; severity changes
recalculate it from the same earliest observation. Without a usable first
observation or KEV deadline, the date is null and the source is `unavailable`.

The current scan-job findings view selects the latest successful snapshot for
each scan target scope, including an empty snapshot that retires absent rows.
For each remaining finding, it uses the earliest valid first observation in
retained jobs with the exact tenant, scan scope, canonical finding ID and
environment. Changing the display window does not restart that retained
observation or its derived deadline. An explicit `scan_id` request preserves
that individual snapshot's dates. Missing dates or canonical identities are
not reconstructed from job completion times, display names or unrelated assets.

This read reuses the existing tenant job history; it does not persist an
independent lifetime record. The default 90-day job TTL, 200-job in-memory
limit, configured tenant quota and explicit deletion can remove older
observations. The resulting first observation is therefore limited to retained
evidence. Increasing retention cannot restore deleted history. Use durable
storage and an evidence retention policy appropriate to the required SLA
history; the compliance hub retains its own current-state lifecycle separately.

An explicitly supplied `Finding.sla_due_at` is marked `explicit`; this identifies
the input origin, not evidence of human approval. Rescans retain
it until another explicitly marked assignment is supplied. This is a model and
integration input, not an individual-finding deadline editor in the dashboard.
Campaign deadlines remain independently editable through **Remediation → Edit
owner and SLA**, the campaign workflow API, CLI, and MCP update command. These
assignments do not rewrite individual finding policy.

Historical non-null dates without recognized provenance remain `unknown` and
are retained. The store copies extant unknown assignments forward before
replacing their ledger payload; it never infers a source by comparing dates or
reconstructs assignments already overwritten before this change. Unknown source
values are not proof that an operator approved a deadline. Existing JSON payload
storage carries this additive metadata without a database-column migration.
