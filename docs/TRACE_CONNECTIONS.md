# Managed trace connections

> **Experimental.** Trace pull, trace collection and trace findings are off by
> default. Enable them on the control plane with `AGENT_BOM_EXPERIMENTAL=traces`.
> See [EXPERIMENTAL.md](EXPERIMENTAL.md).

Use **Connections → Observability & SIEM** to select an operator-configured Langfuse
or LangSmith project and import a bounded window of native observations. **Traces → Connect
platforms** opens the same hub. The browser sends a connection ID using the
existing Agent-Bom session; it does not receive provider credentials.

Agent-Bom SSO authenticates the user to the control plane. Provider authorization
is separate: these trace APIs use project/API keys. This adapter does not turn
a provider's dashboard SSO session into API access. Cloud connections retain their
existing role-assumption, workload-identity, and supported OAuth flows.

## Configure once, select on each use

The control-plane operator provisions scoped provider credentials in the existing
secret source (mounted files preferred). Do not put secrets in the binding JSON,
Git, UI URLs, tickets, or shell history. No new database credential store is used.

1. Mount a credentials JSON file from the deployment's secret manager. Langfuse
   requires exactly `public_key` and `secret_key`; LangSmith requires `api_key`.
   Set a reference such as `TRACE_PRODUCTION_CREDENTIALS_FILE` to its mounted path.
   The existing secret resolver prefers the `_FILE` variant over the environment
   value. Restrict file access to the control-plane service account.
2. Mount a binding file and set `AGENT_BOM_TRACE_CONNECTIONS_FILE` to its path:

   ```json
   {
     "production-traces": {
       "tenant_id": "tenant-a",
       "provider": "langfuse",
       "display_name": "Production traces",
       "endpoint": "https://cloud.langfuse.com",
       "credentials_env": "TRACE_PRODUCTION_CREDENTIALS",
       "enabled": true,
       "expires_at": "2027-01-01T00:00:00Z"
     }
   }
   ```

   Choose an expiry appropriate to the deployment. For LangSmith, set
   `provider` to `langsmith`, use its regional API endpoint, and add `project`
   with the exact project name. Public HTTPS validation still applies. The
   endpoint and project are bound by the operator and cannot be overridden in
   a managed pull request.
3. Start the configured API with `agent-bom api`, sign into the dashboard, then
   open **Connections → Observability & SIEM** and select the connection. A configured
   entry is not proof of provider access. **Pull and correlate** checks access
   and returns native observation, update, replay and rejected-row counts. It requires `runtime.ingest`.

For Helm, use `controlPlane.api.env`, `envFrom`, `extraVolumes`, and
`extraVolumeMounts` to supply these references and read-only secret mounts. For
Docker, mount the same files read-only and provide their `_FILE` references.
Neither path requires embedding provider keys in chart values or image layers.

## Rotation, revocation, and failure behavior

Bindings and secret files are read on every use. Update the mounted secret to
rotate a key. Disable/remove the binding or let its expiry elapse to stop new
pulls; revoke the upstream key for provider-side revocation. These changes do not
cancel a provider request already in flight. Environment-only secret changes
require a process restart.

Tenant/provider mismatch, missing or expired bindings, unavailable secrets, and
malformed configuration fail closed. There is no ambient credential fallback.
The audit records managed connection use with actor, tenant, provider, and
connection ID; this records credential use, not provider success.
Connection listings contain only tenant-visible IDs, labels, and providers;
secret references and plaintext are never returned. Request errors are generic.
Only control-plane operators can edit the binding configuration. Anyone with
`runtime.ingest` in the bound tenant can use its configured trace connections;
per-connection user grants are not implemented.

The advanced temporary-credentials form remains available for one-shot testing.
Content screening is off by default. Provider responses may still contain input
or output content; disabled screening excludes outputs from the adapted evidence.
Temporary-credential pulls are transient. Managed-connection pulls persist native
observations and append content revisions to the runtime store. Replaying a span
preserves its identity and does not increment session counts again. Collection
time alone does not create a revision. Revisions are collector-controlled history,
not independent or tamper-proof audit evidence; a newly collected revision is not
proof of the provider's latest state. Projection retention does not erase replay
identity or revision history. Revision history currently requires operator-managed
storage capacity; no automatic history-pruning policy is provided.

The SQLite-to-PostgreSQL registry importer supports legacy runtime observation
and session groups. It rejects sources containing native revisions, trace import
state, collection checkpoints, or replay receipts before opening the target.
These records require a full source database backup; importing only current
observations would lose history and replay protection. Native trace history
migration across backends is not supported by this importer.

## Upgrading existing collection

Existing collection checkpoints retain their resume cursor when connection scope
is unchanged. Adding account, environment, cloud or project bindings requires a
new connection ID; do not reset the old checkpoint to bypass the conflict.
Older tool-only observations remain available as legacy evidence. They lack the
canonical project/scope fields needed to merge safely into native span history,
so the first native import can add a separate record for the same provider span.
Replay deduplication applies within each identity format, not across that upgrade.

## Local session history providers

`claude-code-sessions` and `codex-sessions` appear in the connector list with
kind `local_session_history`. They map local coding-agent history to the same
span shape for `agent-bom activity` and the `agent_activity` MCP tool, and the
pull route rejects them with a 400. See
[MCP_AUDIT.md](MCP_AUDIT.md#review-what-your-coding-agents-actually-did).

## Import, resume, and inspect

With the authenticated control-plane session, POST to
`/v1/traces/connectors/langfuse/pull` (or `langsmith`) with:

```json
{"connection_id":"production-traces","limit":50,"max_pages":3,"screen_content":false}
```

The response contains an `import_id`, fixed window, completion flag, scope and
request-scoped counts. Repeat with the same `import_id` to resume at the committed
cursor. Optional `window_start` and `window_end` select a timezone-aware window of
at most 31 days on the first request. Completed imports do not fetch again; start
a new import to collect provider updates. Page failures retain prior evidence and
the last committed cursor. Native HTTP reads, including project resolution,
stream at most 2,000,000 decoded response bytes into the JSON buffer and reject
oversized responses as a whole. HTTP error bodies are not read. A 25-second
elapsed-time check runs at headers and between transport chunks; an in-flight
read is bounded separately by the 20-second socket timeout, so this is not a
hard 25-second end-to-end deadline. Rejected rows keep coverage partial even when every
page was traversed. Provider pagination does not guarantee an immutable source.

When a managed import returns a retryable `import.error`, inspect its optional
`retry_after_seconds` and wait at least that long before resuming the same
`import_id`. Native readers parse provider `Retry-After` seconds or HTTP dates,
bounded to 24 hours; missing or malformed headers omit this field. Apply client
backoff when no delay is supplied. The pull request does not sleep or retry
automatically, and a failed page never advances the committed checkpoint.

Open **Traces** for native kinds, physical parents, missing-parent notices and
collection revisions. `GET /v1/runtime/observation-revisions?observation_id=...`
reads paged, tenant-scoped history. SQLite and PostgreSQL store observations,
revisions, session counters and page checkpoints in the same transaction.

The trace explorer accepts exact `source`, `session_id`, `agent_name` and
`connection_id` filters, plus `limit` (1–200) and `offset`. Filtering happens
before pagination. `retained_total` and `source_counts` describe matching retained
observations at query time, not total provider history. Concurrent collection can
change these live counts between pages. The gateway feed appears only on the
first unfiltered page; it is separate from the retained-observation total.


## Exact inventory identifiers

A managed connection may specify `cloud_provider`, `account_id` and `environment`
when those values are known and restricted by the operator. Instrumented native
observations can report `metadata["agent_bom.inventory_node_id"]` (LangSmith uses
`extra.metadata`) containing an exact canonical inventory node ID. Names are
never substituted for IDs.

`GET /v1/runtime/trace-explorer?scan_id=SNAPSHOT` checks these claims against a named
snapshot. Every recorded cloud/account/environment field must agree. Missing or
conflicting scope, absent nodes and snapshots changed during lookup produce no
entity link. The response identifies the exact snapshot generation used. This is
a source-reported identifier association: it does not authenticate the workload,
prove invocation or downstream effects, establish current permission, or prove
exploitation. Imported spans do not inherit findings through display-name matches.
Legacy tool-name correlation results remain explicitly labeled candidates.

If inventory records a normalized cloud resource ID or location, reported cloud
identifiers must also agree with those values. Version or alias resolution is not
inferred to make different identifiers match.

Sources can additionally pin `agent_bom.inventory_scan_id` and
`agent_bom.inventory_generation`; a mismatched pin yields no entity link. For an
exact match, the explorer returns up to ten recorded inventory paths to
vulnerabilities, following only directed uses, dependency, containment and
vulnerability relationships. Traversal is bounded to four hops, 500 nodes,
1,000 edges and a 500 ms store deadline. Returned paths carry node/edge IDs and
the snapshot generation; truncation is disclosed. These paths do not prove that
the span executed the package, exploited the finding or completed a downstream
action. Inspect the pinned graph and its source receipts before making those
claims.


Contract tests: [broker boundaries](../tests/test_trace_connection_broker.py),
[content consent](../tests/test_trace_pull_screen_content.py), and
[browser workflow](../ui/e2e/trace-platform-connectors.spec.ts).

## Normalized events, graph evidence and findings

Every trace source maps into one canonical, metadata-only event
(`agent_bom.runtime.normalized_trace.NormalizedTraceEvent`) before storage:
Langfuse observations, LangSmith runs and OTLP JSON spans (OpenTelemetry GenAI
attributes such as `gen_ai.operation.name`, `gen_ai.agent.name`,
`gen_ai.tool.name`, `gen_ai.request.model` and `gen_ai.usage.input_tokens`).
The tenant comes from the connection or request, never from span attributes.
User IDs are stored only as a tenant-scoped HMAC-SHA256 (`h1:`) keyed from the
primary `AGENT_BOM_AUDIT_HMAC_KEY`; without that key the digest is derived from
the tenant ID alone, carries the `h1w:` prefix and is counted as
`weak_principal_hashes` in coverage and in the graph analysis status. Rotating
the primary key changes digests for later events. Prompt and output text are
kept only as a SHA-256 digest, URLs only as scheme and host, local filesystem
paths only as a `<path:basename>` label (never as resource references), and
`agent_bom.credential_ref` only when it is a credential name. LangSmith
timestamps without an offset are read as UTC, as the LangSmith SDK does; other
sources must send timezone-aware timestamps. Fields a source cannot supply stay empty and
are counted per source in the `normalized.coverage` block of
`POST /v1/traces` and managed pull responses.

The OTLP cost and tool-call readers also accept current
`gen_ai.provider.name` and `gen_ai.tool.name` attributes, preferring them over
legacy `gen_ai.system` and `tool.name` values. Explicit tool, agent, workflow,
retrieval and memory operations are not counted as model inference calls.
Legacy ADK span names remain supported. This is OTLP JSON metadata support;
it does not establish protobuf/gRPC receiver compatibility or provider delivery.
See the [OpenTelemetry GenAI conventions](https://github.com/open-telemetry/semantic-conventions-genai/blob/main/docs/gen-ai/gen-ai-spans.md).

When a scan snapshot is persisted, events from the 30 days before the snapshot
timestamp become `runtime_observed` graph edges (`invoked`, `called`,
`accessed`, `used_credential`) aggregated per source node, relationship and
target with a count, first and last observation, trace sources and up to five
sample trace IDs. Only spans carrying an exact inventory node ID or canonical
ID bind; a credential binds only through the exact `cred:<server>:<NAME>` slot
of a bound server. Name-only matches are counted as candidates and never become
edges. The `runtime_trace_projection` analysis status reports bound, candidate,
unmatched, out-of-window, untimed and rejected counts; a store outage is
recorded as `failed`, not as zero activity. Attack-path ranking and credential
reach read these edges; they show recorded activity, not exploitation.

Screened prompt-injection, personal-data and credential signals, and agents or
tools named in spans with no exact or candidate inventory match (`SHADOW_AI`),
become findings in the tenant's
compliance hub, linked to the exact node when one was reported and deduplicated
per tenant, signal, entity and UTC day.

## Langfuse API compatibility

Langfuse pulls request native observation types through Observations API v2.
Managed imports default to a fixed 24-hour window and follow provider cursors. Metadata is requested explicitly; input/output
fields are requested only with content screening enabled. Traversal completion describes the requested window, not complete project history. Only a missing v2 route (HTTP 404) falls back
to the v1 endpoint for older self-hosted instances. Authorization errors, rate
limits, HTTP 410, and server failures remain visible errors. The legacy API can
return content even when the adapter excludes it from evidence.

See the [Langfuse public API contract](https://langfuse.com/docs/api-and-data-platform/features/public-api).

## Save and resume Langfuse evidence

Select a managed Langfuse connection, then choose **Incremental collection and saved progress → Collect
next page**. The receipt shows cumulative saved observations, committed pages,
collection progress, and retry delays. Open **Trace explorer** to inspect retained
observations. Each request imports at most 100 metadata-only native observations;
collection runs only when requested. Both managed Langfuse and LangSmith window
imports also persist native observations. Incremental collection and window imports
share stable IDs and revision history, so overlapping reads do not inflate session
counts. Temporary-credential previews remain transient. The collection receipt
counts newly inserted observations from that collection, not all retained rows.

For an authenticated API client, POST a body such as
`{"connection_id":"production-traces"}` to
`/v1/traces/connectors/langfuse/collect`. Inspect the returned `status`:
`partial` means request another page; `caught_up` means that selected time window
has been collected; `failed` requires inspecting `last_error` and waiting
`retry_after_seconds` before retrying. GET
`/v1/traces/connectors/langfuse/collection?connection_id=production-traces`
recovers status after a client disconnect. Both endpoints require runtime ingest
permission; provider credentials and cursors remain server-side. They do not
accept endpoint, cursor, content, or tenant overrides.

Each API worker admits at most two collection requests at once, reduced to one
when `AGENT_BOM_WORKER_THREAD_LIMIT` is two or less. Waiting collection requests
do not occupy shared worker threads; deployments with at least two threads leave
capacity for status and other requests. At most eight additional collections
wait per worker. Further requests receive HTTP 429 with `Retry-After: 1` before
claiming a lease or contacting the provider. Retry after that delay and inspect
saved status. A disconnected admitted request retains its slot until its worker
finishes; its page and checkpoint still commit or roll back together. This is
request admission, not background scheduling or a latency guarantee.

The first window covers the previous day with a 15-minute ingestion delay.
Subsequent completed windows overlap 30 minutes, with bounded replay deduplication.
Missing older observations, provider mutations, and late arrivals beyond this
window remain coverage gaps. Imported tool names may produce correlation
candidates; they do not prove cloud workload identity or exploitation.

For operators, [ADR-016](decisions/016-resumable-trace-collection.md) specifies
atomicity, leases, retention, HTTP and storage limits, failure behavior, migration,
and rollback. Private hosts remain unsupported for pull; use the existing OTLP
collector route for private deployments.

For crash recovery, lost acknowledgments, concurrent lease claims, and bounded
tenant-load checks, run the [collection qualification](perf/trace-collection-qualification.md).


## Cloud request identifiers

Native Langfuse metadata and LangSmith `extra.metadata` can retain the bounded
OpenTelemetry keys `cloud.provider`, `cloud.account.id`, `cloud.region`,
`cloud.resource_id`, `faas.invocation_id`, `faas.version`, `aws.request_id`,
`rpc.service` and `rpc.method`. Inspect **Traces → Cloud identifiers** for these
source-reported claims. Credentials and request/response bodies are excluded;
invalid or conflicting cloud identifiers prevent an inventory link.

SDK request IDs and Lambda invocation IDs remain distinct. Function ARNs retain
version or alias qualifiers; aliases are not resolved to versions by name.
A retained span or end timestamp does not prove successful function execution,
a downstream effect, or caller identity. Independent provider execution and
downstream event receipts are still required; managed traces do not collect
Lambda data events or provide that independent correlation automatically.


## Name-based vulnerability candidates

POST OTLP spans to `/v1/traces` and inspect `flagged[].correlation_basis`.
A `candidate_name` result compares tool, server or package names with scan
inventory; it does not establish a package version, inventory relationship or
successful exploitation. These candidates are response-only: they do not create
runtime findings, analytics observations or vulnerability signals on graph edges.
Even an exact tool inventory ID does not prove which package that tool exercised.
Verify the tool-to-package inventory relationship and advisory before treating a
candidate as runtime vulnerability evidence. Trace explorer and span correlation
use the same candidate matcher; an agent-only finding cannot match an arbitrary
tool call. Screened content signals and exact inventory trace edges retain their
separate evidence contracts. Existing stored snapshots and audit records are
preserved; this behavior applies to newly ingested traces.

## Persisted runtime activity in the graph

Authenticated `POST /v1/ocsf/ingest` and gateway activity ingestion persist
metadata for the request tenant. Rebuild a scan graph after ingestion to include
records within its evidence window. The exported graph contains
`recorded_activity` edges and a `runtime_activity_projection` analysis receipt.
This overlay includes stored runtime, proxy and gateway observations and does
not require the experimental trace-provider opt-in.

An OCSF producer may supply exact inventory references in
`unmapped["agent_bom.agent_ref"]` and
`unmapped["agent_bom.inventory_node_id"]`. Cloud bindings also require the
matching `cloud.provider` and `cloud.account.uid`. Native actor/resource IDs and
display names are not automatically treated as inventory IDs. Inspect the edge's
source receipts and unverified resource shadows before relying on a binding.
A recorded allow or deny decision does not establish completed execution or
permission; these edges are excluded from attack-path traversal.

One inclusive UTC window and 20,000-event budget cover both persisted stores.
The analysis receipt reports truncated loads, unavailable stores and rejected
bindings. A failed store preserves the other store's evidence. Receipts contain
allowlisted metadata only; prompts, arguments and results are not projected.
See [runtime failure behavior](RUNTIME_FAIL_MODES.md#graph-evidence-reads).
