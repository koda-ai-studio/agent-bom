# ADR-016: Resumable provider trace collection

Status: implemented for managed Langfuse v2 connections.

## Problem

A transient correlation sample cannot establish a durable collection position.
Retries after a worker dies can either duplicate observations or skip a page if
observations and checkpoints commit separately. Provider records also do not
establish workload identity or independently observed execution.

## Decision

Reuse `runtime_observations` and `runtime_sessions`, with additive tenant-bound
checkpoint and replay-receipt tables in the same database. One authenticated
request collects one page. HTTP transport remains outside the database transaction.
A short database transaction claims a 60-second lease; the final transaction
locks and checks that lease before inserting observations, updating session
rollups, enforcing retention, and advancing the provider cursor together.
Lease decisions use the database clock after acquiring the row lock.
A replacement collector has a new token. An expired collector cannot commit.
SQLite serializes claim/commit with `BEGIN IMMEDIATE`; PostgreSQL locks one
connection checkpoint and applies application-role RLS. Different connections
have distinct session identities, avoiding shared rollup updates. No application
pool may bypass tenant RLS. Schema initialization is serialized once per runtime
store instance and cached for the current instance only; status requests do not
repeat bootstrap writes. Replacing the runtime store replaces this cache entry.
No tenant observations or authorization decisions are cached.

Provider source IDs are preserved. Durable identity includes tenant, managed
connection, trace, and span. Matching a tool name remains a correlation candidate,
not proof of execution in an environment. Content, credentials, and provider
cursors are absent from public collection receipts. Only metadata is persisted.

## Windows, replay and limits

Start with a fixed 24-hour window ending 15 minutes before collection begins.
Follow the provider's opaque cursors without changing this window. After the
window completes, overlap the previous 30 minutes on the next request, advancing
at most 24 hours. This accommodates bounded late arrivals; later arrivals and
provider mutations can still be missed. A completed window is not a completeness
attestation. There is no unbounded historical backfill or autonomous scheduler.

A request allows 100 observations, a 2 MB decoded response, a 25-second checked
stream deadline and 10-second socket timeout (5-second connect timeout). A blocked
read can overshoot the checked deadline by its socket timeout. The lease remains
60 seconds. Cursor history is bounded to 1,000 pages per window; replay receipts
are capped at 100,000 per connection. Hitting either limit fails closed and keeps
the checkpoint. Existing runtime retention caps remain authoritative; totals in
the collection receipt count committed insertions, not currently retained rows.
Completed windows discard replay hashes older than the overlap floor. Replay
protection applies to the active window and retained observations, not forever.
Conflicting normalized metadata for a retained source ID rejects the whole page.

## Failure and recovery

There is one provider attempt per request. Operator retries use persisted
exponential backoff, starting at 60 seconds with up to 25% jitter and capped at
one hour. A valid provider Retry-After can extend the delay up to 24 hours.
Authorization, malformed records, unsupported v2 APIs, unsafe endpoints, and
conflicting evidence never trigger a legacy fallback or automatic retry loop.
Fix configuration or provider data before requesting another page.

Bindings are checked before fetching and again before committing. Changing the
endpoint or project public key requires a new connection ID; secret-key rotation
within that scope is supported. Revocation during a network request cannot undo
that request; the post-fetch check prevents committing under a revoked binding
that it observes. Provider-side revocation remains the upstream control.

A successful HTTP command returns a collection receipt, which can report
`status=failed`; clients must inspect that field. Authentication/authorization and
request validation use 4xx, lease/backoff/scope conflicts use 409, and unavailable
storage uses 503. A lost response is recovered with GET status followed by a
retry; a database commit has an atomic outcome even if its acknowledgment is lost.
Never reset a checkpoint to hide a failed attempt.

## Alternatives and rollback

A second event ledger would duplicate retention and explorer behavior. Saving
observations before a separate checkpoint creates a non-atomic recovery boundary.
Holding a database lock through HTTP would let slow providers block other work.
These alternatives are not used.

Migrate PostgreSQL with the existing Alembic path before enabling collection.
Rollback by disabling the managed connection or running the previous application;
the migration is additive. Preserve all three existing/new evidence surfaces and
checkpoints. Downgrade does not delete evidence tables.

## Verification

Run `uv run pytest tests/test_trace_collection*.py -q`. The PostgreSQL contract
requires a migrated disposable database, its non-superuser application URL, and
an audit HMAC key. Without that configuration, the PostgreSQL test skips.
Provider fixtures prove contracts, not live account compatibility. See the
[Langfuse observations API](https://langfuse.com/docs/api-and-data-platform/features/observations-api)
for supported API versions, field selection, cursor semantics, and ingestion lag.
