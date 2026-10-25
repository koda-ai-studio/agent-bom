# Historical trace-window reads

The graph loader applies tenant, surface and inclusive UTC bounds before its
20,000-event budget. It uses `(timestamp, observation_id)` keyset pages and one
extra record to determine truncation. It does not issue retained-history count
queries. Offset pagination is no longer part of this read path.

## Local PostgreSQL measurement

Measured 2026-10-25 with Python 3.13 and PostgreSQL 16.15 (Linux ARM64, local
Docker tmpfs), using a non-superuser role without `BYPASSRLS`. The table had the
production primary key and tenant/session/time index, with forced tenant RLS.
This is a synthetic, single-client storage measurement, not a deployment or
concurrent capacity qualification.

Each dataset contained 501 matching observations dated October 15 and the
remaining observations dated October 25. The requested window was October 1–20.
Every load returned the same 501 identities, with `limited=false`, in two page
queries and zero count queries. Three consecutive samples:

| Retained observations | Load times (seconds) | Median (seconds) |
|---|---|---|
| 100,000 | 0.3651, 0.3452, 0.3436 | 0.3452 |
| 1,000,000 | 3.4434, 3.7004, 3.5016 | 3.5016 |

The former loader consumed its budget on newer rows before reaching this
historical window. Regression tests reproduce that loss with a smaller budget.
The measured implementation fixes window correctness and removes repeated
counts and offsets. It still parses retained timestamps during selection;
these numbers do not establish constant-time indexed lookup. A persisted UTC
timestamp index is a further optimization to evaluate with migration evidence.

## Reproduction contract

Use a disposable PostgreSQL database with `runtime_observations` as defined in
`deploy/supabase/postgres/runtime-schema.sql`. Insert 100,000, then 1,000,000
unique observations for one fixture tenant, all with
`surface="normalized_trace"`. Rows 1–501 have
`observed_at="2026-10-15T00:00:00Z"`; the remainder have
`observed_at="2026-10-25T00:00:00Z"`. Each JSON payload contains the matching
tenant/id/session/timestamp and a `metadata.normalized` object with the tenant
and unique `source_span_id`. Run `ANALYZE runtime_observations` after each seed.

Under the application's tenant context, time three calls to
`load_window_events(store, tenant, window_start="2026-10-01T00:00:00Z",
window_end="2026-10-20T00:00:00Z")`. Assert the exact returned identity set is
1–501 and the limited flag is false. Count calls to `window_observations`; each
load must make two. Seed outside normal retention APIs so the intended retained
row count is preserved. Remove the disposable database after retaining results.

Additional contracts cover equivalent timezone offsets, microsecond boundaries,
tied timestamps, mixed surfaces, tenant rejection, application-role RLS and
capped empty results: `tests/test_trace_window_selection.py`,
`tests/test_trace_collection_postgres.py`, and `tests/test_trace_graph_evidence.py`.
