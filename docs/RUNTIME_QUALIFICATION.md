# Qualify collector and analytics behavior

Run qualification against disposable infrastructure and keep each JSON receipt
outside the source tree. A successful bounded run describes that OS, permission
context and workload; it does not establish universal support or production
capacity. Failed receipts remain useful and are never overwritten.

## Native endpoint collectors

```bash
uv run python scripts/qualify_endpoint_collectors.py --output /tmp/endpoint-qualification.json
```

The receipt records actual host OS, package version, source/harness provenance,
per-collector status and counts. It excludes application/process rows, usernames,
service names, arguments and raw error text. Four core collectors must execute;
permission-denied/unavailable core collectors fail the check. Partial collection
stays partial. Optional container/image collection may be unavailable, and
`all_collectors_complete` remains false. A container without a service manager
cannot establish host service coverage.

The harness opens an owned loopback TCP listener during collection and requires
its discovery, so an idle host still has a known listener to inspect. Command
receipts retain executable names, status and exit codes, excluding arguments and
command output. The default command deadline is five seconds; use
`--timeout-seconds 30` for a separately recorded longer-deadline run.

The endpoint CI matrix uses a 30-second command deadline on Linux, macOS and Windows,
retaining receipts even on failure. Inspect the receipt and runner permissions
before treating a packaging result as collector qualification. A passing run at
30 seconds does not qualify the normal five-second collector deadline.

## Optional ClickHouse analytics

Start a disposable loopback ClickHouse server using the image version in
`deploy/supabase/clickhouse/docker-compose.yml`. Configure its local user secret
through `AGENT_BOM_CLICKHOUSE_ACCESS_TOKEN`, then run:

```bash
uv run python -m scripts.qualify_clickhouse_analytics \
  --url http://127.0.0.1:8123 --output /tmp/clickhouse-qualification.json
```

This creates a uniquely named database, uses real HTTP/SQL for concurrent
synthetic writes, reopens the client, replays events/findings, and checks
tenant-filtered public reads. The receipt records pass/fail and latency
percentiles. It is application query isolation evidence, not a claim that a
database administrator is tenant restricted. The database remains for inspection;
remove the disposable instance through its normal lifecycle after retaining the
receipt. SQLite/PostgreSQL remain authoritative; this does not add replication or
move control-plane state into the analytics sink.

## API and durable collection workloads

The existing `scripts/run_runtime_capacity_qualification.py` drives separate
HTTP API processes and real SQL. `scripts/run_trace_collection_qualification.py`
uses synthetic provider pages with real SQL through ASGI. Both require
`AGENT_BOM_EXPERIMENTAL=traces`; PostgreSQL additionally requires a migrated
disposable application-role database, its maintenance URL and an audit HMAC key.

```bash
AGENT_BOM_EXPERIMENTAL=traces uv run python -m scripts.run_trace_collection_qualification \
  --backend sqlite --workers 3 --pages 10 --rows 100 --output /tmp/trace-qualification
```

Inspect `receipt.json` and retained attempts before comparing runs. Fixture
replay/throttling/recovery tests do not verify a live Langfuse or LangSmith
account. Provider credentials, deployed infrastructure and real investigations
need separate evidence; synthetic workloads do not establish adoption or
verified remediation in a user environment.
