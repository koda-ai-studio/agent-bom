# Current capabilities, coverage, and contributor roadmap

This page describes repository behavior and contribution opportunities. A merged
capability is not necessarily available in the latest package release. Check the
[release notes](https://github.com/koda-ai-studio/agent-bom/releases) and the
[CI workflow](../.github/workflows/ci.yml) for the revision you use.

**Implemented** means there is a code path and an owning contract test.
**Fixture-tested** means deterministic inputs exercise that path; it does not
establish compatibility with every provider account, SDK version, or deployment.
**Planned** means the behavior is not yet implemented. No delivery date is implied.

## Current product surfaces

| Surface | Implemented path and artifact | Coverage evidence | Boundary |
|---|---|---|---|
| Scan and reports | CLI scans produce inventory, findings, SBOMs, SARIF, HTML, and graph exports | [CLI/report contracts](../tests/test_cli_report_query.py), [output characterization](../tests/test_output_render_characterization.py) | Offline demos validate local behavior, not live provider access or vulnerability-feed freshness |
| Inventory and findings | Tenant-scoped API reads and dashboard investigation | [Inventory tests](../tests/test_inventory_assets.py), [API finding wiring](../tests/api/test_api_scan_findings_wiring.py) | Discovery, assessment, and runtime observation are separate coverage claims |
| Graphs | Persisted graph projections, asset context, and finding paths | [Graph package](../src/agent_bom/graph/), [graph contracts](../src/agent_bom/api/graph_contracts.py) | A graph edge represents its recorded evidence; it is not proof of exploitation |
| MCP | Tool discovery and strict argument validation | [MCP argument contracts](../tests/test_mcp_strict_args.py), [capability manifest](AGENT_CAPABILITY.md) | Tool availability does not imply configured cloud credentials or access |
| Runtime | Proxy/gateway decisions, durable activity, runtime profiles, Shield content checks | [Runtime reference](RUNTIME_REFERENCE.md), [failure modes](RUNTIME_FAIL_MODES.md), [browser acceptance](../scripts/demo/runtime_browser_acceptance.mjs) | Authenticated submission is distinct from independently verified producer identity |
| Dashboard | Runtime preview, Live Activity, trace review, inventory/findings/graph navigation | [Activity tests](../ui/tests/gateway-activity-panel.test.tsx), [browser regression](../ui/e2e/runtime-profile-activity.spec.ts) | Visible summaries describe a bounded received window; retained history is separate |
| Self-hosted deployment | Docker and Helm control-plane/runtime profiles | [Helm chart](../deploy/helm/agent-bom/), [replica safety](../tests/test_helm_replica_safety.py), [Postgres portability](../tests/test_helm_postgres_portability.py) | Local rendering, cluster acceptance, and a customer deployment are different evidence levels |

For provider-specific collection and assessment boundaries, use the maintained
[vendor coverage matrix](VENDOR_COVERAGE.md). For code ownership and dependency
rules, start with [the code map](CODE_MAP.md).

## Incremental behavior already implemented

Incremental collection is not a product-wide gap. The gateway activity ledger
already provides tenant-scoped cursors, replay deduplication within its retained
window, bounded retention, and explicit expired-cursor handling. The browser
resumes from the last complete batch and keeps a bounded event buffer. See the
[ledger](../src/agent_bom/api/gateway_activity_store.py),
[stream client](../ui/lib/gateway-activity.ts), and
[activity regression tests](../ui/tests/gateway-activity-panel.test.tsx).
NVD synchronization also has checkpointed incremental updates and failure
recovery [tests](../tests/test_db_sync_nvd_incremental.py).

The missing incremental path below is specifically **Langfuse/LangSmith pull**.
Reuse the established cursor, tenant, replay, and retention contracts when adding
provider collection state; do not introduce a second conflicting event ledger.
A workload with thousands of daily events needs measured burst throughput,
backlog recovery, storage growth, and query latency. Daily volume alone is not a
capacity benchmark.

## Trace and framework integration coverage

| Integration | Current behavior | Contract coverage | Known limit |
|---|---|---|---|
| OTLP JSON | `POST /v1/traces` parses tool-call evidence; recognized GenAI spans feed model/cost analysis | [OTLP parser tests](../tests/test_otel_ingest.py), [trace API tests](../tests/test_trace_attack_path_routes.py) | JSON support is not an OTLP/gRPC receiver; missing timing, identity, or nesting is not reconstructed |
| Langfuse pull | Public HTTPS observations API → tool spans → tenant finding correlation; content retrieval is optional | [Connector tests](../tests/test_trace_connectors.py), [content opt-out tests](../tests/test_trace_pull_screen_content.py) | Bounded, one-shot legacy observations API; no continuous cursor, full observation tree, or explorer persistence. Explicit non-tool observations are excluded; untyped legacy observations retain the existing tool mapping |
| Langfuse export | Runtime span attributes support Langfuse-compatible OTLP with secret-field redaction | [Export attribute tests](../tests/test_langfuse_otel.py) | Attribute compatibility is not proof that a remote collector accepted the export |
| LangSmith pull | Project name resolves to a project ID before querying tool runs; trace ID remains separate from project ID | [Connector scope tests](../tests/test_trace_connectors.py) | Uses the existing runs-query API and one bounded response; live account and newer API-version qualification remain open |
| LangChain / LangGraph | Tool spans and recognized GenAI/framework span conventions can enter through OTLP or LangSmith | [Parser](../src/agent_bom/otel_ingest.py), [parser fixtures](../tests/test_otel_ingest.py) | No claim of complete checkpoint, branching, retry, or human-interrupt reconstruction |
| Trace explorer | Bounded runtime observations and feed events, with agent/tool finding matches | [Explorer tests](../tests/test_trace_explorer.py), [UI explorer](../ui/components/trace-explorer-panel.tsx) | Agent grouping is not an exact trace tree. Pull results are not saved here. Scan-specific attribution and complete parent/child navigation are not implemented |

### Try the paths

1. Run `uv run agent-bom scan --demo --offline -f json -o scan.json` to inspect
   a local inventory/findings artifact. Use a configured control plane with your
   own scan evidence for meaningful runtime correlation.
2. In **Runtime**, open **Live Activity**. Select an event to inspect its receipt,
   policies, and available trace context. Search and filter the received window,
   page through matching events, or switch to **By agent** for scoped counts.
   Paging pauses the view while collection continues. **Agent traces** matches agent identity
   in a bounded sample; it does not assert a shared trace ID.
3. In **Traces → Connect platforms**, choose Langfuse or LangSmith and provide
   credentials for a public HTTPS endpoint. Credentials are used for that request;
   the form does not save them. Content retrieval starts off. Inspect the returned
   finding links. These pull results are not persisted into the explorer.
4. For collector-driven input, use **Traces → OTLP ingest** to validate an export,
   or send authenticated OTLP JSON to `POST /v1/traces`. Private platform hosts
   are rejected by the pull connector's SSRF guard; use a collector instead.

A zero-match result means no known finding matched the supplied evidence. It
must not be presented as a clean security verdict or complete scan coverage.

## Contribution roadmap

These are **planned tasks**, not shipped capabilities. Before starting, search
[open issues](https://github.com/koda-ai-studio/agent-bom/issues) and comment on
an existing issue, or open a scoped proposal referencing the task below. Include
the provider/SDK versions, expected artifact, and a minimal sanitized fixture.
Never attach production credentials, prompts, customer traces, or private keys.

| Priority / task | Starting point | Acceptance criteria |
|---|---|---|
| P1 — Live platform qualification | `trace_connectors.py`, connector/API tests | Opt-in integration tests for supported Langfuse/LangSmith versions; success, 401/403, 429, malformed response, project isolation, empty versus incomplete results; sanitized fixtures without real content |
| P1 — Current provider API adapters | Existing pull connectors | Langfuse observations v2 and LangSmith query-version compatibility behind explicit contracts; bounded pagination, timeout/retry policy, no silent broadening of project scope, migration docs |
| P1 — Incremental provider collection | Existing pull connectors and gateway/runtime storage contracts | Durable per-tenant provider cursors, overlapping-window replay deduplication, bounded backfill, restart and rate-limit recovery; preserve checkpoints on partial failure; measure burst throughput, lag, storage, and query latency |
| P1 — Persist imported trace evidence | `api/routes/observability.py`, runtime event store | Tenant-scoped stable trace/span/source IDs, replay deduplication, pagination receipts, retention limits, authorization tests, and visible persisted versus transient results |
| P1 — Exact trace navigation | `api/trace_explorer.py`, `trace-explorer-panel.tsx` | Server-side trace filtering; preserve actual parent IDs; distinguish sessions, traces, and spans; handle missing parents, replay, cycles, and multiple agents without inventing nesting |
| P2 — Framework compatibility fixtures | `otel_ingest.py` and parser tests | Versioned LangChain/LangGraph exports covering tools, LLMs, retrieval, branches, retries, and interrupts; expected correlation and unsupported fields documented |
| P2 — Stronger correlation provenance | `runtime_correlation.py`, graph projections | Explain which recorded tool/server/package/identity fields matched; disambiguate shared tool names; do not promote inferred links to observed execution |
| P2 — Operator diagnostics | Connector and runtime UI | Provider status, last successful collection, lag, sampled/partial indicators, and retry actions without displaying raw exceptions or secrets |
| P2 — Broader collection coverage | [Vendor matrix](VENDOR_COVERAGE.md), `cloud/` | One explicit collection or assessment gap per change, denied-versus-empty tests, live opt-in qualification, and an updated owning coverage generator |
| P2 — Architecture and generated contracts | [Code map](CODE_MAP.md), API/UI schema generators | Reduce oversized modules and handwritten duplicate types while preserving contracts and lowering, never raising, architecture baselines |

For a first contribution, add one sanitized parser fixture, improve one empty or
failure state, or qualify one documented provider version. Larger persistence or
authorization changes should start with an issue describing the data contract.

## Keeping coverage accurate

When a task lands, update its row in this page and the owning contract test in the
same PR. Record supported versions and limitations in operator documentation.
Use owning generators for provider matrices, API schemas, capabilities, and
screenshots. A test filename is a reproducible verification entry point, not a
claim that its latest run passed: link the exact PR CI when proposing a change.
