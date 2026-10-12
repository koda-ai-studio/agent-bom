# Qualifying runtime and recorded-access fixtures

Run this bounded suite from a source checkout with the development and API
extras installed. Save the report outside the checkout:

```bash
uv run pytest -q \
  tests/test_execution_effect_qualification.py \
  tests/test_native_cloud_trace_claims.py \
  tests/test_native_trace_import.py \
  tests/test_gateway_auth_tenant_e2e.py \
  tests/graph/test_remediation_receipts.py \
  tests/test_trace_collection_failures.py \
  tests/test_trace_collection_recovery.py \
  --junitxml=/tmp/runtime-fixture-qualification.xml
```

Inspect the test outcomes and skips in the XML report. The gateway fixture
forwards through the ordinary HTTP relay to a task-local synthetic target. The
target records attempts separately from effects. A no-op completes without an
effect; an allowed order lookup records a synthetic read; a denied administrative
action never reaches the target. Recreating the gateway with a scoped policy
change blocks later lookups, leaves the allowed no-op usable, and preserves prior
target receipts. The test harness controls both the gateway and target, so this
is local execution evidence, not independent provider evidence.

| Source or scenario | Qualification | Boundary |
| --- | --- | --- |
| Gateway allow/deny and policy change | Real loopback upstream HTTP with a synthetic target and real tenant keys | Proves the tested mediated route; unmediated paths remain outside enforcement |
| Lambda Invoke outcome | CloudTrail-shaped fixtures through the AWS outcome normalizer | Accepted is not completed; HTTP 200 alone does not prove function success or downstream effect |
| Native Langfuse/LangSmith cloud claims | Adapter, scoped import, durable replay and explorer fixtures | Source-reported IDs never become independent execution proof |
| Same names or native IDs across tenants, accounts, projects and environments | Exact scope and tenant rejection fixtures | Display names and timing are not identity joins |
| Missing parents, retries and restart | Durable trace fixtures | Missing links remain visible; distinct attempts remain distinct |
| Grant removal with complete recollection | Recorded authorization receipt fixtures | Narrow recorded authorization change; not verified remediation or successful action |
| Alternate grants, shared identity paths, stale or incomplete recollection | Graph and receipt negative fixtures | Remaining access or unavailable evidence cannot become containment proof |
| Partial provider pages, replay and process interruption | Collection failure and recovery fixtures | Retains checkpoints/history; PostgreSQL-specific cases require a migrated disposable database |
| Live Lambda execution and downstream cloud effects | Not established by this suite | Requires separately authorized provider execution and attributable target evidence |
| Customer production capacity or adoption | Not established by this suite | Requires a declared deployment workload and customer-controlled qualification |

No fixture grant change mutates cloud IAM. Recorded authorization comparisons
remain inconclusive when required source coverage, freshness, identity binding
or revocation evidence is missing. Runtime auth rejects invalid credentials and
cross-tenant routing; policy denies stop forwarding. Trusted-proxy authentication
audit writes are awaited off the event loop. Their existing best-effort failure
policy remains unchanged: an audit sink failure is logged without rejecting an
otherwise valid authentication.

Next, run the separate [collection and mixed-load qualifications](perf/trace-collection-qualification.md).
Use authorized staging provider receipts to qualify live execution and effects;
do not upgrade synthetic spans, graph topology or missing events into proof.
