# Gateway fail-open / fail-closed posture

Every gateway enforcement subsystem decides what happens when its *own*
machinery fails — a policy file that will not load, a store that errors, an
evaluator that raises. The canonical inventory is code, not prose:

- **Matrix:** `agent_bom.runtime.fail_mode.GATEWAY_FAIL_MODE_MATRIX`
- **Live view:** `GET /healthz` on the gateway, under `fail_mode_runtime`
  (resolved against the running `AGENT_BOM_GATEWAY_FAIL_MODE`)
- **Regression pin:** `tests/test_runtime_fail_mode.py`

Shared gateway audit delivery (`AGENT_BOM_GATEWAY_AUDIT_BACKEND=postgres`) is an
admission requirement, separate from optional audit export. Missing migrations,
database failure, a full queue, expired ownership, or incomplete remote
acknowledgement never authorize tool execution. A crash after remote commit but
before local acknowledgement can replay the event; the receiving ledger must
deduplicate it. Database-clock leases fence stale acknowledgements. The retry
worker can recover another pod's expired claim without its credentials: the
replica set uses one dedicated, tenant-bound delivery credential. Health reports
pending work and loss of acknowledgement; it does not attest the reported agent.

## Summary

| Subsystem | Default posture | Follows `AGENT_BOM_GATEWAY_FAIL_MODE` |
|---|---|---|
| Policy engine (unloadable policy file) | fail-closed | yes |
| Firewall policy (unloadable policy file) | fail-closed | yes |
| Policy plugins (evaluation error) | fail-closed | yes |
| Control-plane policy bundle (parse/eval error) | fail-closed | no |
| Invalid, expensive, or oversized regex in an applicable policy | enforce: deny; audit: explicit invalid-policy receipt | no |
| Conditional access (evaluation error) | fail-closed | no |
| Caller identity (invalid/revoked or missing token) | fail-closed | no |
| JWT verification key fetch (`jwks_uri` / `oidc_issuer` refused by the outbound URL policy: non-HTTPS, private or metadata target without `AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS`) | fail-closed (treated as JWKS unreachable) | no |
| Runtime rate limit (store unavailable) | fail-closed (refuses startup) | no |
| Device posture enrichment (device state unknown) | fail-closed | no |
| Spend budgets (cost-store error) | fail-open | no |
| Cost-anomaly enforcement (cost-store error) | fail-open | no |
| Fleet quarantine (fleet-store error, enforce mode) | fail-closed | no |
| Drift enforcement (drift-store error or per-blueprint lookup cap) | fail-open; secured enforce (identity required): deny | no |
| Graph reachability (evaluation error) | fail-open | no |
| Audit export (sink/webhook delivery failure) | fail-open | no |
| Injection protection (detector error) | alert profile (default): fail-open with alert; enforce profile: fail-closed | no |

Two rules explain the split:

- **Security decision lanes fail closed** and are never softened by
  `AGENT_BOM_GATEWAY_FAIL_MODE`. Only the policy engine, firewall policy
  load, and policy plugins honour that knob, and its default is `closed`.
- **Advisory and telemetry lanes fail open** by design: a spend-, drift-,
  or audit-store error must never take the data plane down. A
  successfully evaluated enforce-mode rule in those lanes still blocks.

Drift enforcement reads open incidents for the caller's own role blueprint
only, newest first, up to 200 per lookup. Open incidents on other blueprints
never affect the lookup. When that blueprint alone has more than 200 open
incidents and none of those read names the tool, the result is reported as
unavailable rather than a clean pass, the same as a store error.

Per-entry failure behavior (the `on_failure` text) is part of the matrix and
shows verbatim in the `/healthz` output. For the surface map around the
gateway see [`RUNTIME_REFERENCE.md`](RUNTIME_REFERENCE.md); for policy-layer
ordering inside a single tool call see `docs/POLICY_PRECEDENCE.md`.

## Injection protection: alert and enforce profiles

The stdio proxy and the gateway inspect every tool result, and every tool in a
`tools/list` result, for prompt injection, semantic injection, HTML/CSS
cloaking, SVG payloads and invisible characters (`response_inspector`), plus
cache poisoning on vector/RAG tools (`vector_db_injection`). Two profiles
decide what happens on a detection.

| | `alert` (default in 0.111.0) | `enforce` |
|---|---|---|
| Poisoned tool description | forwarded; alert | tool removed from `tools/list`; alert `action: stripped` |
| Later call to a removed tool | forwarded | proxy and gateway reject it before the server sees it; alert `action: blocked` |
| Non-JSON-RPC upstream stdout (stdio proxy) | forwarded (scanned when inline scanning is on) | dropped, never relayed; alert `action: blocked`, category `unparsed_stdout` |
| Injected tool result | forwarded; alert | result replaced by a JSON-RPC error; alert `action: blocked` |
| Detector error | fail-open: forwarded; `detector_error` alert | fail-closed: that tool or result withheld; alert tagged as above |

Select enforce with one setting:

```bash
agent-bom proxy --injection-mode enforce --no-isolate --log audit.jsonl -- npx @mcp/server-filesystem /workspace
agent-bom gateway serve --upstreams upstreams.yaml --injection-mode enforce
```

The equivalents are `AGENT_BOM_PROXY_INJECTION_MODE=enforce`,
`AGENT_BOM_GATEWAY_INJECTION_MODE=enforce`, the Helm value
`gateway.injectionMode: enforce`, or `"injection_mode": "enforce"` in the proxy
or gateway policy file. The strictest source wins: a policy file selecting
`enforce` cannot be lowered by the flag. Unknown flag, environment, Helm or
proxy policy values reject startup without echoing the value. An invalid value
in the gateway policy file (at startup or after a hot reload) is treated as
`enforce`. `--log-only` together with `enforce` refuses to start.
The SSE/HTTP proxy (`agent-bom proxy --url`) has no enforcement path yet and
refuses to start when `enforce` is selected; use the stdio proxy or the gateway.

What enforcement acts on (the enforce threshold): `response_inspector`
detections in the categories `prompt_injection`, `semantic_injection`,
`cloaking`, `svg_payload` and `invisible_text` at **high or critical**
severity, and all `vector_db_injection` detections, block or strip.
**Medium**-severity detections (semantic scores under the high band, base64
blobs) are forwarded with an alert in both profiles; enforce does not raise
their severity. In enforce mode the stdio proxy also drops upstream stdout that
is not JSON-RPC, whether or not inline scanning is enabled (the bytes are never
copied into the alert, only their length), because an unparsed line is an
outbound channel no detector has inspected.
Error responses and notifications are not inspected by this profile; inline
scanning (`inline_scanning` in the policy) and gateway DLP still cover them.

Why poisoned tools are removed rather than rewritten: a description is not the
only place a tool carries instructions (`inputSchema` field descriptions and
annotations are scanned as well), and a placeholder description would leave a
callable tool whose behaviour the client can no longer judge. Removing it fails
safe. The stdio proxy also refuses calls to it for the rest of the session; a
later clean `tools/list` restores it. The gateway relay keeps no session, so it
remembers withheld names per `(tenant, upstream)` in a process-local registry
(`agent_bom.runtime.withheld_tools`, at most 4096 entries, 24 h TTL, oldest
evicted first) and refuses a `tools/call` made with a cached name before
admission and before any upstream call. The refusal is the same `-32001`
envelope as a blocked result (`categories: ["withheld_tool"]`) and is audited
as `gateway.injection_alert` with `action: blocked` plus the typed
`gateway.tool_call.blocked` event (`data_action: withheld_tool_call_blocked`).
Fail mode: the registry is memory on one replica. A replica that never saw the
poisoned listing, a restart, TTL expiry or eviction under a hostile 4096+ tool
flood all forget the name (fail-open for that call), and the call's result is
still inspected and blocked on detection. The registry is only consulted while
the effective mode is `enforce`; switching to `alert` forwards calls again.
Audit delivery failure while refusing never forwards the call: the response is
still the refusal, marked `X-Agent-BOM-Audit-Delivery: degraded`.

The replacement error for a blocked result is:

```json
{"jsonrpc": "2.0", "id": 7, "error": {"code": -32001,
  "message": "Tool result withheld by agent-bom injection protection",
  "data": {"policy_source": "injection_protection", "action": "blocked",
           "detectors": ["response_inspector"], "categories": ["prompt_injection"]}}}
```

It names the detector and category and never contains upstream text.

Audit: enforcement emits the same detection alert, with the `action` field set
to `blocked` or `stripped`. Proxy `runtime_alert` records carry it at the top
level and count towards `blocked_runtime_alerts` in the session summary. Gateway
audit events are `gateway.injection_alert` with the alert under `alert`; the
enforced ones also carry the typed result event (`data_action`
`injected_result_blocked` or `poisoned_tools_stripped`, `policy_source`
`injection_protection`). Persisted alerts pass through the existing evidence
redaction; enforcement adds no upstream text. A detector error records only the
exception class name.

The default stays `alert` in 0.111.0 so an upgrade changes no traffic. It is
planned to become `enforce` once detector false-positive rates have been
measured on real catalogs and results. Pin `--injection-mode alert` now if you
need today's behaviour after that change.

## Control-plane browser credentials

Static-key browser sessions bind to the exact key authenticated during sign-in.
Every authenticated request rechecks the current environment or mounted-file
key. Rotation, removal, an unreadable key file, or a switch to clustered mode
invalidates that session with HTTP 401; existing streams recheck through the
same authorization lease. Missing shared revocation state remains fail-closed.
Cookies contain a nonce-specific keyed binding, never the raw login key.
Logout still records nonce revocation after a backing-key change, so restoring
that key cannot revive a cookie that was explicitly signed out.

Bindings use HMAC-SHA-256 with a server-held signing key and distinct static-key
and operator-key domains. They authenticate the credential generation; they are
not password-storage hashes. A cookie alone cannot verify guessed login keys
without the signing secret. Configure `AGENT_BOM_BROWSER_SESSION_SIGNING_KEY`
(or its `_FILE` source) with an independently generated secret; do not reuse the
login key. Compromise of the signing secret breaks this boundary, and these
bindings do not claim protection against a compromised server. Configured signing
secrets pass through PBKDF2-HMAC-SHA-256 with 600,000 rounds. The single-process
fallback uses 32 random bytes and does not survive restart; clustered mode
requires a persistent signing secret.

Verification rejects an unkeyed digest, a binding from another nonce or signing
key, and a binding from the other credential domain. These fail-closed contracts
are exercised in `tests/api/test_browser_session_binding_security.py`, including
inside an otherwise valid signed envelope to isolate the binding check.

Operator-configured slots also bind cookies to their current stored credential
generation. Replacing a slot's key invalidates its previous browser sessions;
reloading an unchanged key preserves that generation while applying the current
configured role. The cookie exposes neither the stored key hash nor salt.

Upgrading from cookies without these bindings requires a fresh sign-in for
static-key and operator-key users. Exchange the current key at `/v1/auth/session` through the
same-origin dashboard. Managed tenant-key sessions continue to use their live
key record, role and scope ceilings. Invalid non-ASCII CSRF tokens return 403;
incorrect non-ASCII static credentials return 401 without exposing exceptions.

## Managed API-key verification cache

Each API process remembers a successful managed API-key verification for up to
`AGENT_BOM_API_KEY_VERIFY_CACHE_TTL_SECONDS` (default 60, clamped to 0-60; 0
disables) in a bounded LRU of `AGENT_BOM_API_KEY_VERIFY_CACHE_MAX_ENTRIES`
(default 1024) entries, so the scrypt derivation runs once per key per window
instead of on every request. The cache only replaces the hash comparison. Every
request still re-reads the stored key record by prefix and re-evaluates
revocation, expiry, rotation overlap and operator-key retirement on that fresh
record, and the entry must match the record's exact `key_id`, salt and hash.
Revocation, rotation and deletion therefore take effect on the next request in
every replica; the cache adds no revocation window beyond the key-store read.
An entry never outlives the key's `expires_at`.

Entries are keyed by HMAC-SHA-256 of the presented key under a random
per-process secret and hold only the `key_id` and an HMAC fingerprint of the
stored record. The raw key and the scrypt output are never retained, and the
secret is not persisted, so a restart empties the cache. Failed verifications
are never cached: a wrong key always pays the full derivation. A valid key
answers faster on a hit, which reveals nothing to a caller who does not already
hold it. The gateway runs key-store reads and verification in a worker thread,
like the API middleware, so a cache miss never stalls the event loop.

## Conditional-access header authority

Gateway transport authentication does not authorize a client to assert its own
MFA, directory groups, managed device, approved client, environment or risk score.
By default, `x-agent-*` policy-context headers provide no trusted access evidence.
Policies requiring those attributes deny when they are unavailable; numeric risk
constraints require finite scores and finite numeric bounds, including a maximum.

After configuring incoming gateway authentication as described in
[`RUNTIME_REFERENCE.md`](RUNTIME_REFERENCE.md), configure the controlled
identity/posture proxy transport-peer CIDRs explicitly:

```bash
AGENT_BOM_GATEWAY_TRUSTED_CONTEXT_PROXY_CIDRS=10.42.0.10/32 \
  agent-bom gateway serve --upstreams upstreams.yaml --bind 0.0.0.0:8090
```

The proxy must authenticate and
bind these assertions to the caller, remove client-supplied `x-agent-*` headers,
and overwrite them with verified values. Restrict direct access to the gateway.
A trusted network is an operator-controlled boundary, not proof of MFA by itself.
The setting accepts at most 32 comma-separated IPv4/IPv6 networks, is resolved at
startup, and rejects invalid or unrestricted `/0` networks. Programmatic
`GatewaySettings.trusted_context_proxy_cidrs=()` overrides the environment and
disables this trust. Restart to apply configuration changes.

The gateway CLI disables Uvicorn's automatic forwarded-peer rewriting so the
transport peer remains available for this decision. Custom ASGI launchers must
also preserve the original peer (for Uvicorn, `--no-proxy-headers`).
`X-Forwarded-For` cannot establish context authority; existing trusted-proxy
settings only resolve the client IP used by separate source-CIDR conditions.

## Graph evidence reads

Persisted trace, runtime, proxy and gateway observations share one
20,000-event graph-read budget with the gateway activity ledger. Reads filter
tenant, surface and inclusive UTC time bounds before consuming that budget. Pages use a timestamp/id cursor;
unrelated retained history is neither counted nor projected. A capped load is
reported as limited even if no valid event survives normalization. Store errors
produce a failed evidence receipt; they do not turn missing telemetry into a
clean graph or change gateway enforcement. A failing store does not hide
records from the other store. Trace providers retain their experimental opt-in;
already-ingested runtime and gateway metadata does not require it.

The `recorded_activity` relationship retains metadata-only source receipts and
never participates in attack-path traversal. Allow and deny decisions are
records, not proof that execution completed or a permission exists. Exact node
references bind only within the tenant and consistent recorded cloud scope.
Name-only, missing-scope and conflicting identities remain unverified resource
shadows with candidate counts. Replayed receipts do not increase event counts.
Load caps and rejected bindings appear in `runtime_activity_projection` analysis
status. No stored event is rewritten or deleted by projection.

OCSF ingestion retains bounded, allowlisted actor/session, cloud and device
attribution. Actor principal identifiers use tenant-bound digests; missing
deployment HMAC keys retain the explicit weak-digest marker. Source-reported
identity is not verified agent identity. Session identities include tenant,
source and account scope. Without a native session, only retries of the same
event are grouped. A timestamp synthesized at ingestion is marked `receipt`,
not evidence of execution time.

Local incident feedback reads at most 8 MiB, 10,000 records and 64 KiB per line
(plus one byte or line for limit detection). Byte/line/record limits, malformed
records and unavailable files appear as limited graph evidence. Reading never
truncates, rewrites or removes the source JSONL. The existing append sink remains
fail-open for relay availability; operators retain ownership of file rotation
and evidence retention.

## Per-agent novel-tool baseline

`ProtectionEngine.process_tool_call(..., agent_id=...)` learns a tool-frequency
baseline after 20 calls and refreshes it every 10 further calls. A tool absent
from the prior baseline produces a sanitized medium alert carrying the agent,
tool and baseline sample size; repeated calls to that tool are suppressed until
the next refresh. Rare tools already in the baseline are not novel. This is
evidence of a changed call pattern, not confirmed execution or compromise.

This detector is advisory: it does not directly block a call. When Shield is
enabled, its alert participates in the existing correlation and kill-switch
policy. No identity, cold start, restart or LRU eviction means no mature
per-agent baseline and therefore no novelty alert (fail-open for this signal).
State stays in one engine instance, with at most 1,024 agents and 1,000 recent
calls per agent; callers must provide a stable, appropriately scoped agent ID.

## Local tool-drift baselines

`Shield(deep=True, server_id="tenant-a/account-a/server-a")` restores the
named server's tool baseline from `drift_baselines/<sha256>.json` under
`AGENT_BOM_STATE_DIR` (default `~/.agent-bom`). Use a stable identity that
includes the tenant, account and server boundaries of the caller. Each Shield
instance must observe only that server's catalog. The identity is hashed for
the filename and is not written into the baseline; hashing is not authorization
or protection from an actor who controls the state directory.

Without `server_id`, tool baselines remain in memory per instance. This also
applies to the stdio proxy and the CLI/API protection engines, which do not
identify one persistent upstream server. The proxy still establishes a baseline
from its first complete `tools/list` catalog and detects later tool-name changes
within that session. A session restart without an identified, restored baseline
cannot prove cross-session drift.

The legacy `drift_baseline.json` has no trustworthy server attribution. It is
ignored and preserved, never migrated to a guessed owner. Missing, malformed or
unreadable scoped baselines start without a historical baseline. Persistence
errors are **fail-open**: in-memory drift detection continues, but history may
be unavailable after restart. The first complete catalog then establishes a new
baseline; it is not proof that the server is unchanged or safe. Scoped files are
written atomically with owner-only permissions. This changes tool-baseline
storage only; other runtime policy and kill-switch behavior is unchanged.

## What is *not* an isolation boundary

The stdio proxy's launcher check (`agent_bom.security.require_recognized_launcher`)
and shell-metacharacter argument check are launch-hygiene guards against
misconfigured server entries. They confer no isolation: a recognized launcher
(`python`, `node`, `docker`) can still run arbitrary code as the host user.
The execution control for MCP servers is container isolation —
`agent_bom.proxy_sandbox` via `--isolate` (see `docs/MCP_SECURITY_MODEL.md`).

The check accepts a bare launcher name from the allowlist, or an absolute path
(`/opt/project/.venv/bin/python`, as desktop-client configs write it) whose
basename is a known launcher when the file — symlinks followed — exists, is a
regular executable that is not world-writable, sits in a non world-writable
directory (sticky bit included, so `/tmp` never qualifies) and, for a symlink,
resolves to a launcher name or package-manager shim (`python3.13`,
`npx-cli.js`). Relative paths, `..` segments, directories and anything else are
rejected; the rejected server is recorded as `security_blocked` with a
`launcher_rejected` coverage warning so a live audit never skips it silently.

## Gateway settings at startup

`agent-bom gateway serve --fleet-enforcement enforce` blocks quarantined
identities and denies calls when the fleet lookup is unavailable. `warn`
records the condition without blocking; `off` explicitly disables that check.
The gateway validates enforcement and DLP modes before creating audit sinks or
upstream clients. Python integrations normalize mode case and surrounding
whitespace; unknown modes, non-finite timeouts, invalid pool sizes, and negative
rate limits reject startup instead of silently disabling protection. Settings
representations omit credentials, policy contents, and credential-bearing URLs.
Correct the named setting and restart; mode errors never echo its supplied value.

### Invalid policy expressions

Policy creation and updates reject malformed regular expressions and patterns longer than 500 characters before changing stored state. Correct the indicated rule and retry the write. Existing stored policies and local JSON policy files receive the same validation at evaluation time: blocking rules fail closed; advisory rules produce an explicit invalid-policy warning. Disabled policies and policies bound to a different agent do not apply. Invalid-policy diagnostics omit patterns, argument names and argument values.

### Bounded regular-expression evaluation

Policy writes and stored/local policy evaluation reject nested repetitions,
alternation inside repetitions, counted repetitions above 1,000, and expression
nesting beyond 32 levels. The existing 500-character pattern limit still applies.
Rewrite an affected rule using simpler patterns before enabling enforcement.
For example, replace `^(a+)+$` with `^a+$`. This is a conservative grammar guard,
not a claim to identify every expensive expression.

The matcher uses the timeout-capable [regex engine](https://pypi.org/project/regex/)
in Python-compatible VERSION0 mode, with 25 ms per match and a shared 100 ms
budget per policy evaluation. Inputs beyond 10,000 characters and exhausted
budgets produce an explicit evaluation-limit decision; they never count as
non-matches. Enforce mode denies; audit mode permits with an explicit receipt.
These limits are operational safeguards, not a gateway throughput guarantee.
The bounded 512-entry compiled-pattern cache is process-local. Diagnostics omit
regex text, argument names, and argument values; policy and rule IDs identify
the affected configuration. Existing policy records are preserved for correction.

VERSION0 does not give identical Unicode character classes to Python `re`.
For Unicode-mode expressions, inputs whose word/digit/space classification
differs between the engines (for example, certain combining marks and joiners)
produce an explicit incomplete-evaluation decision: deny in enforce mode,
receipt in audit mode. This guard is conservative, including for literal
expressions on such inputs. Ordinary Unicode text with matching classifications
remains supported. Use an explicit ASCII expression such as `(?a)\W` only when
ASCII character-class semantics are intended; scoped Unicode overrides still
receive the guard.

Unicode case-insensitive evaluation is also conservative: when case-insensitive
matching encounters non-ASCII input or non-ASCII/escaped literals, it returns the
same incomplete-evaluation decision unless ASCII semantics are explicit.
This avoids differing dotted/dotless-I case folds weakening an existing block.
Escaped literals may trigger this guard even when they encode ASCII; write the
literal directly or use explicit ASCII semantics when that is the intended rule.


### Side-scan connection authorization

Server-side snapshot scans fail closed unless the authenticated tenant owns a
non-demo connection and its current operator binding grants the exact target,
collector and location. REST rejects unauthorized scope with 403; MCP and the
scheduler return `unavailable`. No provider credential or mutation is attempted
on denial. Credentials are constructed only from that binding, with no ambient
fallback, and the binding is rechecked before constructing clients. A changed
binding invalidates a retry's authorization fingerprint. This gate does not
revoke tokens already issued by the provider; use provider revocation for that.


Side-scan cleanup requires recorded resource IDs and current provider ownership
before Azure/GCP detach or deletion. Atomic version checks prevent competing
workers from claiming the same cleanup. Running executions, existing cleanup
claims and timed-out provider operations are not automatically reclaimed.
Unmount, detach or disk-deletion failure stops dependent deletion and leaves
partial cleanup evidence. A confirmed provider 404 is treated as absence;
permission and network failures remain incomplete. Tag-only AWS orphan sweeps
are disabled because legacy runs lack durable ownership records. Reconcile
those resources manually using saved IDs and provider events; no clean-state
claim follows from an empty sweep result.

## AI advice

AI advice fails closed: a failure removes advice and never changes scanner results.

| Failure | Behaviour | Where it shows |
|---|---|---|
| AI not enabled for the deployment or tenant | No provider call. `POST /v1/graph/explain` returns 409. | `GET /v1/ai/status` state `off`, with the reason; findings page; CLI |
| Non-loopback provider without `AGENT_BOM_AI_ALLOW_REMOTE=1` | Refused at resolution and again at the provider boundary, before any request | Run status `blocked`; audit outcome `blocked` |
| Provider down, timeout, or empty response | That batch produces no advice; the scan continues | Run status `partial` or `failed`; audit outcome `failed` or `empty` |
| Invalid or unparseable response | The bad entry or response is dropped; valid neighbours stand | Audit `guard_rejected` with the reason |
| Model tries to dismiss a protected finding | Dismissal discarded and the finding stays confirmed | `guard_applied` on the assessment; audit `guard_rejected` |
| Budget, capacity wait or run deadline reached | No further calls; advice so far is kept | Run status `partial` or `failed`; audit `over_budget` or `over_capacity` |
| Advice store unavailable | Findings list still answers, with a warning | `warnings` on `GET /v1/findings` |
| Control-plane audit write fails | Fails closed for the AI call: its output is discarded, so no advice is stored and no explanation returned without its record. The scan itself continues, since it does not depend on advice | Run status `failed`; explain returns 503 `audit_unavailable`; error log |
| CLI local audit write fails | The scan and its advice stand, with a warning. The local log records one user's own calls and can be opted out of, so an unwritable state directory should not take their results away | Log warning |
| Explain rate or budget store unavailable | Fails closed: no model call | 429 with `Retry-After` |
| Explain rate or daily budget exceeded | 429 with `Retry-After`, no model call | `agent_bom_rate_limit_hits_total{bucket="ai_explain"}` or `ai_explain_budget` |

## Scheduled scan dispatch

The scan scheduler rechecks its leadership lock after reading due schedules
and before dispatching each occurrence. Lost leadership stops that dispatch
batch. A missing, disabled or rescheduled tenant-owned record is skipped;
a store error backs off without authorizing a scan from the stale due list.
These checks do not provide exactly-once execution across a crash after
submission or leadership loss after the final check. Submission idempotency
must cover those boundaries where available.

## Graph roll-up warm-up failures

Roll-up warming is a best-effort cache optimization. A failed warm-up does not
change persisted scan evidence; the next reader computes the view cold. A fatal
worker exit releases its busy state and discards only pending cache warm-ups,
while the original exception remains visible. New commits can start another
worker. Pushed reports use detached snapshots in the in-memory job store so
background readers do not serialize the writer's report during graph enrichment.

## Stdio tool-definition drift

The stdio proxy compares each completed `tools/list` catalog with its session
baseline, including `name`, `title`, `description`, `inputSchema`, `outputSchema`,
`annotations`, `execution`, `icons` and `_meta`. Additional declaration fields
are hashed together and reported as `extensions`, without exposing their keys.
A declaration change under an unchanged name emits a HIGH
`tool_drift` alert identifying the changed fields. Field values are never
included in these alerts or persisted; only per-field SHA-256 fingerprints are
held in memory. Durable audit records retain the tool name and a normalized
change reason; detailed field lists follow the existing replay-only redaction
policy. JSON object key order, schema `required`/`enum` set order and declaration
`icons` order do not create drift. Arrays inside literal schema values or vendor
metadata retain their order, so changing them still produces drift. Name-only Shield
callers and persisted server-scoped name baselines retain their existing contract;
definition fingerprints are established anew in each session.

`notifications/tools/list_changed` starts a private, read-only `tools/list`
refresh. Notifications still reach the client, while proxy-owned responses are
consumed internally. Client and refresh pagination are kept separate. Refreshes
coalesce repeated notifications, allow at most 20 pages and 4,096 tools, and
have a 30-second deadline (each stdin drain is bounded to 5 seconds). Tool names
are limited to 512 characters; all fingerprinted fields share a 256 KiB canonical
JSON byte budget per tool, including extension keys and values. Canonical JSON
is streamed into the hashes, and metadata object key order does not create drift.
Malformed or oversized catalogs never establish a baseline. Client-requested
incomplete catalogs produce a coverage warning. Errors, timeouts and incomplete
notification refreshes emit an incomplete-catalog alert and preserve the baseline.
Session shutdown cancels the outstanding deadline.

This detector is advisory/fail-open: alerts do not block tool calls or change
injection enforcement. A definition change is evidence of drift, not proof of
malicious intent or execution. This notification refresh applies to the stdio
proxy; it does not add HTTP gateway or SSE-proxy enforcement.

### Gateway upstream tuning

`gateway serve` accepts upstream HTTP pool, timeout, failure-threshold and
circuit-cooldown flags with matching `AGENT_BOM_GATEWAY_UPSTREAM_*` environment
variables. Invalid or non-finite settings fail startup before control-plane
requests or binding a listener. CLI flags take precedence; security policies and
authentication defaults are unchanged. See the [operator limits and defaults](perf/gateway-relay-latency.md#configure-upstream-limits).

## Demo tenant ingest

With `AGENT_BOM_DEMO_ESTATE=1` (`agent-bom serve --demo-estate`), the showcase
tenant holds only labeled synthetic data. Every authenticated principal passes
through one tenant-binding step, and that step refuses ingest operations
addressed to the showcase tenant with `409 Conflict` and a fixed message, for
every role. The guarded operations are listed in
`src/agent_bom/api/demo_tenant_guard.py`; a test fails when a new ingest-shaped
write route is neither guarded nor declared non-ingest. Other tenants on the
same server, and all reads, are unaffected. Anonymous callers in demo mode are
already clamped to `viewer` and cannot write at all.

## Executive brief read access

`GET /v1/brief` fails closed for anonymous callers outside the explicitly enabled
sample demo. Scoped API keys need `brief:read` for the aggregate view; a
`posture:read` grant alone is insufficient. MCP resolves the authenticated tenant
before invoking the same read. Demo responses carry `sample_data: true`.

The brief is advisory and unsigned. An unavailable graph is reported as
`exposure_status: unavailable`, never as a clean graph. Other source-read failures
fail the request through the existing sanitized API error handling. Independently
read source scopes and snapshot identifiers remain attached; the brief does not
claim atomic consistency, compliance attestation, or confirmed exploitation.

## MCP public read-only tier

Fail-closed in every direction. With the tier off (the default) anonymous
`/mcp` requests are 401 as before. With it on, an anonymous `tools/call`
outside the allowlist is HTTP 401, any other anonymous method except
`initialize`, `ping`, notifications and the filtered listings is refused, and
an invalid, expired or unrecognised bearer token is 401 rather than a fallback
to anonymous access. An unparseable `AGENT_BOM_MCP_PUBLIC_READONLY` value
refuses startup, as does combining the tier with MCP OAuth or SSE. Rate-limit
state is in process memory, so it cannot be unavailable; a restart resets it.
Anonymous callers are bucketed by IPv4 address or IPv6 /64, so one host cannot
mint new buckets by rotating addresses inside its own prefix. A fifth of the
aggregate budget is reserved: once the shared four fifths are used, a bucket
that has made fewer than 3 calls in the window may still make up to 3 more,
counted per IPv6 /48 or IPv4 /24, so one heavy network cannot lock out
newcomers or spend the reserve by rotating buckets. Each bucket runs at most
`AGENT_BOM_MCP_PUBLIC_CALLER_CONCURRENCY` (default 4) tool calls at once; the
next returns a `rate_limited` tool error with `retry_after_seconds`. Anonymous
`initialize` draws on a separate session budget with the same per-bucket and
aggregate limits and answers JSON-RPC error `-32000` past it. The
no-login edition (`--profile public`) serves streamable HTTP statelessly, so
anonymous callers hold no entries in the session table; a public tier on
another profile keeps sessions for bearer callers, and anonymous session
creation is bounded only by that budget. With
`AGENT_BOM_MCP_PUBLIC_TRUSTED_PROXY_HOPS` above 0, `X-Forwarded-For` is read only
from peers inside `AGENT_BOM_MCP_PUBLIC_TRUSTED_PROXY_CIDRS` when that is set; an
unparseable list trusts no peer, and hops without a list logs a start-up
warning because any peer can then pick its bucket.
Railway and the Procfile preserve the authenticated image default; neither forces
this optional tier on a deployment that already uses OAuth. Release verification
uses the configured managed credential and rejects anonymous access. An upload is
not proof of a successful rollout: failed startup or stale version/schema evidence
keeps deployment verification failed.
See [MCP server](MCP_SERVER.md#public-read-only-tier).

## API-key verification cache

The process-local cache remembers successful verifications for at most 60 seconds
and never past the key's expiry. Its indexes and record fingerprints use
HMAC-SHA-256 under a random process secret; the stored credential verifier remains
salted scrypt. No raw credential or stored verifier is retained in a cache entry.

Every request still loads the credential record and checks revocation, expiry,
rotation and operator retirement. A changed credential record or process secret
cannot reuse a cached match. A miss, eviction, expiry or disabled cache requires
normal scrypt verification; it never grants access. Failed verifications are not
cached. Cache entries remain bounded by `AGENT_BOM_API_KEY_VERIFY_CACHE_MAX_ENTRIES`;
setting that limit or `AGENT_BOM_API_KEY_VERIFY_CACHE_TTL_SECONDS` to zero disables
the optimization.

On SQLite, the `last_used` stamp written after a successful verification is best
effort: if another writer holds the database for more than 100 ms, such as a large
graph snapshot commit, the stamp is skipped and the next request records it. The
decision to accept or refuse a key never depends on that write, and revocation,
expiry and rotation are still read from the committed key row on every request.
`last_used` can therefore lag by the length of such a write.

## Current graph refresh

A current-estate request retains the previous complete generation while waiting
for a background refresh. A concurrent promotion cannot delete that generation
until the request's read scope ends. Responses using retained evidence declare
`freshness: previous_generation`; they do not claim the latest source evidence.
A cold request with no complete generation still returns a bounded, retryable
503 while building. Explicit stale generation continuations still fail with 409,
and generation retention does not cross tenant boundaries.

After a push the API also warms the roll-up views, the reachability index, the
executive reads and the posture counts. These warm-ups load the estate into
Python, and under the GIL a CPU-bound thread makes every concurrent request wait
for the interpreter each time it returns from I/O (a 95 ms graph read took 9.4 s
beside a busy loop). Warm-ups therefore run as background work: at bounded
yield points in their row loops, while any request other than an orchestrator
probe is in flight, they sleep without holding the GIL for at most 100 ms, then
continue. Constant traffic slows a warm-up but cannot stop it, a request never
waits on its own yield point, and the current-graph build itself does not yield
because a cold read may be waiting for it.

At start-up the API prepares current generations before the first read asks.
One daemon thread takes the tenants of the newest 1,000 completed jobs, at most
16, newest first, and builds each through the same coalescing queue that reads
use, under that tenant's binding. A read that arrives mid warm-up joins the
build in progress rather than starting another, waits its usual
`AGENT_BOM_CURRENT_GRAPH_BUILD_WAIT_MS`, and past that answers 503
`current_estate_building` with `Retry-After: 1` as before. A tenant past the cap,
or one whose build fails or exceeds
`AGENT_BOM_CURRENT_GRAPH_PREWARM_TENANT_SECONDS` (default 300), is built by its
first read instead; the start-up log line counts prepared, skipped and failed
tenants without naming them or carrying source errors. The warm-up never blocks
start-up or the event loop and does not run while the demo estate is seeding.
`AGENT_BOM_CURRENT_GRAPH_PREWARM=0` turns it off.

While the warm-up runs, `/readyz` answers 503
`{"status": "not_ready", "reason": "current_graph_prewarming"}`, so the chart's
readiness probe keeps a restarted replica out of the Service until its graphs
are built and no routed read lands on a cold replica. The hold is bounded by
`AGENT_BOM_CURRENT_GRAPH_PREWARM_READY_SECONDS` (default 120): past it the
replica reports ready even if the warm-up is still running, and reads that
reach an unbuilt tenant get the bounded 503 above. Liveness (`/health`,
`/healthz`, `/livez`) and the chart's `startupProbe` never wait on the warm-up,
so a slow warm-up cannot get the pod restarted. A warm-up that fails at any
step, including opening the job store, reports `incomplete` with reason
`prewarm_failed`, logs a sanitized one-line warning (no traceback, no
connection string) and releases readiness at once. A disabled warm-up holds
nothing. Measured under the chart's 1 CPU / 2 GiB limit with a 200-agent
tenant, the hold lasted 3.4 seconds and the first read after it returned 200;
see "Push admission, start-up readiness and refresh under cgroup limits" in
[PERFORMANCE_BENCHMARKS.md](PERFORMANCE_BENCHMARKS.md).

## Oversized result pushes

One push is stored as one job result, so a decoded push can never exceed 240 MiB
(the PostgreSQL jsonb value limit, less margin), whatever
`AGENT_BOM_API_RESULT_PUSH_MAX_BYTES` says. The CLI measures the serialized
report before uploading: past 240 MiB it sends nothing and fails the run with
the report size, its agent count and how many agents fit in one push. When the
control plane answers 413 for a smaller configured budget, the CLI reads
`max_bytes` from the response and prints the same advice once, without
retrying. The advice is to split the inventory into several files and scan each
with its own `--inventory` path: each path is its own target scope, so its next
push replaces only its own earlier evidence and the current estate is the union.
Nothing is truncated and no agent is dropped. Connector and lake pushes log the
same message and report the push as failed.

## Unauthenticated result pushes

When the control plane answers a scan push with 401 or 403, the CLI fails the
run (exit 1, the local report is kept) and says why: no key was sent, the key
was rejected, or the key may not push. The message names `--push-api-key` and
`AGENT_BOM_PUSH_API_KEY`, and notes that a local `agent-bom up` / `serve` prints
its loopback "Dev API key" at startup and mints a new one on every start. The
key itself is never printed.

## Rejected repository URLs

`POST /v1/scan` (and every endpoint that shares its request guard) checks
`repo_url` before queueing, without network access. A URL with a disallowed
scheme (`file://`, `ssh://`), scp-style or local-path syntax, embedded
credentials, control characters, or a host outside
`AGENT_BOM_REPO_SCAN_ALLOWED_HOSTS` is answered `422` with the rule that failed
(naming at most the scheme or host the caller sent; embedded credentials are
never echoed), and the server logs
a sanitized warning. A URL that passes these checks but cannot be cloned (DNS
resolves to an internal address, the repository does not exist, a size cap is
hit) fails the job with `Repository scan failed: <reason>`, with credentials,
URLs and server paths scrubbed, and logs a warning, instead of the generic
"An internal error occurred".

## CLI log output under `--log-json` and `-q`

With `--log-json`, `scan`, `image`, `fs` and `code` write one JSON object per
line to stderr: progress lines become `INFO` records on the `agent_bom.progress`
logger, failure notices become `ERROR` records, and the update notice is
skipped. With `-q`, progress is silenced (including the discovery banner) and
only errors print. With both, only warning and error records print, as JSON.
stdout carries only the report.

When `--log-json` appears anywhere in argv (before a `--` separator) or
`AGENT_BOM_LOG_JSON` is on, the entry point decides before Click parses, so a
usage error that stops parsing early is still JSON. Click usage errors
(unknown option, bad or missing value), `ClickException` failures and uncaught
exceptions each come out as one `ERROR` record on the `agent_bom.cli` logger
with `context.exit_code` and `context.error_type` (`usage`, `error`, or the
exception class). Messages pass through `sanitize_text`; uncaught exceptions
also go through `sanitize_error`, which removes paths, URLs and credential
assignments. Exit codes are unchanged: 2 for usage errors, the exception's own
code for `ClickException`, 1 for an uncaught exception, 130 on interrupt.

## Non-finite numbers in a push

JSON has no NaN or infinity, and the job store cannot encode them. A pushed
report containing `NaN`, `Infinity`, `-Infinity`, or a number too large for a
double (`1e999`) is rejected at parse time, before admission, with `422` and a
`finite_number` error at the value's location (`["body", "agents", 0, "score"]`)
on both the synchronous and the `Prefer: respond-async` path. Nothing is stored
and no idempotency key is claimed. Earlier builds stored the value on SQLite
and answered `503` on PostgreSQL.

## Push completion and scan recovery

A synchronous push remains `running` until graph persistence succeeds and the
completed job receipt is durable. Poll `GET /v1/results/push/{job_id}` for the
receipt; `stored` requires a recorded persisted graph. A legacy `done` row with
no graph receipt reports `failed` and can be retried with its original
idempotency key. A process exit between writes cannot certify completion.

Distributed scan and push jobs use dispatch leases for recovery. Creation age
never fails a job that holds a queue row, including old admissions reclaimed by
another worker. Live owners renew their leases; expired leases can be reclaimed,
and stale tokens cannot acknowledge successor claims.

A job claimed by a replica that dies, such as an asynchronous push whose pod is
force-deleted mid-ingest, is picked up by any live replica, or the replacement
pod, without a client retry. It waits at most the claim lease plus one claim
poll: `AGENT_BOM_API_SCAN_LEASE_SECONDS` (default 120) plus
`AGENT_BOM_API_SCAN_CLAIM_POLL_SECONDS` (default 3), so about two minutes. The
new owner re-reads the job and ingests it once; an admission that was already
committed is not run again. A live owner renews its leases on a dedicated
thread every poll (at most a sixth of the lease), so a slow claim loop or a
busy event loop cannot let a running job's lease lapse. During shutdown the
replica stops claiming but keeps renewing until its in-flight jobs drain. A
lease shorter than a database outage can still lapse on a live owner; the job
may then run on two replicas, so keep the lease well above expected outages. Local in-process jobs
retain the age timeout and restart cleanup. Lease renewal is worker liveness
evidence, not proof of forward progress; a live but stalled worker still
requires operational diagnosis. These rules preserve tenant scoping and fail
closed on completion claims without persistence evidence.

Three outcomes end a distributed job that nothing else would finish. Each leaves
it `failed`, which the client resubmits under the same idempotency key:

- **A dispatched job out of attempts.** Each claim counts against
  `AGENT_BOM_API_SCAN_MAX_ATTEMPTS` (default 5). Once the last claim's lease
  expires the job fails with the attempt count instead of being redelivered, so
  a report that crashes every worker cannot loop. The new admission starts over.
  A rolling restart also uses up an attempt for each job it interrupts.
- **A synchronous push whose replica died.** The request heartbeats a lease in
  the same queue table for as long as it runs, however long that is. When that
  lease (at most 120 seconds) expires, any replica fails the job. It is not
  replayed, because only the request held an endpoint inventory. A retry can run
  as soon as the idempotency reservation lapses, even before the job is failed.
- **A pushed job with no queue row at all**, older than the 30-minute stuck-job
  timeout. Current writers never leave one; earlier releases could.

A run that raises or is cancelled before recording an outcome, such as a store
outage during ingest, keeps its queue row so the lease can expire and the job can
be redelivered. Worker reads retry briefly first, and a store error never marks
the report failed. Without distributed dispatch the job stays `pending`: a resubmit
re-offers it, and the age timeout or next restart fails it otherwise.

Without distributed dispatch, one process runs each job at most once at a time.
A dispatch that arrives while the same tenant's job is still held by a finishing
worker, such as an identical push after retention or the retry of a failed push,
is recorded rather than dropped. When the worker finishes it re-reads the job and
runs it again only if it is `pending`, so a replay of the admission it just
finished does not run twice. If that read fails or the executor is shutting
down, the job stays `pending` for the next resubmit, the age timeout or restart.

## Hosted MCP OAuth

OAuth authentication is fail-closed and independent of gateway fail-mode flags.
Missing tenant or introspection configuration refuses startup. Invalid signature,
issuer, audience, subject, scope, tenant or token lifetime denies access. An
expired/revoked token, missing introspection claims, inconsistent signed and
introspected identity, timeout, redirect, oversized response or issuer failure
cannot fall back to signature-only validation or anonymous access.

Every HTTP request is authenticated before MCP dispatch, including requests in
an existing session. The signed tenant must equal the deployment's configured
tenant; conflicting tool arguments return an error without executing the tool.
Read-only registration also excludes unknown plugin tools, writes, process
execution and activity-history collection. Public OAuth discovery is available
without credentials and contains no tenant inventory or secrets.

Revocation takes effect on the next HTTP request once the authorization server
reports the token inactive. It does not cancel an operation already admitted or
erase results already returned. There is no positive introspection cache.
Public keys are cached for five minutes with refresh rate limiting. Subject
allowlist changes require restart. Issuer administrators and a compromised
resource-server process remain trusted boundaries; token checks do not prove
protection against either administrator rewriting policy or stored evidence.

### STRIDE assessment

| Threat | Boundary and mitigation | Remaining constraint |
|---|---|---|
| Spoofing | Verified issuer/signature, exact audience, approved subject and signed tenant; client uses authorization code with S256 PKCE | Issuer must protect tenant attributes and client registration |
| Tampering | Introspection identity must match signed claims; tool arguments and headers cannot override tenant | Issuer and server administrators remain trusted |
| Repudiation | Existing request identifiers and bounded tool telemetry remain available; no tokens or issuer errors are logged by the verifier | Process-local telemetry is not an independent audit record or durable login ledger |
| Information disclosure | Exact deployment tenant, scoped stores and explicit tool allowlist; introspection only to issuer HTTPS origin | Tool results are visible to the authorized client; hosting logs/backups require operator policy |
| Denial of service | Token size, response size and request timeout bounds; unknown-key refresh throttled | Introspection adds issuer availability/latency dependency; edge rate limits and capacity testing remain operator responsibilities |
| Elevation of privilege | Read scope only, read-only catalog, no history or process execution; revocation checked per HTTP request | New tools need capability classification and annotation review before exposure |

Regression evidence: `tests/test_mcp_oauth_tenant_revocation.py` exercises two
seeded tenants, wrong-tenant arguments/tokens, revoked sessions, contradictory
introspection and issuer failures. `tests/test_mcp_external_oauth.py` covers
signature, time, discovery and key rotation. Run an approved real MCP client
against the configured issuer as described in [MCP_OAUTH.md](MCP_OAUTH.md);
unit tests do not establish production login or directory acceptance.

Rollback restores a compatible application and issuer configuration together.
Never disable authentication or enable the public tier as a recovery shortcut.

## Shared request rate limits

On Postgres, request rate limits (the per-IP ceiling and the per-tenant budgets)
are shared by every replica through `api_rate_limit_hits` and the admission pool,
at most four autocommit connections per process, shared with authentication state. A hit is one round trip: its
transaction, 400 ms statement and lock bounds, the prune of that bucket and the
count-and-record statement are pipelined, with every value bound as a parameter.
A hit takes no lock another hit waits on, so concurrent hits on other replicas can
each be admitted before seeing the other; budgets consumed through
`consume_if_below` (websocket handshakes, AI explain, trial scan credits) take the
bucket's transaction lock and stay exact.

A request waits at most two seconds for the shared store, including this process's
own scheduling: CPU-heavy ingest and graph threads in the same process delay every
thread. Sustained CPU-bound work in the API process can still delay a request past
that wait, and limits are then per process until the store answers again.
The store's own work is bounded by the database at 400 ms, and taking a connection
at 400 ms. A store error or a wait past two seconds still degrades to process-local
limits for five seconds, logs `Shared rate-limit store unavailable` at most once a
minute, and retries the shared store after that.

## Authentication failure throttling

API and MCP HTTP authentication share source-based backoff. The default is ten
failed authentications in 60 seconds, followed by a 30-second block; subsequent
blocks double to 900 seconds. One hour without failures resets escalation.
Configure `AGENT_BOM_AUTH_FAILURE_LIMIT`, `AGENT_BOM_AUTH_BACKOFF_SECONDS`, and
`AGENT_BOM_AUTH_MAX_BACKOFF_SECONDS` on every replica with the same values.
The response is 429 with `Retry-After` and `X-RateLimit-Scope: auth-source`.

On Postgres the state uses the migration-owned `api_auth_failure_limits` table
through the admission pool it shares with rate limits: at most four autocommit connections per process, with the application role and its
row-level-security check. Ingest, graph and report work hold the application pool
for seconds, so admission never queues behind them. An admission read is one round
trip: its transaction, `SET LOCAL` 400 ms statement and lock bounds, the read with
the source bound as a parameter, and the commit are pipelined together. A failure
write opens its transaction, bounds and the source's transaction lock in one round
trip, then continues in that transaction. `SET LOCAL` keeps the bounds working
behind a transaction-mode connection pooler. SQLite processes share it when they use the
same `AGENT_BOM_DB` path: authentication state lives in the owner-only
`<database>.auth-limits.db` sidecar so a scan-ingest write transaction cannot
lock its budget. Without a persistent database it is process-local.
Eight dedicated threads separate auth state from background work. At most 64
operations may be running or queued for them per application, at most four of them
failure writes and at most two from one source, so a burst of distinct callers waits
briefly rather than being refused. Beyond that bound, an admission check returns 503
without tripping a process-wide breaker. A caller waits at most two seconds, including
time queued and this process's own scheduling, for an answer, and is then refused with
503. The store's own work is bounded at 400 ms by the database; the longer wait covers
CPU-heavy ingest and graph reads in the same process, which delay every thread there,
so valid keys are not refused for local load. A queued operation nobody is waiting
for is abandoned; one already running keeps its slot until it exits. An answer that has
already arrived when a stalled host fires that timer is used, because it is correct.
Postgres auth transactions bound pool acquisition, statement execution and lock
waits to 400 ms each. Pool saturation and SQL cancellation/lock timeouts fail
that request closed without activating the global outage cooldown.
SQLite uses one connection per worker. Admission reads never wait for a writer,
so one stalled transaction blocks no other source's check. Writers in one process
queue on a lock, and a writer waits at most 400 ms for it or for another process. The process-local in-memory database has one connection, and a
bounded lock around it gives the same 400 ms limit to every operation.

A failed attempt that cannot be written is never lost. Its count waits in memory,
for at most 4,096 sources, and the next operation for that source carries it,
including the next admission check, which then refuses the source. The caller still
receives its 401, since the credential was already refused. Only a process exit
before the next operation loses that count; a wave of concurrent guesses can
therefore pass the limit by at most the number in flight, not by every attempt.

### Outage breaker

| Condition | Response | Effect on others |
|---|---|---|
| Dead pooled connection | Retried on the next connection within 400 ms | None. A database restart leaves several, and each costs one attempt |
| One store error | 503 for that request | None; a success clears the count |
| Three consecutive store errors, no success between | Breaker opens for five seconds: 503 with `Retry-After: 5`, including valid keys | Fails closed. One operation goes through every 500 ms to find recovery, and one success closes the breaker |
| Slot, deadline, pool or lock timeout | 503 for that admission check | None. Contention is not evidence of an outage |
| Audit write or receipt-budget failure | The caller is unaffected | None. Counted as a dropped receipt |

After a Postgres restart, valid keys recover as soon as the driver's pool has a
new connection. The pool reconnects in the background with its own backoff, and
requests until then receive 503.

### Failed-authentication receipts

Receipts are written by two dedicated workers with their own queue of 256, at most
eight per source, so an audit stall or a flood from one source cannot refuse anyone
or hold an answer. Every failure increments
`agent_bom_auth_failures_total{reason="failed_credential"}`, whatever happens to its
receipt. A receipt that is not written increments
`agent_bom_auth_receipts_dropped_total{reason}` (`over_budget`, `queue_full`,
`source_queue_full`, `write_failed`) and is reported by an `auth.receipts_dropped`
audit entry within about five seconds, without waiting for another failure, retried until
it is written. That entry gives `dropped_receipts`, `window_started_at`, `window_ended_at`,
`dropped_source_count` and up to 20 sources as `dropped_sources`. All reasons but
`over_budget` also log an error at most once a minute.
At exit the process waits two seconds for queued receipts and logs an error if any
remain. Those, and a gap not yet recorded, are then lost, with the log and metric the
only record.

Admission reads are cached for at most one second and 4,096 source addresses.
Concurrent cold requests from the same source share one admission lookup, with
at most eight outstanding source lookups and 64 waiting requests per source.
Lookup tasks are shared only within their owning event loop; cache and capacity
accounting remain synchronized across loops serving the same application.
Excess waiters receive 503; canceling a waiter does not cancel the shared read.
A failure invalidates that source locally; atomic shared-store updates still
decide the failure count and backoff. Another replica's block or a new outage
may take up to one second to become visible through an existing admission
cache entry. Once a store exception is observed, all local admission cache
entries are cleared. This cache holds source admission only; key validity and
revocation still use the current durable credential record on every request.

### What needs authentication state

| Request | During a backoff | Auth store down |
|---|---|---|
| `GET`/`HEAD` of `/health`, `/healthz`, `/livez`, `/readyz`, `/ping`, static assets; CORS preflight with `Origin` and `Access-Control-Request-Method` | Served | Served |
| `GET`/`HEAD` of `/`, `/version`, `/docs`, `/redoc`, `/openapi.json`, `/brand/mark.svg` | Served | Served |
| Anonymous route, when the operator enabled anonymous access | Served | Served, if the route's own data store answers |
| Anything presenting a credential, or `/v1/auth/*`, SCIM and unclassified routes | 429 | 503 |
| `/ws/proxy/metrics` and `/ws/proxy/alerts`, when authentication is required | Closed with 4029 | Closed with 1013 |

These exact operations verify nothing, so neither a source's backoff nor the auth
store has any bearing on them. Any other method on those paths, a plain `OPTIONS`, and
every other path can reach a key check, so they are limited like everything else; a
test walks every HTTP, websocket and MCP route to hold this. On the API, `/.well-known/*` is one of
those other paths. The standalone MCP server serves its OAuth discovery documents there
without a check. They still pass the coarse per-IP limit, whose
shared store degrades to local limits in an outage. `AGENT_BOM_DISABLE_DOCS`
still removes the documentation routes.

Anonymous reads depend on their own data, which is why backends differ when a
database is down. On Postgres, auth state and data share one database, so an
anonymous read returns 503 from the route itself. On SQLite, auth state is a
separate sidecar file: losing it leaves anonymous reads working, and they fail only
if the data file does. Neither case is a clean result reported from missing data.

When the operator explicitly enables anonymous access, credential-free requests
to declared non-auth routes do not query failed-authentication state. They still
pass through the anonymous principal resolver, route authorization, and ordinary
global/read/write quotas. Viewers cannot perform analyst/admin operations;
anonymous writes require the operator's existing no-auth role configuration.
Configuring credentials clamps anonymous fallback to viewer, even when
`AGENT_BOM_NO_AUTH_ROLE` requests a higher role. Presented keys, sessions and
proxy identity headers, auth endpoints, configured SCIM paths, and unclassified
routes retain authentication admission. Removing credentials grants only the
access already explicitly configured for anonymous callers; it cannot grant
an authenticated identity or bypass the role gate.

Only source addresses incur backoff; a claimed key or tenant cannot consume
another source's allowance. Backoff rejects requests from the blocked source
before credential verification, including valid keys and sessions. Users behind
one NAT or unconfigured load balancer therefore share the block.

### Source identity behind a proxy

Configure both `AGENT_BOM_TRUSTED_PROXY_CIDRS` and `AGENT_BOM_TRUSTED_PROXY_HOPS`
on every replica. The session attempt limit on `/v1/auth/session` and the OIDC, SAML
and Snowflake sign-in routes uses the same source, and a blank key is refused before
it spends any attempts. Every `X-Forwarded-For` line is combined in received order before
hops are counted, so a second line cannot select or forge the source. Only the
trailing trusted hops are read for this limit, so padding the chain changes nothing;
other consumers still treat a chain over 32 entries as untrusted. An IPv6 source
is limited as its /64, since one customer routinely holds at least that much, and an
IPv4-mapped address counts as its IPv4 address. A receipt for such a source also
records the exact address as `client_address`.

| Profile | Behaviour |
|---|---|
| Helm with `controlPlane.ingress.enabled` | Rendering fails unless `controlPlane.api.trustedProxy.hops` and `.cidrs` are set (or both variables in `controlPlane.api.env`), `.fromSecret=true` with `.secretName` reads both from that Secret as required keys, so a pod without them does not start, or `.sharedSourceAccepted=true` records that one budget is intended |
| Compose hosted-POC overlay | One hop, trusting Docker's default address pools `172.16.0.0/12` and `192.168.0.0/16`. Override both variables for a custom pool. `hosted_poc_preflight.py` fails if either is empty |
| Compose platform and fullstack | Both variables pass through and default to empty, for a loopback bind with no proxy |

Each condition below warns once per process, without logging header contents:

| Condition | Meaning |
|---|---|
| Forwarded header with no proxy settings, or proxy auth without them | Clients behind that proxy share one budget |
| Forwarded header from a peer outside the CIDRs | The peer address is used. If it is your proxy, correct the CIDRs |
| Only `X-Real-IP` arrives | It is not used. Configure the proxy to send `X-Forwarded-For` |
| No transport peer, as on a unix socket | Forwarded addresses cannot be trusted and all clients share one budget. Listen on TCP behind the proxy |
| A trusted entry that cannot be read as an address | Ports (`203.0.113.7:51234`, `[2001:db8::7]:443`) and quotes are accepted. Anything else is limited as one shared `unparseable-forwarded-address` source, never as the proxy's own address, so it cannot block clients whose entries are readable. Check what the proxy writes |

A proxy cannot be detected before it makes a request. Owned API/MCP launchers
disable server-side proxy-header rewriting. For direct ASGI deployment, use
`uvicorn --no-proxy-headers` to preserve the transport peer.

### What counts as a failure

Only the handler that verified a credential marks a failure, by setting
`request.state.authentication_failed`. A status code alone never counts.

| Counts | Does not count |
|---|---|
| Wrong API key, in `Authorization: Bearer`, `X-API-Key` or `POST /v1/auth/session` | Nothing presented, including the logged-out dashboard's `/v1/auth/me` |
| Unsupported `Authorization` scheme | Proxy identity headers with no attestation secret |
| Unreadable browser-session cookie | Expired or revoked session, or one signed before a signing-key change |
| JWT that fails verification, including a bad signature on an expired token | Expired JWT with a valid signature; identity provider or token endpoint unreachable or returning 5xx |
| Wrong key or attestation secret on a websocket, by header or first message | Websocket key without the required scope or role; a token in the URL, which is refused unread |
| Wrong SCIM bearer or wrong proxy attestation secret | Inactive SCIM user or inactive trial, whose identity did verify |
| Invalid trial invitation, failed OIDC code exchange or SAML assertion | Missing OIDC or SAML state; missing report download token on a valid key |
| OAuth `invalid_client` and `invalid_grant`; standalone MCP 401 when a token was presented | Generic 400/403 validation or authorization errors; MCP challenge with no token |

A session with a well-formed envelope and an unexpected signature is not counted,
because a key rotation produces exactly that. Forging one needs the signing key, so
an unlimited count of such attempts gives no guessing advantage; the coarse per-IP
limit still applies to them.

`auth.failed` receipts use the reserved `__auth_security__` operator chain,
not the default tenant's audit chain. Tenant audit list, integrity and export
routes cannot select that chain; privileged operator collection uses the
underlying audit store/database. Receipts contain the validated source, status
and an audit-keyed HMAC-SHA256 credential fingerprint in `hmac_sha256`, with a
separate purpose prefix. Logs alone cannot validate credential guesses. Raw
keys, cookies, tokens and credentials are never retained. Rotating the audit
signing key changes these fingerprints, so correlation does not continue across
rotation; retained receipts are not rewritten. Preserve prior verification keys
under the operator's evidence-retention policy.

Receipt admission permits at most three per source per minute, and 100 per deployment
for repeat receipts. A source's first receipt in the window has a ceiling of 400, with
at most 25 per IPv4 /16 or IPv6 /48, so one network's flood cannot erase other sources'
only record. A flood across hundreds of networks can still spend it, and the
`auth.receipts_dropped` entry then records the loss. Blocked requests do not append another receipt. These sampled records
establish observed failures, not an exhaustive attempt count or independent
collector evidence.

### What integrity checks detect

`verified` rows check out under the held signing key. `tampered` rows are shown to
have changed. `unverifiable` rows are ones no held key can check, reported with
`status: partially_unverifiable` and an explanation. It is never a clean result.
Links between rows and the stored count and head need no key, so reordering, deletion
and truncation are detected in every state, unless the stored checkpoint was rewritten
to match and the chain's genesis row survives.

| State | Row contents | Reported |
|---|---|---|
| SQLite, row from the key's boundary up to the next key's | Any change is detected | `verified` or `tampered` |
| SQLite, row before the key's boundary or in another key's range (an earlier key, or an ephemeral key that is gone) | Changes are **not** detected | `unverifiable`, unless it verifies under the held key |
| Postgres, row at or after the first row the key verifies | Any change is detected | `verified` or `tampered` |
| Postgres, row before that | Changes are **not** detected: a different earlier key and altered contents cannot be told apart | `unverifiable` |
| Postgres, every row fails its signature with links and count intact | A different key and every row altered cannot be told apart, including a single-row chain | `unverifiable` |

On SQLite, the first time a key opens the log it signs a boundary: rows from there until
the next key's boundary must verify under it. Configuring or rotating a key therefore
needs no other action, and tampering after that point is reported exactly. Opening once
with the wrong key loses nothing when the right one returns. To check older rows, restart
with the key that wrote them; other keys' rows then read `unverifiable`.

A boundary can be signed only with its key, so editing that table cannot make a row read
as verified, and a row it covers cannot be excused by rewriting its boundary. An added
unsigned boundary can end a key's range early, which turns later failures into
`unverifiable`: visible and never clean, but not exact. Deleting every boundary
removes the boundary until the next start, when a new one begins at the end of the log.
Rows the key still verifies keep later rows exact, but changes before the first such row
then read `unverifiable`, as on Postgres. Postgres keeps no record of the key.
This local metadata is a diagnostic receipt, not independent tamper evidence: an actor
holding both the records and the key can rewrite them undetected.

The key identity row is a salted HMAC of the key's digest, and a database opened with an
older unsalted digest is upgraded in place. Testing a candidate key against it costs about
one HMAC-SHA-256, the same as testing one against any stored audit row with known contents,
so it adds no offline guessing route, and a slow derivation would protect nothing while
those rows exist. Use a high-entropy signing key.

A larger chain is not walked. The integrity response and export report
`status: not_verified_over_budget`, `verified: null` (no count exists, which differs
from zero rows verifying), `checked: 0`, `unverifiable`, `total_entries` and
`verification_limit`, and the dashboard says "Not verified" with those counts. The
HTTP limit is at most 10,000 entries; larger histories require offline verification
with an explicitly larger budget. Configure `AGENT_BOM_AUDIT_HMAC_KEY` before using
persistent audit logs as evidence.

### STRIDE assessment

| Threat | Scenario and mitigation | Remaining constraint |
|---|---|---|
| Spoofing | A second `X-Forwarded-For` line or IPv6 rotation sought a fresh budget. Lines are combined before hops are counted; IPv6 is limited by /64 | Shipped defaults trust Docker's pools on the hosted overlay; anything else that can reach the API over those networks is trusted |
| Tampering | Rows are held to the key from its signed boundary, and links and counts need no key. Key digest stored as a salted HMAC | Rows before a key's boundary are unverifiable. Postgres cannot tell altered rows from a different key before the first row that verifies. An actor controlling both the records and the key can rewrite them |
| Repudiation | Receipts leave the request path, so a stall can no longer block on them. Drops are counted, logged, and recorded in the chain | Receipts still queued two seconds after process exit starts are lost, with an error logged |
| Information disclosure | Warnings use fixed text with no header values; receipts hold a keyed fingerprint and validated addresses | Exact addresses in receipts are visible to operators who can read that chain |
| Denial of service | Expired sessions, missing credentials and missing report tokens no longer lock out a source. Audit stalls, dead connections and one source's failures no longer refuse others | A shared NAT or /64 still shares one budget. Three consecutive real store errors still fail closed for everyone |
| Elevation of privilege | Exempt routes are an exact list of public documents that verify nothing. Admission still fails closed for anything presenting a credential | Uncounted well-formed session forgeries rely on the signing key staying secret |

Regression evidence: `tests/test_auth_failure_defects.py`,
`tests/test_auth_failure_deployment.py`, and `tests/test_auth_failure_processes.py`,
which runs separate server and client processes against SQLite and a private Postgres
cluster and skips where Postgres server binaries are not on `PATH`. The secret-group
behaviour was exercised against real Linux permissions with `postgres:16-alpine`, not
through a complete `docker compose up` on a Linux host.
