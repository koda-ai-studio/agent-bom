# Gateway fail-open / fail-closed posture

Every gateway enforcement subsystem decides what happens when its *own*
machinery fails — a policy file that will not load, a store that errors, an
evaluator that raises. The canonical inventory is code, not prose:

- **Matrix:** `agent_bom.runtime.fail_mode.GATEWAY_FAIL_MODE_MATRIX`
- **Live view:** `GET /healthz` on the gateway, under `fail_mode_runtime`
  (resolved against the running `AGENT_BOM_GATEWAY_FAIL_MODE`)
- **Regression pin:** `tests/test_runtime_fail_mode.py`

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
| Later call to a removed tool | forwarded | proxy rejects it before the server sees it; alert `action: blocked` |
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

What enforcement acts on: `response_inspector` detections in the categories
`prompt_injection`, `semantic_injection`, `cloaking`, `svg_payload` and
`invisible_text` at high or critical severity, and all `vector_db_injection`
detections. Medium-severity semantic scores and base64 blobs stay alert-only.
Error responses and notifications are not inspected by this profile; inline
scanning (`inline_scanning` in the policy) and gateway DLP still cover them.

Why poisoned tools are removed rather than rewritten: a description is not the
only place a tool carries instructions (`inputSchema` field descriptions and
annotations are scanned as well), and a placeholder description would leave a
callable tool whose behaviour the client can no longer judge. Removing it fails
safe. The stdio proxy also refuses calls to it for the rest of the session; a
later clean `tools/list` restores it. The gateway relay keeps no session state,
so it strips the tool from each listing but does not refuse a call made with a
cached name. The result of such a call is still inspected.

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
