# Threat Model

This document describes the source-level trust boundaries and residual risks of
agent-bom. It complements [SECURITY.md](../SECURITY.md),
[Permissions](PERMISSIONS.md), and [Runtime failure modes](RUNTIME_FAIL_MODES.md).
It does not certify a deployment or establish that a finding is exploitable.

## Deployment and actors

The customer controls the host, identity provider, credentials, databases,
network policy, TLS termination, and independent evidence retention. A local
CLI scan, self-hosted API, MCP server, proxy, and gateway have different
privileges; enabling one does not grant permission to use the others.

Threat actors include malicious packages or registries, compromised MCP
servers, poisoned repositories and skill files, callers attempting to cross
tenant boundaries, and attackers controlling external metadata or model files.
An attacker who controls the scanner process, its signing key, and its evidence
store can defeat that local evidence boundary.

## Trust boundaries

| Input or capability | Boundary and control | Remaining uncertainty |
|---|---|---|
| Local repositories, configs, SBOMs, model files and archives | Treat contents as untrusted. Parse as data; bound reads, decompression and traversal. MCP paths are confined to home or explicit operator workspace roots. Helm charts with symlinks are refused before rendering or textual fallback. | Files can change during a scan. Static checks do not establish runtime behavior. Use an immutable input snapshot when concurrent filesystem mutation is a concern. |
| Advisory and package APIs | Normalize identities and preserve source, freshness, aliases and match evidence. | Stale feeds, unsupported ecosystems and missing inventory limit conclusions. Empty results do not establish clean posture. |
| Remote repository clone | Monitor file count and bytes during cloning, including `.git`; kill the clone process group on limit or timeout. Refuse symlinks before invoking any local parser. | Periodic measurement can overshoot between checks. Use a filesystem quota and isolated scan worker for a strict disk ceiling. |
| Serverless deployment ZIP | Stream downloads within 64 MiB; reject more than 10,000 members, members over 8 MiB, total expanded size over 256 MiB, or expansion over 100:1 before reading metadata. AWS function/layer, Azure and GCS failures report incomplete package coverage. | These per-archive limits are conservative and can reject legitimate large deployments. Concurrent scans still need worker admission and memory limits. |
| Container registry | Digest-checked manifests/blobs, bounded downloads, registry egress policy and credential handling. | A valid digest proves content identity, not publisher trust or absence of malicious behavior. |
| Docker daemon | Explicit image scanning may inspect/save a local image; automatic local-first selection can prefer a short reference already in the daemon. | The daemon socket is privileged. A local RepoDigest does not prove registry publication. |
| Cloud inventory | Ordinary discovery uses read-only provider permissions. Server connections and queries are tenant scoped. | An SDK response can be incomplete or denied. Connector availability is not proof that every service or account was assessed. |
| Kubernetes posture | MCP posture/workload tools require per-call `live=true` and the server live-introspection policy. | A refused collection is `not_collected`; it is not a successful empty scan. Kubernetes read permissions remain privileged. |
| API callers | Authentication, tenant context, role and route policy, request limits, CSRF/session checks and Host validation. | The customer must configure its IdP, TLS and proxy trust boundary correctly. An authorized administrator can perform documented destructive actions. |
| MCP callers and results | Strict arguments, path validation, explicit live/write gates, and untrusted-result notices. | JSON, notices, sanitization and injection heuristics do not make model consumption safe by themselves. |
| MCP `scan` `project_path` (filesystem) | The server reads a caller-supplied directory statically and read-only. The path must resolve, symlinks followed, to an existing directory inside the server user's home or a root listed in `AGENT_BOM_MCP_WORKSPACE_ROOTS` (absolute, non-root entries only); traversal, symlink escapes, files and missing paths are refused with `AGENTBOM_MCP_VALIDATION_INVALID_PATH`. | A caller with MCP access can enumerate any readable project under those roots. Keep the roots narrow and run the server as a low-privilege user; the sandbox bounds reads, not what the caller may ask about. |
| MCP live audit launcher | `mcp audit --live` and `mcp introspect` execute only commands whose basename is a recognized MCP launcher (version or shim suffixes such as `python3.13` tolerated). A path is accepted only when it is absolute and normalized, resolves (symlinks followed) to an existing regular, executable file whose resolved basename is also recognized, and neither the file nor the parent directory of the link or target is world-writable (sticky-bit directories such as `/tmp` included); relative paths, traversal segments, directories and writable files are refused, the server stays `security_blocked`, and a `launcher_rejected` coverage warning records the basename and failed check. | A recognized basename does not prove binary provenance: a user-writable `~/.venv/bin/python` is still the operator's own interpreter, and live introspection runs the configured server with the operator's privileges. The file checks run before the process starts, so a file swapped between check and launch by a user who can write it is not caught. Review configurations before `--allow-command-execution`. |
| MCP tool, resource and prompt descriptors | `scan --enforce`, `mcp audit --live`, `mcp introspect` and the runtime proxy share one rule set (`parsers/tool_poisoning_patterns.py`) for hidden instruction markup, concealment ("do not tell the user"), credential-file paths, exfiltration URLs, parameter smuggling, before/after-every-tool sequencing and natural-text base64 blobs. Rules run on the raw text and on de-obfuscated projections (zero-width removal, homoglyph and leetspeak folding, first decoded base64 run, at most 200 characters); every wildcard is bounded so matching stays linear. Each hit is a high finding tagged OWASP MCP03 / LLM01 and raises the introspected tool and server to at least high risk. | Detection is pattern-based: paraphrased, translated or multi-turn instructions and payloads in encodings other than base64 are missed, and benign descriptions that quote these phrases are flagged. A clean descriptor says nothing about what the tool does when called; pair with proxy enforcement and drift detection. |
| MCP session scan results (`result_id`) | `blast_radius`, `should_i_deploy` and `exposure_paths` answer from the caller's own stored `scan` result (explicit `result_id`, else the caller's newest) before persisted evidence, and label the answer `session_scan_result`. Results live in `mcp_scan_results` keyed by tenant plus a SHA-256 owner digest of the verified bearer token (stdio: the local OS user); every read filters on tenant, owner digest and expiry, an unknown, foreign or expired id is refused, and unauthenticated HTTP callers are denied. Results are capped at 128 MiB each and a per-tenant entry count. | A session result reflects the project the caller chose to scan, so a deploy answer built from it is only as trustworthy as that input; consumers should check `source`. Token rotation drops access to earlier results. The entry cap is per tenant, so heavy use by one caller in a tenant can evict another caller's results early (availability, not disclosure). |
| Report identifier redaction | Entropy-based redaction skips structural identifier keys (`exposure_path_id`, `package_purl`, `server_ref`, `bom_ref`, graph ids); credential-pattern and per-component sensitive-value checks still apply to every value, and credential-named keys are never exempt. | A low-entropy secret placed in an identifier-shaped field that matches no credential pattern is retained. Keep secrets out of package names, server names and paths. |
| Result push ingestion (`POST /v1/results/push`) | The CLI gzip-compresses pushes by default (`AGENT_BOM_PUSH_GZIP=0` disables it for receivers older than 2026-09-10). The control plane inflates in bounded steps of at most 64 KiB against a decoded budget of 256 MiB (`AGENT_BOM_API_RESULT_PUSH_MAX_BYTES`), refuses trailing or concatenated gzip members, and returns 413 once a body past 1 MiB decoded expands beyond 100:1, under the same read deadline and throughput floor as other bodies. Other routes keep the 10 MiB limit. Host validation, the IP rate limit and API-key authentication run before the body is buffered or inflated; tenant binding applies before the payload is stored. | Each in-flight push can hold up to the decoded budget in memory, so concurrent large pushes need worker memory limits and ingress rate limiting; with authentication explicitly disabled any reachable client can use that budget. The ratio cap is a heuristic: an unusually repetitive genuine report can be refused, and a body that stays under 100:1 is bounded only by the byte budget. |
| Exec read prewarm | After an authenticated push commits, or after the demo seed, the API queues one background warm-up of four read routes (posture counts, compliance summary, fix-first view, executive brief) for that push's tenant only. The routes are called in-process with a synthetic request bound to that tenant (`auth_method=prewarm`) and fill the same tenant-keyed response cache; nothing is returned to a caller. One worker thread per process, at most one pending warm-up per tenant, failures are logged and skipped, `AGENT_BOM_EXEC_PREWARM=0` disables it. | The warm-up bypasses the HTTP auth dependency by design, so any future route added to `EXEC_READS` must derive its scope only from `request.state.tenant_id`. The queue is per process: other workers or replicas still rebuild on their first read, and the extra reads add database load right after each push. |
| Local caches and analytics mirror retention | Current-estate projection files under `<state dir>/current-estate-cache` are swept on store construction: the newest 8 by last use stay, older ones go after `AGENT_BOM_CURRENT_ESTATE_CACHE_MAX_AGE_DAYS` (14), and the projection the process is opening is never removed. `agent-bom db prune` uses the same rule, previews by default and deletes only with `--yes`; it touches only `*.db` files (and their `-wal`/`-shm` siblings) in that directory. The local scan mirror drops whole runs older than `AGENT_BOM_ANALYTICS_MAX_RUN_AGE_DAYS` (90) or beyond `AGENT_BOM_ANALYTICS_MAX_BYTES` (2 GiB live) and always keeps the newest run. | Projections are rebuildable caches, but a process using one that is not among the newest 8 can have it removed by another process and pays a rebuild. Mirror retention discards local scan history; keep reports or a configured database if older runs are evidence. Neither sweep applies to Postgres or ClickHouse tables. |
| Release and registry automation | Workflows declare `permissions: {}` at the top and grant per job. The weekly MCP registry sync holds `contents: write`, `pull-requests: write` and `issues: write`: it signs its commit, force-updates one fixed branch with lease, and, when Actions may not open the pull request, creates or updates a single tracking issue with the diffstat and manual command and then fails. Issue text is built from counts and repository metadata, not from fetched registry content. | `issues: write` lets a compromised step in that job create or edit issues. Registry data from the official registry, npm and PyPI is untrusted and reaches `main` only through a reviewed pull request. |
| Proxy, gateway and Shield | Policy enforcement applies to traffic routed through configured enforcement points; decisions and audit receipts record that scope. | Direct SDK/cloud-console calls and bypassed traffic remain outside enforcement. |
| Gateway and posture audit outboxes | Durable per-tenant, per-destination queues (`gateway_audit_outbox` on Postgres, `posture_webhook_outbox` on SQLite) persist sanitized events before delivery. Rows are tenant-bound with RLS, admission is capped by bytes and row count, and delivery claims hold a database-clock lease; an acknowledgement deletes only rows that still carry the claimant's unexpired lease token (fenced), so a stale worker cannot drop work it no longer owns. Delivery is at least once. | The outbox is a second copy of audit evidence inside the database boundary: a database administrator can read, delete or replay it, and the receiving ledger must deduplicate event IDs. Lease expiry depends on the database clock, not the worker's. |
| Database and export destinations | Tenant-aware stores, configured encryption, redaction and authenticated delivery. | Database administrators and downstream retention/access policies remain part of the customer's trust boundary. |

## Collection scope and finding evidence

Ollama collection binds inventory to the selected endpoint. Failure of an
explicit endpoint does not substitute local manifests; implicit local fallback
is labelled as manifest inventory, not confirmed serving state. Missing AISVS
exposure evidence remains unknown. See `src/agent_bom/cloud/ollama.py`,
`tests/cloud/test_cloud_ollama.py` and `tests/test_aisvs_benchmark.py`.

Distribution-ambiguous package matches remain possibly affected until matching
distribution evidence resolves them. Missing scores and stale catalog evidence
remain visible in reports; neither proves absence of risk. See
`tests/test_scan_distro_cpe_possibly_affected.py` and
`tests/test_html_finding_details.py`. HTML pagination bounds visible rows, while
the full report remains in memory; it is not a total-memory limit.

IaC exceptions (inline markers, ignore-file entries, policy `allow` rules and
approved tenant exceptions) require a reason and never delete evidence: accepted
findings stay in JSON, SARIF and HTML with their source, origin, owner and
expiry, and leave only the gates. Expired or malformed exceptions are not
applied. Inline markers and ignore files are controlled by whoever can commit to
the scanned repository; a policy `block` rule with `"waivable": false` rejects
them, and only a tenant exception approved by a second admin can waive it.
Repository scans through the API and the MCP `scan` tool apply inline markers
and the bound tenant's approved exceptions only. See `site-docs/features/iac-exceptions-policy.md`,
`tests/test_iac_exceptions.py`, `tests/test_iac_policy.py` and
`tests/api/test_iac_tenant_exceptions.py`.

## Image evidence and signature verification

Registry discovery distinguishes `unsigned`, `present-unverified`, `verified`,
`invalid`, and `unknown`. Failed registry discovery is incomplete evidence, not
proof of an unsigned image. Local archives retain unknown signature status
unless verification evidence is available; the signature-required policy must
not accept unknown as verified.

Key-based verification binds the signature to the scanned digest. Keyless
Sigstore bundle verification requires the exact expected issuer and identity,
a matching subject digest, certificate verification, and transparency-log
verification using offline trust material. The Sigstore extra is optional;
missing verifier support fails the requested verification. Trust refresh is a
separate explicit operation. See [Image security](IMAGE_SECURITY.md) and
`tests/test_image_keyless_verification.py`.

Image layers can retain secrets even after a later whiteout removes the file.
The report distinguishes historical layer presence from the final filesystem.
Model inspection never loads a pickle as executable Python. Namespace `.pth`
startup files are distinguished from model checkpoints by bounded syntax
classification; that distinction does not claim startup code is safe to run.
Source PII matching distinguishes arithmetic from personal fields. Known
CPython documentation samples require an exact complete docstring hash and
expected source owner; changed samples and executable assignments remain
scannable. These are detection heuristics, not comprehensive DLP.

## Opt-in workload disk side-scans

Side-scans create snapshots/clones, attach temporary disks, read their contents,
and clean up those temporary resources. They require separate lifecycle
permissions. REST, MCP, and scheduled runs must bind the target to a tenant-owned
connection and an exact operator grant. Credential construction rechecks this
binding and does not fall back to ambient credentials. Ordinary GCP discovery
keeps read-only scopes; lifecycle scopes belong only to the authorized path.

Azure/GCP cleanup uses the durable execution ledger, versioned state claims,
fresh provider identity/ownership checks, and dependency order: detach before
deleting the clone, then delete the snapshot. Provider mutation uncertainty is
persisted before dispatch and retained when readback fails. Active workers,
conflicting ownership, timeouts, unmount failure and uncertain mutations prevent
automatic cleanup from claiming completion. Resources needing reconciliation
remain visible; matching tags alone do not authorize a provider-wide sweep.

AWS in-process cleanup stops after unmount, detach, wait, or deletion failure
and does not force detach. Automatic AWS crash recovery has no durable ownership
ledger and is disabled; operator reconciliation is required. These safety
contracts have fixture/SDK-fake regression coverage. They do not constitute a
live credentialed provider qualification. See [Cloud connect](CLOUD_CONNECT.md),
`tests/cloud/test_side_scan_cleanup_authority.py`, and
`tests/api/test_side_scan_connection_grants.py`.

## Anonymous public MCP tier

Off by default; enabled only by `--public-readonly` /
`AGENT_BOM_MCP_PUBLIC_READONLY=1` on Streamable HTTP. Assets: the server host's
files, configs and scan store; tenant and operator data; the bearer-protected
tool catalog; upstream advisory/registry quotas; process availability. Actor:
any internet client with no credential, able to send arbitrary JSON-RPC,
headers (including `X-Forwarded-For`) and rotating source addresses. Trust
boundary: the `/mcp` request without an `Authorization` header. Design and
tests: [MCP server](MCP_SERVER.md#public-read-only-tier),
`src/agent_bom/mcp_tools/public_tier.py`, `tests/test_mcp_public_readonly_tier.py`,
`tests/test_deployment_probe.py`.

| STRIDE | Attack | Mitigation | Regression test | Residual risk |
|---|---|---|---|---|
| Spoofing | Present a forged or expired token, or guess the internal anonymous credential, to reach full tools. | Any `Authorization` header takes the unchanged bearer path (no downgrade). The anonymous credential is 256 random bits per process, added only by the gate and never sent to clients. | `test_invalid_bearer_token_is_not_downgraded_to_anonymous`, `test_public_tier_without_bearer_token_still_refuses_other_tools` | None beyond the bearer path's own. |
| Tampering | Use an anonymous call to write tenant data, scan state or audit records. | Allowlisted tools are lookups with no store writes; write tools stay operator-token gated; everything else is refused. | `test_anonymous_non_allowlisted_tool_is_401`, `test_new_tools_default_to_auth_required` | Lookups still refresh agent-bom's own advisory caches, which hold public data. |
| Repudiation | Abuse anonymously without attribution. | Calls are recorded with caller `public-anon:<client address>` in the bounded request trace and logs. | `test_anonymous_rate_limit_is_per_caller_and_enforced` (caller keying) | Addresses are not identities; behind an unconfigured proxy every anonymous caller shares one label. |
| Information disclosure | Read host files, history, saved scans, operator advisories, metrics or resources; make the server fetch an internal URL (SSRF). | Default-deny allowlist (`check`, `intel_lookup`, `registry_lookup`) reviewed by implementation; argument sets pinned so a path/URL/host argument forces re-review; OS-ecosystem checks (host distro/package DB) refused; `intel_lookup` skips operator data for anonymous callers; resources, prompts and completions refused; registry fetches go to fixed origins with URL-encoded names. | `test_allowlisted_tool_schemas_take_no_host_or_url_arguments`, `test_anonymous_os_package_check_is_refused`, `test_anonymous_intel_lookup_skips_operator_advisory_data`, `test_anonymous_non_tool_methods_are_refused` | Responses reveal the server's advisory-data freshness and agent-bom version, both already public. |
| Denial of service | Flood lookups, rotate addresses, send large bodies, or spoof `X-Forwarded-For` to reset budgets. | 16 KiB body cap (413), 256-character arguments, per-client and aggregate anonymous budgets on top of the existing per-caller, global and concurrency limits; the client address is taken from the right of `X-Forwarded-For` only for declared trusted hops. | `test_anonymous_oversized_body_is_413`, `test_anonymous_overlong_argument_is_refused`, `test_spoofed_forwarded_prefix_does_not_reset_the_bucket`, `test_aggregate_anonymous_budget_caps_rotating_callers` | Budgets are per process, so replicas multiply them; upstream OSV/registry quotas are shared with authenticated callers; volumetric attacks need edge rate limiting. |
| Elevation of privilege | Call a non-allowlisted tool, a tool added later, or batch one in with an allowed call. | ASGI gate answers HTTP 401 for any anonymous `tools/call` outside the allowlist, including inside a batch; the MCP middleware independently refuses the same and filters `tools/list`; new tools are auth-required until reviewed. Startup refuses the tier with MCP OAuth and over SSE. | `test_anonymous_batch_with_non_allowlisted_call_is_401`, `test_public_tier_rejects_oauth_combination`, `test_cli_public_readonly_requires_streamable_http`, `test_public_readonly_probe_requires_http_401_not_a_jsonrpc_error` | The allowlist is a reviewed code constant; a mistaken addition is caught only by its argument-set test and review. |

Prompt injection: advisory summaries returned anonymously are third-party text
and carry the server's untrusted-data instructions, the same as authenticated
results; the tier adds no agent instruction surface.

## API and browser exposure

Non-loopback API binds require configured authentication unless an operator
explicitly overrides it. Tenant, role and write-scope checks apply to protected
routes. Viewer access is read-only; deletion and administration use elevated
route policies. Cookie sessions also require CSRF/origin checks for unsafe
methods. Host allowlists constrain browser-to-localhost/DNS-rebinding exposure;
non-loopback deployments should explicitly set their permitted hostnames.

Swagger UI and ReDoc use version-pinned external assets with subresource
integrity and fresh script nonces. Inline styles remain permitted for rendering.
`AGENT_BOM_DISABLE_DOCS=1` removes `/docs`, `/redoc`, and `/openapi.json`.
Configured webhook, ticketing and export paths have separate network and secret
boundaries; consult their operator runbooks rather than assuming every output
sink uses identical egress controls.

## Queue acknowledgement and evidence retention

AWS SQS and Azure Storage Queue event consumers use receive/delete permissions
on a configured queue. Successful dispatch is acknowledged; dispatch failure
leaves the message available for redelivery. Malformed and foreign-account
messages are discarded with counters, without retaining their original body.
Use dedicated per-connection queues and independently retained source events
for investigation or replay. A queue acknowledgement is a cloud mutation and is
not part of a read-only inventory claim. See [Permissions](PERMISSIONS.md).

The gateway and posture outboxes apply the same rule inward: a worker
acknowledges only the rows its own unexpired lease covers, an expired lease
makes the rows claimable again, and an acknowledgement reports whether every
claimed row was removed, so a caller cannot mistake a lost lease for a
completed delivery.

Audit hash chains and configured HMACs detect changes relative to a trusted
checkpoint/key. They cannot prove completeness against someone who can delete
or rewrite both the evidence and its checkpoint/key. Response signing is an
optional configured proxy capability; not every JSON-RPC message is signed.
Independent collector/provider records and externally retained checkpoints are
needed for stronger integrity claims. Missing events, truncation or a broken
chain indicate missing/unverifiable evidence, not proven malicious intent.

## Resource exhaustion and fail modes

Input limits cover compressed stored job/hub payloads, image blobs/layers,
model files, API requests and bounded result surfaces. Reaching a limit or losing
collection coverage must remain visible. Cypher export resolves node labels
with one lookup table instead of repeatedly scanning all nodes per edge.
These bounds do not make arbitrary inputs cost-free; operators still need
worker/resource quotas and appropriate retention.

Authentication, tenant binding, side-scan grants, signature-required policy,
and cleanup ownership checks fail closed. Collection errors preserve partial,
unknown or not-collected outcomes. Runtime observe/enforce policies and degraded
audit delivery have their own documented choices in
[Runtime failure modes](RUNTIME_FAIL_MODES.md).

## Scope limits and review

Agent-bom does not establish protection from unknown vulnerabilities, hidden
infrastructure, out-of-band actions, compromised administrator/IdP credentials,
all prompt injection, or model inference/privacy attacks. Configured access,
recorded relationships, observed execution, exploitability and impact are
separate claims. Verify remediation with a new scan of the same scope; a pin
change alone does not prove a running deployment was updated.

Review this model after security-boundary changes and before release.
Trust boundaries reviewed November 1, 2026, for the 0.113.0 release: MCP
descriptor poisoning detection, absolute-path launcher acceptance,
identifier-safe redaction, MCP session result scoping, gzip push budgets, exec
read prewarm, local cache and mirror retention with `db prune`, and the
registry-sync tracking issue. This scoped review does not establish full
security review, publication or live provider qualification.


### Consolidated scan and demo evidence boundaries

- MCP exception lookup resolves the server-bound tenant; callers cannot choose
  another tenant's suppressions. Store failure preserves active findings and a
  warning (`tests/test_iac_exceptions_mcp.py`). Approval and expiry still apply.
- Embedded MCP credentials contribute names to exposure counts; output retains
  the existing value redaction. Identity fingerprints retain their previous
  environment-key basis (`tests/test_mcp_embedded_credentials.py`).
- Demo intelligence receipts are partial, explicitly synthetic fixtures. The
  seeder refuses operator database paths or existing non-demo evidence, and
  maintenance checks persisted jobs and snapshot freshness before skipping work
  (`tests/test_demo_maintenance_receipts.py`). These receipts do not establish
  live feed freshness or independent validation.
- Go checksum candidates carry unknown reachability and low confidence; a
  historical checksum cannot raise a declared direct requirement
  (`tests/test_go_sum_pre_117_supplement.py`).
