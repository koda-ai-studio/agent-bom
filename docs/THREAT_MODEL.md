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
| Proxy, gateway and Shield | Policy enforcement applies to traffic routed through configured enforcement points; decisions and audit receipts record that scope. | Direct SDK/cloud-console calls and bypassed traffic remain outside enforcement. |
| Database and export destinations | Tenant-aware stores, configured encryption, redaction and authenticated delivery. | Database administrators and downstream retention/access policies remain part of the customer's trust boundary. |

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

Review this model after security-boundary changes and before release. Source
review: October 27, 2026, for the 0.111.0 candidate; publication and live
provider qualification are separate release evidence.
