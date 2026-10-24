# Connecting Clouds to agent-bom

Connect AWS, Azure, GCP, and Snowflake to the self-hosted control plane, verify
read access, and collect inventory and posture evidence.

Discovery uses read APIs with operator-granted permissions. Optional content
and deep-scan collection requires explicit scope configuration. Evidence is
normalized into the control plane's graph and findings stores. Workload identity
avoids stored connection secrets where supported; legacy credential modes store
encrypted provider credentials, including database connection strings. Runtime
enforcement and export destinations have separate permissions and data boundaries.

---

## Provider setup

| Provider | First command | Grant, evidence and limits |
|---|---|---|
| AWS | `agent-bom connect aws --emit --out agent-bom-aws-readonly.json` | [AWS setup](cloud/aws.md) |
| Azure | `agent-bom connect azure` | [Azure setup](cloud/azure.md) |
| GCP | `agent-bom connect gcp` | [GCP setup](cloud/gcp.md) |
| Snowflake | `agent-bom connect snowflake` | [Snowflake setup](cloud/snowflake.md) |

Deploy the grant in the source account, establish a connection, run inventory,
and inspect the returned source coverage before interpreting findings. See
[provider coverage](VENDOR_COVERAGE.md) for the generated collector catalog.

## Verify collection before interpreting posture

Run a metadata-only inventory with the existing provider credential, for example:

```bash
AGENT_BOM_AWS_INVENTORY=1 agent-bom cloud inventory --provider aws --profile scanner -f json > inventory.json
```

The artifact contains native resource lists under `providers` and execution
coverage under `scan_run`. Azure and GCP use `--subscription` and `--project`
with `AGENT_BOM_AZURE_INVENTORY=1` and `AGENT_BOM_GCP_INVENTORY=1`, respectively.
Keep artifacts private: resource and identity metadata can identify an estate.

Inspect `scan_run.outcome` and its scopes before calling the collection complete.
The command can exit successfully while some reads were denied. Stored cloud
connection reports also derive partial coverage from inventory warnings,
missing permissions, and errored or no-data benchmark checks. Failed controls
alone do not mean collection failed: a complete read can establish bad posture.
Collection gaps remain partial even when other accounts in the same run succeed.

Azure's optional Entra directory read includes human users, service principals,
groups and bounded membership expansion. It requires the separate Microsoft
Graph token and `AGENT_BOM_ENTRA_DISCOVERY=1`; ARM Reader alone does not enable
directory collection. User metadata comes from the read-only
[Microsoft Graph users endpoint](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0).
Unavailable pages and pagination limits leave coverage incomplete.

After a stored connection scan, inspect its inventory, findings and graph in the
same tenant. Full-snapshot reconciliation retains earlier evidence for a partial
target; a later complete snapshot can remove assets no longer present. This is
snapshot reconciliation, not a native incremental change feed. Validate updates,
deletions and reappearance in isolated replays before relying on removal behavior.
Cross-cloud links require matching identifiers or recorded relationships; having
three connected clouds does not itself establish communication between them.

## Interpret network and identity relationships

After collecting inventory, open a relationship in Investigation or Connections
and inspect its source, configuration receipt and unknowns. Inventory placement,
group membership, permission grants and observed calls have different meanings;
account ownership or shared VPC membership does not establish communication.

AWS load-balancer instance links require target-group registration with matching
account, region and VPC scope. The collector reads `DescribeTargetGroups` and
`DescribeTargetHealth`; denied reads preserve incomplete backend coverage. IP,
Lambda and load-balancer target registrations remain metadata until their graph
resolution is supported. A registered private backend remains visible without a
claim that the internet can reach it.

Subnet routing classification uses the explicit association, or the collected
VPC main route table, and active IPv4/IPv6 internet-gateway default routes.
Missing or transitional route evidence stays unknown. A public address, public
subnet classification, permissive rule or WAF association alone does not prove
end-to-end reachability or vulnerability mitigation. Configuration-only network
bindings are non-traversable for attack-path derivation and retain
`network_reachability: unknown` in their evidence. This excludes unsupported
attack paths; it does not assert that the resources are isolated.

Local compute and network identifiers include account and location scope.
Kubernetes AWS provider IDs lack an account: without a recorded
`k8s_cloud_account_id` in imported server connection metadata, that host remains
separate from account-qualified inventory. Existing stored snapshots retain their
original identifiers; recollection builds the scoped identifiers.

## Repository Terraform (optional)

The repository also includes `deploy/terraform/connect-*` grants for
operator-managed infrastructure workflows. Start with the wheel-safe command
above; each [provider guide](#provider-setup) describes the optional Terraform
path and its permissions.

## Workload identity for stored connections

Azure and GCP connections can use an operator-managed workload binding instead
of a stored client secret or service-account key. AWS continues to use STS
AssumeRole. Existing encrypted credential connections remain supported.

The operator mounts a JSON file and sets
`AGENT_BOM_CONNECTION_WORKLOAD_BINDINGS_FILE` to its path. Keep this file writable
only by the operator and mount projected token files read-only. A binding names
one agent-bom tenant, provider identity, target subscription/project, and expiry:

```json
{"bindings":{"azure-reader":{
  "tenant_id":"customer-a","provider":"azure","auth_mode":"workload_identity",
  "role_ref":"application-client-id","scope_id":"subscription-id",
  "directory_tenant_id":"entra-tenant-id",
  "token_file_path":"/var/run/secrets/azure/tokens/azure-identity-token",
  "expires_at":"2027-01-01T00:00:00Z"
}}}
```

Register it with `POST /v1/cloud/connections` using the authenticated tenant:

```json
{"provider":"azure","display_name":"Production","role_ref":"application-client-id",
 "auth_params":{"tenant_id":"entra-tenant-id","subscription_id":"subscription-id",
 "auth_mode":"workload_identity","credential_binding":"azure-reader"},
 "auto_scan_on_create":false}
```

Omit `external_id` for workload modes. Then call
`POST /v1/cloud/connections/{id}/test` to verify provider access and
`POST /v1/cloud/connections/{id}/scan` to collect evidence. A configured binding
is not verified access or completed assessment.

For Azure user-assigned managed identity use `auth_mode=managed_identity` and
omit the token file. For GCP use `provider=gcp`, `auth_mode=workload_identity`,
`role_ref=<service-account>@<project>.iam.gserviceaccount.com`, `scope_id=<project>`,
an operator-mounted JWT `token_file_path`, and the exact `audience`
`//iam.googleapis.com/projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>`.
GCP public `auth_params` contains `project_id`, `auth_mode`, and
`credential_binding`; omit Azure-only fields. GCP exchanges the projected JWT
with Google's fixed STS endpoint, then impersonates the bound service account
with the read-only cloud-platform scope and a 3,600-second token lifetime.

Configure issuer, subject, audience and attribute restrictions in the provider's
federation trust and grant only required discovery permissions. The provider
verifies the signed token; agent-bom does not treat decoded claims as proof.
Bindings default to `inventory_scope=account`; organization fan-out requires
`inventory_scope=organization` in both operator binding and connection.

Every broker use reloads the binding. Missing, disabled, expired, malformed or
mismatched bindings fail closed, with no fallback to stored or ambient keys.
Disabling a binding prevents new broker sessions; revoke already-issued tokens
through the provider when immediate revocation is required. Rotation of mounted
projected tokens is handled by the provider SDK. This is an operator-managed
reference, not an automatic vault integration.

SDK references: [Azure workload identity](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.workloadidentitycredential),
[Azure managed identity](https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.managedidentitycredential),
[Google identity pools](https://google-auth.readthedocs.io/en/latest/reference/google.auth.identity_pool.html),
[Google impersonation](https://google-auth.readthedocs.io/en/latest/reference/google.auth.impersonated_credentials.html).

## 1c. Control-plane Connections wizard (browser onboarding)

The dashboard **Connections** page runs the same read-only grant flow as a
three-step wizard: **Provider → Setup → Details**.

Manual connection scans are durable jobs: `POST
/v1/cloud/connections/{id}/scan` returns `202` with a `job_id`; poll `GET
/v1/scan/{job_id}` for completion. Send an `Idempotency-Key` header when a
caller may retry the POST so the retry receives the original job instead of
starting duplicate work.

**Scope (single target vs org fan-out).** By default each connection — and
`POST /v1/cloud/connections/{id}/scan` — covers **one** AWS account, Azure
subscription, or GCP project (AWS "All enabled regions" is still that one
account). Set `inventory_scope=organization` on the connection (AWS Connections
wizard **Whole organization** does this) so Connections `/scan` fans inventory
across member accounts / subscriptions / projects via the brokered management
credential. StackSet (or equivalent) is still required so member accounts have
the read-only role to assume. CLI enrichment and Helm scanner Jobs remain gated
by env flags (`AGENT_BOM_AWS_ORG_INVENTORY`, `AGENT_BOM_AZURE_ALL_SUBSCRIPTIONS`,
`AGENT_BOM_GCP_ALL_PROJECTS`; see §§3–5) — those flags are **Job/CLI only** and
are **not** required for per-connection fan-out. On the Helm CronJob, first-class
chart values map to those CLI flags:
`scanner.cloud.aws.orgInventory` → `AGENT_BOM_AWS_ORG_INVENTORY`,
`scanner.cloud.azure.allSubscriptions` → `AGENT_BOM_AZURE_ALL_SUBSCRIPTIONS`,
`scanner.cloud.gcp.allProjects` → `AGENT_BOM_GCP_ALL_PROJECTS` (optional
`maxAccounts` / `maxSubscriptions` / `maxProjects` cap the run). Connections org
gate = the row's `inventory_scope=organization`; Helm `orgInventory` never
flips that row. That column is the **only** switch: `PATCH
{"inventory_scope":"account"}` turns fan-out off, and a legacy row that carried
the scope under `auth_params` is promoted into the column on read (the
`auth_params` key is dropped) so the API, the stored row, the scan, and the UI
scope chip always report the same blast radius. Control-plane
`tenant_id` is the agent-bom tenancy key — it is
**not** an Azure AD tenant or AWS account ID; one CP tenant can own many
connections. Recurring connection scans need both scheduler opt-in
(`AGENT_BOM_CONNECTIONS_SCHEDULER`, or Helm
`controlPlane.connectionsScheduler.enabled=true` which injects that env) and a
per-connection `scan_interval_minutes` (default concurrency 4). Cadence is the
**intersection** of those two — an interval alone does nothing until the
scheduler is enabled. `scan_mode=continuous` enables mid-interval event drain
on each scheduler tick when a provider event queue/subscription env is set
(`AGENT_BOM_AWS_EVENT_QUEUE_URL`, `AGENT_BOM_AZURE_EVENT_QUEUE`,
`AGENT_BOM_GCP_EVENT_SUBSCRIPTION`); drain stamps `last_event_at` only — full
scans still use `claim_due_scan` / `last_scan_at`. `auto_scan_on_create`
defaults true and runs the brokered scan path immediately after Create
(failure marks the row `error` with a sanitized detail; the connection is kept).
Org fan-out caps: AWS 200
(`AGENT_BOM_AWS_MAX_ACCOUNTS`), Azure 500
(`AGENT_BOM_AZURE_MAX_SUBSCRIPTIONS`), GCP 200 (`AGENT_BOM_GCP_MAX_PROJECTS`).

### Practical enable path

End-to-end for one org-scoped AWS connection that keeps evaluating:

1. **Wizard** — dashboard **Connections** → Provider (AWS) → Setup. Prefer
   **Whole organization** so the grant script is StackSet-shaped and Details
   will store `inventory_scope=organization`.
2. **StackSet (or equivalent)** — apply the generated grant so every member
   account has the read-only role (ExternalId match). Confirm Role ARN output.
3. **Connection** — Details: paste Role ARN + ExternalId, set cadence
   (`scan_interval_minutes`), optional `scan_mode=continuous`, create. With
   `auto_scan_on_create` (default true) the first brokered `/scan` runs
   immediately and fans members when `inventory_scope=organization`.
4. **Cadence** — interval on the row alone is inert until the control-plane
   scheduler is on.
5. **Helm scheduler** — `--set controlPlane.connectionsScheduler.enabled=true`
   (injects `AGENT_BOM_CONNECTIONS_SCHEDULER=1` on the API). Pilot compose leaves
   this off; set the env explicitly if you want recurrence locally.
6. **Continuous + queue** — mid-interval event drain needs **both** gates:
   `AGENT_BOM_CONNECTIONS_SCHEDULER=1` from step 5 (the drain is a scheduler
   tick and no-ops without it, even with a queue configured) **and** the
   provider queue/subscription env on the API (`AGENT_BOM_AWS_EVENT_QUEUE_URL` /
   Azure / GCP equivalents) with `scan_mode=continuous`. Drain stamps
   `last_event_at`; full inventory still follows the due-scan claim path.

Do **not** set `scanner.cloud.aws.orgInventory` unless you also want the
**Helm CronJob / CLI** org-inventory Job path. That flag does not substitute
for `inventory_scope=organization` on the Connections row.

- **One ExternalId, carried end-to-end.** For AWS the wizard generates a single
  high-entropy `sts:ExternalId` **once** and carries it unchanged from Setup into
  Details. The value embedded in the copy-ready grant script (the one you paste
  into your trust policy) is the exact value the connection stores — the two can
  never diverge. "Regenerate" (Setup step only) mints a fresh value and updates
  both places together; only use it before you have applied the grant. The other
  providers' secret field is a real credential you paste (Azure client secret,
  GCP service-account key JSON, Snowflake PEM), encrypted at rest and never
  returned to the browser.
- **Roles.** Creating a connection or running a scan needs the **analyst**
  (Contributor) role or higher; **viewer** is read-only. The wizard and empty
  states surface your role and, when an action needs a higher one, the concrete
  way to elevate. Roles are the closed enum in `src/agent_bom/rbac.py`.
- **Scan depth (opt-in, read-only).** The Setup step's collapsed **Scan depth
  (advanced)** control keeps the default path least-privilege (`SecurityAudit` +
  `ViewOnlyAccess` for AWS, `Reader` for Azure, `roles/viewer` for GCP). Turning
  on **Deep-scan** adds the read-only *content* reads those baseline policies
  structurally exclude — AWS: Lambda code, ECR image pull, Inspector, CIS account
  contacts, Bedrock agents; Azure: `Key Vault Reader` + `AcrPull`; GCP:
  `roles/artifactregistry.reader` — the same grants as each module's
  `deep-scan.tf`. **DSPM object sampling** (AWS) grants read-only
  `s3:GetObject`/`s3:ListBucket` **scoped to the bucket ARNs you name** (never a
  wildcard). The choice threads into the generated grant script and, for the
  Terraform method, sets `enable_deep_scan_reads` / `dspm_s3_bucket_arns`. Headless
  parity: `agent-bom connect <aws|azure|gcp> --emit --deep-scan [--dspm-bucket
  arn:aws:s3:::…]`.
- **All regions (AWS).** The Details step offers an explicit **All enabled
  regions** toggle. Checked, the connection stores the `all` sentinel and the scan
  fans out across every enabled region (via `discover_inventory_all_regions`)
  using the one brokered role; unchecked, you scan the specific free-text
  region(s) as before.
- **Snowflake packaging.** The Snowflake Setup step chooses between the read-only
  **metadata role** (default) and the **Snowpark Container Services / Native App**
  — "run agent-bom inside your account." The native-app option generates the
  provider/private-preview install recipe inline, reusing the shipped package under
  `deploy/snowflake/native-app/` (see
  [`docs/snowflake-native-app/INSTALL.md`](snowflake-native-app/INSTALL.md) for
  the exact first command, artifact, and next step). The protected release lane
  builds and pushes all four SPCS images; external Marketplace availability still
  requires Snowflake Product Security and listing approval and is not claimed by
  the generated recipe.
  Headless parity: `agent-bom connect snowflake --emit --spcs`.

### Self-host defaults ("just works" on the shipped compose)

The pilot compose (`deploy/docker-compose.pilot.yml`) is preset so first-run
connect works without extra flags:

- `AGENT_BOM_NO_AUTH_ROLE=analyst` — a local **no-auth** stack resolves to
  analyst (not viewer), so you can connect and scan. `AGENT_BOM_DEMO_ESTATE=1`
  always clamps to read-only viewer for public demos.
- **Connection encryption key auto-seeded.** On first boot a local/no-auth stack
  generates a Fernet key at `~/.agent-bom/connections.key` (persisted in the data
  volume) and wires `AGENT_BOM_CONNECTIONS_KEY_FILE` to it, so creating a
  connection does not fail closed with `AGENT_BOM_CONNECTIONS_KEY unset` (503).
  Set `AGENT_BOM_CONNECTIONS_KEY` / `_FILE` or a managed key provider to bring
  your own; `AGENT_BOM_NO_AUTO_CONNECTIONS_KEY=1` disables auto-seeding.

The production-shaped compose (`deploy/docker-compose.platform.yml`) is
auth-required and takes every secret — including `connections_key` — from mounted
Docker secret files (write them with `scripts/deploy/hosted_poc_preflight.py
--write-secret`; see `deploy/secrets/README.md`). It never auto-seeds and never
carries plaintext secrets in the compose.

---

## Collection and permission boundary

Baseline inventory uses scoped metadata reads. Opt-in content inspection and
disk side-scans require separate permissions; disk side-scans may create and
clean up temporary resources. Stored connection secrets are encrypted in the
configured control plane. External enrichment and exports have their own egress
boundary. Read [Trust](TRUST.md) and [permissions](PERMISSIONS.md) before enabling
a collection lane. Missing permissions, partial results and unsupported
collectors do not establish a clean estate.

### Authorization evidence completeness

Azure RBAC and GCP IAM scans report whether every required authorization feed
was collected as `complete`, `partial`, or `indeterminate`. The authenticated
cloud-connection API, MCP inventory summary, CLI summary, and connection UI
expose only aggregate source counts. Raw bindings, conditions, diagnostics,
provider paths, and provenance stay in the tenant-scoped scan artifact and are
never copied into operator summaries.

`partial` and `indeterminate` are fail-closed states: they do not prove access
and they never fall back to name- or privilege-label heuristics on a supported
authorization-evidence path. The graph API records the same limitation under
`analysis_status.authorization_evidence:<provider>`.

CI verifies Azure/GCP parity, incomplete-source behavior, heuristic
containment, and tenant-isolated graph persistence with deterministic fixtures.
Credentialed Azure/GCP smoke evidence remains environment-owned; a fixture run
proves the contract but is not a claim that a particular customer tenant was
successfully scanned.

---

## Provisioning identity controls

The connect modules use randomized principal names, an AWS ExternalId, and
issuer/subject/audience constraints for federation. Review the emitted grant
and the source account's trust policy; these controls do not establish complete
least privilege or immunity from credential misuse.

## 7a. Audit-trail behavioral edges — no new role

Setting `AGENT_BOM_AUDIT_TRAIL=1` reads the security-relevant slice of each
cloud's native audit trail (AWS CloudTrail, Azure Activity Log, GCP Cloud Audit
Logs) into **behavioral graph edges** ("who *did* reach what"). It is opt-in,
read-only, and drops the raw events — logs stay in your account.

**It needs no new IAM role.** Audit-trail reuses the **same** read-only connect
role you already created:

| Cloud | Existing read-only role | Audit read | Already covered? |
|-------|-------------------------|------------|------------------|
| AWS   | `SecurityAudit` (+ `ViewOnlyAccess`) | `cloudtrail:LookupEvents` | **Yes — zero new permission.** `LookupEvents` is in the AWS-managed `SecurityAudit` policy. |
| Azure | `Reader` / `Security Reader` | `Microsoft.Insights/eventtypes/values/read` | Yes in standard setups — sits inside the built-in `Reader` role. |
| GCP   | `roles/viewer` | `logging.logEntries.list` | Yes in standard setups — sits inside `roles/viewer`. |

Net: turning on audit-trail behavioral edges costs **no new role** and, in
standard setups, **no new permission**.

> **The one exception family is the opt-in disk side-scan.** AWS EBS side-scan
> is exposed through the CLI with `AGENT_BOM_SIDESCAN=1`. Azure Managed Disk
> and GCP Persistent Disk lifecycle adapters run the same executor across the
> CLI, REST, MCP, UI, and the opt-in scheduler auto-trigger, resolving
> separately scoped lifecycle credentials from the provider default chain. Each provider requires
> a **separate, narrowly
> scoped lifecycle role** distinct from the read-only scanner role:
> `deploy/terraform/connect-aws-sidescan`,
> `deploy/terraform/connect-azure-sidescan`, or
> `deploy/terraform/connect-gcp-sidescan`. Audit-trail does not.

---

## 7c. Runtime/EDR workload evidence (optional, read-only, additive)

Disk side-scan is agentless and point-in-time. When an operator *already* runs an
EDR or runtime sensor, agent-bom can ingest that source's signals to **enrich**
the same canonical workloads — process executions, IOC detections, network
connections, file-integrity events, behavioural alerts. There is **no mandatory
host agent**: agent-bom neither installs nor requires a sensor, and runtime
evidence never replaces disk evidence.

Ingest is hardened and fails closed (`runtime_workload_evidence.py`):

- **Authenticated source.** Sources register identity metadata only. Batches require a
  verified API key or OIDC bearer credential with the exact
  `runtime:ingest:<source-id>` scope and a lifetime of at most one hour.
  Expired, revoked, unscoped and non-expiring keys fail closed. Tenant, provider,
  and account are taken from the authenticated source — a payload that claims a
  different provider/account is rejected (confused-deputy guard).
- **Freshness + provenance.** Every accepted signal must provide `observed_at`;
  agent-bom records it with `source_id` and `source_kind` in fixed-width UTC.
  Missing, unparseable, future-dated, or stale observations are rejected, as is
  a signal with no workload reference.
- **Deduplicated + isolated.** Signals dedup on
  `(tenant, provider, account, workload, dedup_key)`; that key leads every store
  query and is part of the dedup identity, so two tenants can carry the same
  logical signal without one dropping or leaking. Durable persistence has
  in-memory, SQLite (restart- and cross-process-safe), and Postgres backends
  (`runtime_workload_evidence_store.py`).
- **Metadata only.** Producers must submit redacted metadata references. The
  ingest contract keeps a bounded key allowlist and drops nested, raw-content,
  oversized, and known credential-shaped values; it is not a general-purpose
  secret vault or payload store.

**Honesty — additive, never a cleanliness claim.** Every evidence summary carries
`clean_workload_assertion: false`. A workload with no matching runtime signal is
marked `no_runtime_signal`, never "clean". Enrichment annotates workloads,
findings, and the nodes an attack-path campaign already traverses; it never adds a
graph edge, so reachability stays edge-derived and is never fabricated.

Wired today: findings surfaced by `GET /v1/findings` (and the overview /
compliance / observability reads that share the enricher) gain a
`workload_runtime_evidence` field on workload-scoped rows once a tenant has
signals; the JSON API export carries it automatically. Authenticated ingest is
available at `POST /v1/cloud/runtime-evidence/ingest`, CLI
`agent-bom cloud runtime-evidence-ingest`, and the MCP tool
`runtime_evidence_ingest` (sources via `AGENT_BOM_RUNTIME_EVIDENCE_SOURCES`;
empty registry fails closed). Graph persist and investigation graph loads
annotate matching CWPP workload nodes via the same index (tenant-scoped;
absence stays `no_runtime_signal`, never "clean"). JSON / SARIF / HTML report
exports carry the same field when it is already attached on a finding or when
the tenant durable evidence store is non-empty (`AGENT_BOM_TENANT_ID`). The
findings Evidence drawer shows a dedicated Workload runtime evidence panel
(separate from proxy/gateway reach badges). CLI
`agent-bom cloud side-scan-capabilities` prints the honest provider surface;
`agent-bom cloud side-scan --provider azure|gcp` runs the shipped executor
(opt-in via `AGENT_BOM_SIDESCAN`).

### Runtime producer authentication

Register source metadata on the control plane through
`AGENT_BOM_RUNTIME_EVIDENCE_SOURCES`, for example:

```json
[{"source_id":"edr-1","tenant_id":"tenant-alpha","provider":"aws","account_id":"123456789012","kind":"edr"}]
```

Use the existing authenticated `POST /v1/auth/keys` endpoint to provision a
producer key with the exact scope `runtime:ingest:edr-1`, its tenant, an admin role, and an explicit `expires_at` no more than one hour after issuance.
Alternatively, configure the existing OIDC verifier and use a verified bearer
JWT with the same exact scope, tenant binding, `iat` and `exp`. Source identifiers
in scopes are percent-encoded (for example, `edr/1` becomes `edr%2F1`). Wildcard
scopes do not grant source authority. Rotate credentials before expiry; API key
revocation is checked on each ingestion request.

For CLI and MCP, configure `AGENT_BOM_API_URL` and exactly one of
`AGENT_BOM_API_KEY` or `AGENT_BOM_API_TOKEN` in the process environment through
external credential provisioning. Use an HTTPS origin; HTTP is accepted only
for a loopback host. Set `AGENT_BOM_TENANT_ID` to the intended
tenant. Credentials are transmitted in authentication headers, never evidence
JSON or model-visible tool arguments. The MCP caller must independently pass
its existing authenticated write-authorization gate.

```bash
agent-bom cloud runtime-evidence-ingest --source-id edr-1 --file signals.json \
  --reason "Import approved runtime observations"
```

The command reports accepted, rejected and persisted counts. Inspect the
corresponding finding's workload runtime evidence next. `--no-persist` validates
through the same authenticated API without storing signals. It still requires a
configured control plane. Successful writes include audit status; an audit sink
failure after persistence is reported as partial, not as a successful audit.

**Migration:** remove `secret` and `secret_hash` from source registrations;
legacy registrations fail closed. Remove `secret` from API/MCP payloads and
`--secret` / `AGENT_BOM_RUNTIME_EVIDENCE_SOURCE_SECRET` from producers. There is
no shared-secret fallback. Evidence storage and existing receipts are unchanged.

The Azure/GCP disk side-scan is now surface-aligned across CLI
(`agent-bom cloud side-scan`), REST (`POST /v1/cloud/side-scan`), MCP
(`cloud_side_scan`), the `/cwpp` UI, and an opt-in scheduler auto-trigger
(`AGENT_BOM_SIDESCAN_SCHEDULER`, off by default) that re-runs each configured
target on a cadence — every surface driving the same `run_provider_side_scan`
executor and reading the same durable lifecycle store. The executors ship as
concrete Azure Managed Disk and GCP Persistent Disk adapters with injected SDK
clients, but no credentialed live smoke is claimed yet
(`credentialed_smoke=false`) — live proof requires scoped snapshot/attach/delete
permissions and execution on the selected collector host. The API uses its own
configured cloud identity; supplying a collector ID does not dispatch work to a
remote host.

Azure/GCP setup failures are stored as terminal, unevaluable executions with a
safe failure code. Exact retries with the same idempotency key return the stored
state and counts without running another cloud lifecycle. Changed collector,
location, or scan options conflict; legacy records without a request fingerprint
cannot prove equivalence and are rejected without rewriting history. A running
execution remains running on retry. A new CLI invocation creates a new execution;
it does not automatically resume an earlier cleanup.

Scan completion and cleanup completion are separate. Failed unmounts remain
recorded as partial cleanup; the owned attachment, clone disk and snapshot are
retained for operator recovery. No detach or delete is attempted on that path. Inspect the
execution's owned resources and warning codes before operator recovery; there is
no automatic acknowledgement of a failed local unmount. Zero findings apply only
to completed scan stages, never to a clean workload. The durable side-scan
artifact contains lifecycle metadata and counts; it does not create a canonical
package/CVE finding graph.

---

## 9. Cloud SDK freshness (a non-blocking coverage signal)

agent-bom reads each estate through the provider's own SDK (boto3, the Azure
management SDKs, the Google Cloud SDKs, the Snowflake connector). An SDK that
lags the version the connectors are built against can quietly miss provider
services or APIs added in newer releases — a gap that *looks* like coverage. So
the freshness of the SDK layer is surfaced, never left silent.

- **What it checks.** Each installed provider SDK is compared against a
  bundled *recommended floor* (the minimum pinned in the `pyproject.toml`
  extras). This is an **offline, deterministic** comparison — it never queries
  PyPI or a provider for the newest release, so it stays reproducible and
  air-gap safe.
- **Non-blocking by design.** This is a *signal*, never a gate: it never
  changes an exit code or fails a scan. An SDK below its floor produces a
  warning; a provider SDK you have not installed is only informational (a user
  who scans only AWS is never nagged about an absent Azure SDK).
- **Where it shows up.**
  - `agent-bom doctor` renders a **Cloud SDK freshness** section: each anchor
    SDK with its installed version, the recommended floor, and an upgrade hint.
  - `--agent-mode` scan metadata carries a `cloud_sdk_freshness` block
    (`status`, `stale_count`, and the flat list of warning messages) under
    `summary`, alongside the vuln-DB freshness fields, when the scan read a
    cloud provider. Scans that call no cloud API omit it.
- **How to refresh.** Upgrade the matching extra, e.g.
  `pip install -U 'agent-bom[aws]'` (or `[azure]` / `[gcp]` / `[snowflake]`).
- **Staying current automatically.** Dependabot keeps the provider SDKs on a
  safe cadence via the `cloud-and-ai-sdks` group in `.github/dependabot.yml`
  (boto3/botocore are data-driven and backward-compatible, so new provider APIs
  land through routine bumps).

### 9.1 Provider-API deprecation posture (a legacy-SDK exposure guard)

The freshness check above answers "is my SDK current?". A complementary signal
answers "does my install still depend on a provider API the vendor has
*retired*?" A retired API returns errors (for example Azure AD Graph now returns
HTTP 403), so a check that still routes through it under-covers or fails
silently.

- **What it checks.** A small, first-party-sourced watchlist of retired /
  deprecated provider APIs (e.g. the retired **Azure AD Graph API**, the
  deprecated **oauth2client** auth library), each keyed by the *legacy*
  distribution that speaks it. The probe is whether that legacy SDK is present
  in the environment — an **offline, deterministic** check evaluated against the
  current date.
- **Honest default is "clear".** agent-bom already uses the modern replacement
  for every entry (Azure identities/roles via Azure Resource Manager, GCP auth
  via `google-auth`), so the shipped posture is *clear*. The signal only lights
  up if a legacy SDK is dragged into the tree — a supply-chain / coverage guard.
- **Retired-API exposure.** When a retired API is *both* past its removal date
  and reachable via an installed legacy SDK, it is marked **gated** to preserve
  the existing posture schema. This means the environment remains capable of
  reaching that retired API; it does not claim a scanner consumed the helper or
  skipped a check. `removed_provider_apis()` exposes the posture set for callers.
- **Where it shows up.**
  - `agent-bom doctor` renders a **Cloud API deprecations** section (each API
    with its status and migration target).
  - `--agent-mode` scan metadata carries a `deprecations` block (`status`,
    `removed_count`, `at_risk_count`, `gated`, `warnings`) nested under
    `cloud_sdk_freshness`; `doctor --agent-mode` emits a
    `cloud_api_deprecations` section in its envelope.

### Duplicate control identifiers in earlier reports

New AWS benchmark runs evaluate VPC flow logging once, as check `3.9`; the
duplicate implementation under `5.6` has been removed. New Azure benchmark
runs evaluate storage account default network denial once, as check `3.8`;
the duplicate implementation under `3.2` has been removed. Update check-ID
filters from AWS `5.6` to `3.9` and Azure `3.2` to `3.8`. These are corrections
to agent-bom's implemented catalog, not a claim of complete benchmark coverage.

Each condition now contributes one result to pass/fail totals, the evaluated
denominator, findings and remediation. Previously saved reports retain their
original identifiers and totals; run a fresh assessment for corrected counts.
The generated benchmark inventory records the implemented checks. An official
coverage percentage remains unavailable without a repository-provenanced
authoritative catalog.

## Integration surfaces


The marks in the README header identify supported product surfaces. They do
not all mean the same kind of connector, and they do not imply identical depth.
This matrix names the shipped role and a direct way to verify it.

| Marks | Role | Shipped capability | First proof |
|---|---|---|---|
| Claude, Cursor, GitHub Copilot, Windsurf, Codex CLI, VS Code, Cortex Code | Client discovery | Discover local and project MCP/client configuration, instruction files, servers, tools, packages, and relationships. These are configuration discovery paths, not vendor-account API connections. | `agent-bom where --json`, then `agent-bom scan .` |
| AWS, Azure, GCP | Read-only cloud connection | Connect with provider-native credentials; inventory cloud and AI assets; run posture, IAM, and benchmark checks with explicit permission gaps. | `agent-bom connect aws --emit --out agent-bom-aws-readonly.json`, deploy it, then connect with its outputs |
| Kubernetes | Scan and deploy | Scan Kubernetes and Helm configuration, inspect live cluster posture when access is supplied, and deploy the self-hosted control plane with Helm. | `agent-bom iac k8s/`; see [Kubernetes deployment](../site-docs/deployment/kubernetes.md) |
| Okta | Identity | Use Okta as an OIDC provider and optionally run gated, read-only non-human identity discovery. This is not presented as a full Okta CSPM connector. | `agent-bom identity discover --provider okta --format json` |
| Snowflake | Data platform | Read-only source and posture evidence, Native App packaging, and selected warehouse-backed product paths. | `agent-bom connect snowflake`; see [cloud connections](cloud/snowflake.md#6-snowflake--connect-with-a-key-pair-never-a-password) |
| Databricks | Data platform | SDK-backed discovery of clusters, libraries, and model-serving endpoints plus read-only security best-practice checks. | `agent-bom scan --databricks --databricks-security` |
| Prowler, AWS Security Hub | Report import | Import existing Prowler JSON-OCSF and Security Hub ASFF files as cloud posture and CVE findings with account, region, resource, compliance and tool provenance. File-based: no credentials, no network, no tool execution. | `agent-bom agents --external-scan prowler-output.ocsf.json`; see [scanner importers](IMPORTERS.md) |
| ClickHouse | Analytics backend | Optional tenant-scoped analytics store for findings, posture history, trends, and runtime events. It is a backend, not a scanned cloud account. | `agent-bom report analytics --clickhouse-url URL` |

Across these surfaces, raw credential values remain in the operator boundary.
Connections use environment references, provider credential chains, or
customer-managed secrets; partial permissions remain visible in scan outcomes.

See [product boundaries](PRODUCT_BOUNDARIES.md), [provider setup](#provider-setup),
and [agentic workflows](../site-docs/reference/agentic-workflows.md) for the
exact credential, artifact, and next-step contracts.
