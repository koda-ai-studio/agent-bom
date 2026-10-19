# Trust and deployment boundary

Reference for operators evaluating **agent-bom** in their own environment. For product lanes and hosted POC limits see
[`PRODUCT_BOUNDARIES.md`](PRODUCT_BOUNDARIES.md).

## What runs where

| Component | Default location | Customer control |
|---|---|---|
| CLI scanner | Workstation / CI runner | Customer executes; no hosted dependency |
| Control plane API + UI | Customer VPC / cluster / laptop | Self-hosted Helm, Docker, or local `agent-bom api` |
| Graph + findings store | Customer SQLite or Postgres | Data never leaves the configured boundary |
| Runtime proxy / gateway | Customer network path | Optional enforcement lane; explicit failure modes |
| Vulnerability intel | OSV/GHSA/NVD when online; bundled demo DB offline | Network egress is operator-controlled |

Scanning is read-only by default. The opt-in capabilities that change state
(disk side-scan, proxy enforcement and rollout, remediation, ticketing, outbound
destinations) and how each is scoped are listed in
[SECURITY.md — Trust model and permissions](../SECURITY.md#trust-model-and-permissions).

Managed multi-tenant SaaS is **not** shipped from this repository. Gated hosted
POC environments exist only for limited evaluation and are labeled as demo
estate data.

## Tenant isolation

- Every API request resolves a **tenant id** (header, session, or trusted-proxy
  binding). Cross-tenant reads and writes are rejected.
- Supported PostgreSQL deployments enforce tenant row-level security. SQLite
  pilots remain single-node; separate files define separate deployment environments.
- API keys, OIDC sessions, SAML assertions, and SCIM tokens are validated
  before route handlers run. Anonymous access is opt-in for local development
  only.
- Audit log entries are append-only and can be signed for tamper evidence
  (see compliance export paths).

## What we store (and do not)

**Stored:** inventory metadata, advisory-backed findings, graph nodes/edges,
credential **names** and refs, compliance control mappings, runtime event
metadata, audit actions.

**Not stored by default:** plaintext secrets, cloud API secret values, raw model
weights, or buyer source code (unless explicitly scanned from a path the
operator provides).

Redaction and `sanitize_error` / `sanitize_text` guards apply on API and log
paths so raw exceptions do not leak paths, ARNs, or connection strings.

## How evidence is derived

1. **Discovery** — agents, MCP servers, packages, cloud connectors, fleet
   heartbeats.
2. **Reachability** — symbol/graph reach, effective reach bands, runtime
   observed/blocked tool calls.
3. **Posture** — CNAPP-style overlays, IAM effective permissions, governance
   drift.
4. **Export** — JSON, CSV, Parquet, SARIF, CycloneDX, and signed compliance
   bundles share the same underlying finding rows (`framework_tags` parity on
   API/CSV/Parquet).

The finding drawer **Why it matters** block summarizes reach, runtime state,
blast radius, and compliance tags so operators do not have to read four screens
to prioritize.

## First proof commands

```bash
# Local scanner (no network)
agent-bom agents --demo --offline

# Release smoke (install → scan → export)
./scripts/release_smoke.sh

# Labeled control plane estate
agent-bom api --demo-estate --allow-insecure-no-auth
```

Artifact: terminal findings, dashboard queue/graph/runtime surfaces, exportable
reports. Demo estates are watermarked **Demo data — sample environment** in the UI.

## Verification hooks

| Check | Command |
|---|---|
| Release smoke | `./scripts/release_smoke.sh` |
| Pre-tag consistency | `scripts/preflight_release.sh` |
| Pilot install | `scripts/pilot-verify.sh <url> <api-key>` |
| Runtime HITL queue | `GET /v1/runtime/approval-queue` · decisions require `policy.manage` |
| Product screenshots | `cd ui && npm run capture:product-proof` |

## Claim To Code Map

| Claim | What it means | Code |
|---|---|---|
| API key auth + RBAC | API keys carry `admin` / `analyst` / `viewer` roles and are checked per route prefix | `src/agent_bom/api/auth.py`, `src/agent_bom/api/middleware.py` |
| OIDC / SSO | Any standard OIDC provider can issue bearer tokens for API access | `src/agent_bom/api/oidc.py`, `src/agent_bom/api/middleware.py` |
| Fail-closed tenant claims | Missing tenant claims now fail closed by default; `AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1` is the explicit single-tenant compatibility override | `src/agent_bom/api/oidc.py` |
| SCIM lifecycle provisioning | IdPs can create, list, patch, deactivate, and group users through a dedicated SCIM bearer surface | `src/agent_bom/api/routes/scim.py`, `src/agent_bom/api/scim_store.py`, `src/agent_bom/api/postgres_scim.py` |
| Postgres tenant isolation | The authenticated tenant is pushed into the DB session as `app.tenant_id` before request handling | `src/agent_bom/api/middleware.py`, `src/agent_bom/api/postgres_store.py` |
| PostgreSQL row-level security | Tenant-bearing tables have RLS policies keyed off the current tenant | `deploy/supabase/postgres/init.sql`, `src/agent_bom/api/postgres_store.py` |
| API keys persisted in Postgres | Keys move from in-memory to transactional storage when `AGENT_BOM_POSTGRES_URL` is set | `src/agent_bom/api/server.py`, `src/agent_bom/api/postgres_store.py`, `src/agent_bom/api/auth.py` |
| Exceptions and false positives persisted in Postgres | Exception workflow uses a tenant-aware Postgres store when configured | `src/agent_bom/api/server.py`, `src/agent_bom/api/postgres_store.py`, `src/agent_bom/api/routes/enterprise.py` |
| Audit log integrity | Audit entries are chain-signed with HMAC and can be verified via API | `src/agent_bom/api/audit_log.py`, `src/agent_bom/api/routes/enterprise.py` |
| Rate limiting | Read and scan endpoints have separate request budgets with shared Postgres-backed storage when configured | `src/agent_bom/api/middleware.py`, `src/agent_bom/api/postgres_store.py` |
| Request tracing | API preserves W3C trace context and exposes tracing state on authenticated `/v1/system/health` | `src/agent_bom/api/tracing.py`, `src/agent_bom/api/middleware.py`, `src/agent_bom/api/server.py` |
| ClickHouse analytics backend | Server mode can buffer analytics writes and report backend state on authenticated `/v1/system/health` | `src/agent_bom/api/server.py`, `src/agent_bom/api/clickhouse_store.py` |
| Snowflake backend | Snowflake has native stores for selected enterprise data paths, not full transactional parity | `src/agent_bom/api/server.py`, `src/agent_bom/api/snowflake_store.py` |

## Trust Boundaries

| Boundary | Trust level | Controls |
|---|---|---|
| Browser to UI/API | authenticated enterprise user | ingress TLS, OIDC/proxy auth, httpOnly same-origin session cookie, CSRF protection |
| API to stores | trusted service path | tenant propagation, Postgres RLS, parameterized stores, bounded connection pools |
| Scanner to local files | local user trust boundary | read-only config parsing, path validation, redaction of credential values |
| Scanner to public vuln APIs | untrusted external data | HTTPS, defensive parsers, no code execution from responses |
| Gateway/proxy to upstream MCPs | untrusted upstream | policy evaluation, credential/PII leak detectors, SSRF/private egress blocking |
| API to SIEM/webhook/export targets | operator-approved egress | scheme and private-network validation before outbound push |
| Release artifacts to operator | public supply chain | Sigstore, SLSA provenance, SBOMs, dependency review, image scan gates |

## Data Classification

| Data class | Examples | Default handling |
|---|---|---|
| Inventory metadata | packages, MCP server names, tool names, endpoint IDs | stored in customer-owned Postgres or export files |
| Findings | CVEs, risky permissions, policy hits, blast radius | tenant-scoped API and store paths |
| Audit records | actor, action, resource, tenant, details digest | HMAC-chained per tenant, exportable and verifiable |
| Credentials | API keys, OAuth client secrets, cloud tokens | values are not stored in scan output; deployment secrets live in operator secret stores |
| Compliance evidence | signed bundles, verification keys, audit export | Ed25519 preferred for auditor-distributable verification |
| Telemetry | Prometheus metrics, traces, client error reports | self-hosted endpoints; no mandatory vendor telemetry |

## Encryption And Signing Matrix

| Surface | In transit | At rest | Integrity |
|---|---|---|---|
| Browser/API traffic | customer ingress TLS | Postgres/customer store | request ID, audit entry |
| API keys | HTTPS/TLS at ingress | scrypt-hashed or stored key metadata only | rotation and revocation audit |
| Browser session cookie | same-origin secure cookie in production | signed token payload, no JS-readable bearer token needed | HMAC signature with configured or ephemeral key |
| Audit log | API transport | Postgres or configured audit store | per-tenant HMAC chain |
| Compliance bundle | API transport | operator archive | Ed25519 signature, HMAC fallback |
| Postgres backup | S3/TLS | S3 SSE-S3 or SSE-KMS | restore drill and checksum verification |
| Release artifacts | GitHub/Docker registry TLS | operator artifact store | Sigstore, SLSA, SBOM, image signatures |

## Vulnerability Enrichment Posture

The scanner can enrich findings with OSV, NVD, EPSS, CISA KEV, and GHSA data.
Those sources are treated as untrusted external inputs and are fetched over
HTTPS with defensive parsing. `GET /v1/posture/enrichment` exposes a non-secret
runtime posture for each source: latest success, latest failure, cache hits,
configured SLO, and whether the current process sees the source as `ok`,
`stale`, `degraded`, or `unknown`. Operators should review this surface before
treating KEV, EPSS, or NVD-derived risk scoring as complete.

OSV `upstream` links connect distro advisories to upstream CVEs without making
those records aliases. EPSS uses the highest available probability and its
matching percentile; KEV uses the earliest available remediation deadline and
that entry's dates. `upstream_ids`, `epss_cve_id`, and `kev_cve_id` retain the
relationship and selected source CVEs in scan/check JSON and finding evidence;
CycloneDX/SPDX retain them through import/export. Upstream links do not replace
the distro's fix, severity, or advisory identity with an upstream value.
See the [OSV relationship definitions](https://ossf.github.io/osv-schema/#upstream-field).

After upgrading an existing local vulnerability database, run
`agent-bom db update --source osv --source epss --source kev` to repopulate upstream metadata.
The schema upgrade retains known findings and invalidates the old OSV sync
receipt. Old read-only databases stay readable but need a writable update to
recover links that older releases discarded. Missing enrichment remains unknown;
it does not establish that a vulnerability is unexploited.

## Secrets Lifecycle

Recommended production posture:

- source API, OIDC, OAuth2, audit HMAC, Ed25519, Postgres, and webhook secrets
  from the customer's secret manager
- mount Kubernetes secrets through External Secrets or equivalent CSI/IRSA
  controls
- set `AGENT_BOM_SECRET_PROVIDER` and `AGENT_BOM_EXTERNAL_SECRETS_ENABLED=1`
  when the deployment is backed by AWS Secrets Manager, Vault, External
  Secrets, or an equivalent customer secret manager
- set rotation timestamps for audit HMAC, compliance signing, SCIM bearer, and
  browser-session signing keys so posture endpoints can expose key age
- rotate API keys through the API rather than replacing all clients at once
- restart API/gateway workloads after rotating mounted signing or OAuth client
  secrets

`GET /v1/auth/secrets/lifecycle` and `GET /v1/auth/policy` expose a non-secret
summary of this posture. They report configured sources, key IDs when supplied,
rotation age, missing required secrets, and whether the deployment has declared
an external secret-manager authority. These endpoints never return secret
values.

`GET /v1/auth/secrets/rotation-plan` turns that posture into a non-secret
operator change plan. It prioritizes due, unknown-age, ephemeral, and required
missing secrets; includes AWS Secrets Manager, Vault, External Secrets/CSI, or
generic secret-manager command templates; and lists rollout, verification, and
timestamp-recording steps. The response is designed for change tickets and does
not automate custody-sensitive secret generation.

The rotation-plan response now exposes an explicit `rotation_adapter` object
for the configured `AGENT_BOM_SECRET_PROVIDER`. Supported adapters are:

| Provider value | Custody boundary | Rotation model |
| --- | --- | --- |
| `aws_secrets_manager` | Customer AWS account | `put-secret-value`, rollout restart, lifecycle verification |
| `hashicorp_vault` | Customer Vault cluster | `vault kv put`, rollout restart, lifecycle verification |
| `external_secrets` / `csi` | Customer upstream provider | Rotate upstream, wait for Kubernetes Secret sync, rollout restart |
| `kubernetes_secret` | Customer Kubernetes Secret | Apply a rotated env-file secret manifest, rollout restart |
| `operator_secret_manager` | Customer secret manager | Generic operator-owned change ticket and rollout |

Every adapter response sets `secret_values_included=false`, names the expected
secret-manager audit evidence, and includes a timestamp-recording command for
the matching `*_LAST_ROTATED` metadata. `agent-bom` never fetches or returns the
secret material.

`agent-bom` does not replace the customer's KMS, Vault, IdP, or privileged
access management system. The product exposes posture and supports rotation
paths; the operator owns secret authority, approval workflow, and key custody.

Rotation procedures and `*_LAST_ROTATED` env var names are public in this
repository; live secret values and production rotation timestamps are
operator-private. See [PUBLICATION_POLICY.md](PUBLICATION_POLICY.md).

## SCIM And Revocation Boundary

SCIM is the provisioned identity lifecycle store. User and group resources
include tenant-bound Agent BOM role metadata, but the tenant is still assigned
server-side from `AGENT_BOM_SCIM_TENANT_ID`; tenant fields in IdP payloads are
ignored for routing. Runtime authentication continues to come from API keys,
OIDC, SAML, browser sessions, or trusted reverse-proxy headers. A SCIM
deactivation records the lifecycle event and removes the provisioned active
membership view, but live OIDC/SAML/proxy sessions must be terminated at the
upstream IdP or proxy, and API keys must be revoked through the key lifecycle
API.

## Logging, Monitoring, And Incident Response

Relevant security signals:

- authenticated `/metrics` for Prometheus scraping
- SIEM integration for audit and finding export
- client error telemetry for dashboard failures
- HMAC audit export and verification endpoints
- PrometheusRule defaults for high-risk runtime and control-plane alerts
- private vulnerability reporting through GitHub Security Advisories

Incident response ownership remains with the self-hosting organization. The
published security policy defines maintainer disclosure SLAs for product
vulnerabilities; customer deployment incidents follow customer process.
`docs/ENTERPRISE_SUPPORT_MODEL.md` defines the supported-version window, patch
cadence, escalation paths, and the boundary between product vulnerabilities and
customer-operated incidents.

## Security Header Posture

Control-plane responses emit HSTS, CSP, frame, content-type, referrer, and
permissions-policy headers. HSTS defaults to
`max-age=31536000; includeSubDomains`; preload enrollment is intentionally
operator opt-in through `AGENT_BOM_HSTS_PRELOAD=1` because browser preload is a
domain-level commitment. Operators can also set
`AGENT_BOM_HSTS_MAX_AGE_SECONDS` when a shorter staged rollout is required.

`GET /v1/auth/policy` exposes the non-secret effective header posture under
`security_headers` so change windows can record whether preload is enabled and
which CSP mode is active.

Packaged self-hosted dashboard builds generate `ui_dist/csp-hashes.json` during
`scripts/build-ui.sh` and release packaging. When that manifest is present, the
API serves dashboard HTML with hash-based `script-src` entries instead of
`script-src 'unsafe-inline'`. If the manifest is absent, the dashboard posture
reports `inline_compat` so operators can see that the static export is using the
compatibility fallback.

## Availability, Backup, And Restore

The Helm chart includes an optional Postgres backup CronJob that writes custom
format `pg_dump` artifacts to S3-compatible storage. The restore script is
tested in CI through a MinIO-backed round trip. Production deployments should
set real RPO/RTO targets, bucket retention, KMS keys, object lock where needed,
and restore-drill cadence.

See `site-docs/deployment/backup-restore.md` for the operator runbook.

## Storage Schema And Upgrade Readiness

The control plane exposes a non-secret storage schema manifest in
`GET /v1/auth/policy` under `storage_schema`. SQLite and Postgres control-plane
stores record component versions in `control_plane_schema_versions`; graph
storage keeps its legacy `graph_schema_version` marker and is also listed in
the manifest; ClickHouse analytics creates the same schema-version table for
analytics readiness checks. Operators should capture this surface before and
after rolling upgrades so schema drift is visible alongside release, Helm, and
container version checks.

An audit hash chain and signatures support integrity checks against a retained checkpoint. They do not prevent an actor controlling the records and signing keys from deleting or rewriting evidence. Preserve independent collector/provider receipts and operator-controlled checkpoints when stronger assurance is required.

## Customer-Owned Evidence

Procurement packets for regulated deployments should include these operator-owned
artifacts alongside the product evidence above:

- IdP MFA, conditional access, group-to-role mapping, and SCIM assignment policy
- ingress TLS, private DNS, network policy, WAF, and egress policy
- KMS, Vault, Secrets Manager, or External Secrets configuration and rotation
  evidence
- Postgres HA, backup retention, restore drill records, and object-lock policy
- SIEM routing, alert ownership, incident response, and escalation contacts
- data retention schedule, DPA, subprocessor review, and support-access policy
- release approval record for the exact tag deployed
- internal escalation contacts for platform, security, IdP, cloud, and database
  owners

## Evidence Collection Checklist

1. Record the release tag, commit SHA, image digests, Helm chart version, and
   deployment mode.
2. Download the GitHub Release assets and verify Sigstore bundles, SLSA
   provenance, and SBOMs using `docs/RELEASE_VERIFICATION.md`.
3. Attach the CI check summary for CodeQL, dependency review, gitleaks, PR
   self-scan, package tests, UI validation, and release consistency checks.
4. Export tenant-scoped audit evidence with `GET /v1/audit/export` when the
   control plane is deployed.
5. Export or screenshot non-secret posture from `GET /v1/auth/policy`,
   `GET /v1/auth/secrets/lifecycle`, and `GET /v1/auth/secrets/rotation-plan`.
6. Attach restore-drill evidence from the backup/restore workflow or the
   customer's latest production restore exercise.
7. Attach customer-owned IdP, KMS, network, retention, and incident-response
   evidence.
8. Attach the self-hosted support boundary and escalation record from
   `docs/ENTERPRISE_SUPPORT_MODEL.md`, plus any customer-owned support contract
   or internal incident workflow.

## Operator references

- [Authentication and effective permissions](AUTH_SSO.md)
- [Deployment and rollout](DEPLOY_PLATFORM.md)
- [Operations evidence and recovery](ENTERPRISE_OPERATIONS_EVIDENCE.md)
- [Support and disclosure](ENTERPRISE_SUPPORT_MODEL.md)
- [Control walkthroughs](ENTERPRISE_SECURITY_PLAYBOOK.md)
- [Threat model](THREAT_MODEL.md) and [security architecture](SECURITY_ARCHITECTURE.md)
- [Control mappings](CONTROL_MAPPING.md) and [security testing](PENTEST_READINESS.md)

Product controls and local test receipts do not establish a certification, a customer restore result, or hosted-service readiness. The self-hosting organization owns its identity, network, key custody, retention, legal and incident-response controls.

## Finding and scan payload encryption at rest (deployment prerequisite)

Finding, scan, and graph payloads are **not** application-layer encrypted. This
is by design: confidentiality at rest is delegated to the storage layer so the
control plane stays operable across SQLite, Postgres/RDS, and object storage
without managing a payload-encryption key or breaking search, indexing, and
graph queries. Selected fields still get app-layer protection — managed API keys use per-key salted scrypt hashes, while model-broker virtual
tokens use SHA-256 hashes, the audit chain is HMAC-signed, browser sessions are
signed, and stored cloud-connection secrets use envelope encryption — but the
finding bodies themselves rely on encryption-at-rest from the backend.

For any buyer with a data-classification or regulatory requirement, treat these
as prerequisites before ingesting real findings:

- **Database at rest** — enable encryption on the Postgres/RDS instance (e.g. RDS
  storage encryption with a customer-managed KMS key) or the underlying volume
  (LUKS/EBS encryption) that backs SQLite.
- **Object storage at rest** — enable bucket/default encryption (SSE-KMS or
  equivalent) for any S3/GCS/Azure Blob destinations used for exports, backups,
  or air-gapped DB snapshots.
- **Access controls** — keep the database and object storage private to the VPC,
  enforce least-privilege IAM/DB roles, and rely on tenant `FORCE ROW LEVEL
  SECURITY` (Postgres) for multi-tenant isolation.
- **In transit** — TLS is always verified on outbound calls; terminate ingress
  TLS and prefer the delegated mTLS posture below for the proxy/gateway seam.

The published site mirror of this prerequisite lives in
[Enterprise MCP / Endpoint Pilot — Security properties](../site-docs/deployment/enterprise-pilot.md#security-properties)
and [Own-Infra EKS](../site-docs/deployment/own-infra-eks.md#finding-and-scan-payload-encryption-at-rest).

If a threat model requires application-layer (pre-storage) encryption of finding
payloads, that is not provided today; scope it explicitly rather than assuming it.

For secret lifecycle posture, production deployments should declare the external
secret authority and rotation metadata without exposing secret values:

```bash
export AGENT_BOM_AUDIT_HMAC_KEY="mount-from-secret-manager"
export AGENT_BOM_SECRET_PROVIDER="aws_secrets_manager" # or hashicorp_vault, external_secrets, csi
export AGENT_BOM_EXTERNAL_SECRETS_ENABLED=1
export AGENT_BOM_AUDIT_HMAC_LAST_ROTATED="2026-04-24T00:00:00+00:00"
export AGENT_BOM_COMPLIANCE_SIGNING_LAST_ROTATED="2026-04-24T00:00:00+00:00"
export AGENT_BOM_BROWSER_SESSION_SIGNING_KEY_LAST_ROTATED="2026-04-24T00:00:00+00:00"
export AGENT_BOM_SCIM_BEARER_TOKEN_LAST_ROTATED="2026-04-24T00:00:00+00:00"
```

Operators can verify the non-secret posture at `GET /v1/auth/secrets/lifecycle`
or inside `GET /v1/auth/policy`. For change windows, use
`GET /v1/auth/secrets/rotation-plan` to generate a non-secret operator plan
that names the affected env vars, customer secret-manager action, rollout
commands, verification curl, and `*_LAST_ROTATED` timestamp to record. The plan
never returns secret values and is safe to attach to an internal change ticket.

Production and multi-replica control planes require `AGENT_BOM_AUDIT_HMAC_KEY`
at startup. The local ephemeral fallback remains available for workstation
pilots only; using it in a production-shaped environment requires the explicit
`AGENT_BOM_ALLOW_EPHEMERAL_AUDIT_HMAC=1` escape hatch.
