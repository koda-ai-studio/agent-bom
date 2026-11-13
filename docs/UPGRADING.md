# Upgrade to 0.115.0

These instructions target 0.115.0 once its artifacts are published.
The source version alone does not establish package or image availability.

## Preserve configuration and evidence

Record the running package version and image digests. Back up the configured
database and retained reports using your backend's supported backup procedure;
preserve encryption keys, identity configuration, tenant settings and audit
checkpoints in your existing secret store. Test restoration before upgrading.
Do not overwrite evidence from earlier scans.

## Select the installed surface

After publication, in the existing Python virtual environment, choose the
same extras you use:

```bash
python -m pip install --upgrade agent-bom
# API / dashboard deployment:
python -m pip install --upgrade 'agent-bom[ui]'
# MCP server:
python -m pip install --upgrade 'agent-bom[mcp-server]'
agent-bom --version
```

These commands select the latest published package. Confirm the reported
version is 0.115.0 or a later release whose upgrade notes you have reviewed;
if it remains 0.114.0 or older, this upgrade has not been applied.

For a uv-managed CLI installation, use `uv tool upgrade agent-bom` after
publication and verify the resulting version. Preserve any additional cloud
extras required by your deployment. Base CLI installation does not install the
API server dependencies. `sca-import` replaces the deprecated `snyk` extra;
the old name remains a compatibility alias.

Use versioned images or recorded digests. The API, standalone UI, collector,
MCP stdio and MCP HTTP images have different entrypoints and dependency sets;
keep the image role aligned with your deployment manifest. Follow the
[deployment guide](../site-docs/deployment/overview.md) for your selected
profile and its migration procedure. Do not reuse the unpublished v0.112.0 tag.

## Changes from 0.114.0

- **Helm attestation.** A clustered or production control-plane API (more than
  one replica, an autoscaler, `AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT=1` or
  `AGENT_BOM_DEPLOYMENT_ENV=production`) fails rendering without request
  attestation: set `AGENT_BOM_TRUST_PROXY_AUTH=1` with
  `AGENT_BOM_TRUST_PROXY_AUTH_SECRET` and `AGENT_BOM_TRUST_PROXY_AUTH_ISSUER`
  (or app-native mTLS) in `controlPlane.api.env`, or put them in the auth Secret
  and set `controlPlane.api.listenerAttestation.fromSecret=true`. Such an install
  already refused to start without them.
- **Helm Postgres pool.** `AGENT_BOM_POSTGRES_POOL_MIN_SIZE` and `_MAX_SIZE` in
  `controlPlane.api.env` are rejected; use `controlPlane.postgres.pool.minSize`
  and `.maxSize` (defaults 2 and 20), which also set the role connection limits
  the migration Job applies. Pin larger limits with
  `controlPlane.postgres.connectionLimits`; with migrations disabled, apply them
  yourself. Postgres `max_connections` must cover them.
- **Helm NetworkPolicy.** A `NodePort` or `LoadBalancer` control-plane Service
  with the NetworkPolicy enabled needs `controlPlane.networkPolicy.ingressCIDRs`
  (or an `additionalIngress` rule).
- **Helm shutdown.** `controlPlane.api.terminationGracePeriodSeconds` defaults to
  60 and `controlPlane.worker.terminationGracePeriodSeconds` to 45; a shorter
  grace period than the `controlPlane.api.shutdown` budget fails rendering.
- **Scan lease.** `AGENT_BOM_API_SCAN_LEASE_SECONDS` defaults to 120 instead of
  600. Leases renew on their own thread, so long jobs are unaffected; an explicit
  value is kept.
- **Identities.** Inventory agents without their own `config_path`, and Ollama
  model agents (now named `name:tag`), change id once; reports list the earlier
  ids in `previous_canonical_ids` and `previous_graph_ids`.
- **Exports.** Parquet and Iceberg exports move to schema version 6
  (`malicious_basis` after `sla_due_at_source`). Read 0.114.0 files by column
  name, not position.
- **MCP OAuth tools.** An MCP server with OAuth registers only read-only tools:
  the default profile serves 7 tools, without `scan`. A static bearer token keeps
  all 8.
- **Hosted MCP images.** `Dockerfile.sse` and `Dockerfile.public-mcp` sync OSV
  (PyPI, npm), CISA KEV and FIRST EPSS before serving, so start-up is longer and
  the image health check allows a 240 s start period. Give a platform health
  check at least as long. A failed sync still starts the server.
- **Railway.** Railway stops reading `railway.json` on 2026-12-01. Migrate the
  OAuth MCP service (`railway config migrate`) or set its Dockerfile path to
  `deploy/docker/Dockerfile.sse` before then.
- **Persistence.** Apply Postgres migrations through `20261112_01`.
  `20261111_01` drops six unused indexes `CONCURRENTLY` (its downgrade
  recreates them); `20261112_01` raises a bounded `agent_bom_app` connection
  limit (1 to 99) to 100. A limit of 0, a role you locked on purpose, is kept
  and the migration logs a warning.

## Earlier changes from 0.113.2

- **MCP OAuth.** A server with `AGENT_BOM_MCP_OAUTH_*` settings refuses to
  start ("Incomplete or invalid MCP OAuth configuration") until these are also
  set: `AGENT_BOM_MCP_TENANT_ID`, `AGENT_BOM_MCP_OAUTH_INTROSPECTION_URL` on the
  issuer's origin, `AGENT_BOM_MCP_OAUTH_INTROSPECTION_CLIENT_ID`, and
  `AGENT_BOM_MCP_OAUTH_INTROSPECTION_CLIENT_SECRET` (or `_FILE`). Every token,
  including a deployment probe's, needs a signed `tenant_id` claim equal to that
  tenant. Configure the issuer's claim and introspection client before
  upgrading the server; see
  [MCP_OAUTH.md](MCP_OAUTH.md#self-hosted-keycloak-setup). A platform that keeps
  the previous container when a health check fails will go on serving 0.113.2.
- **Helm ingress.** Enabling `controlPlane.ingress` fails rendering unless
  `controlPlane.api.trustedProxy` declares the proxy in front of the API, or
  `sharedSourceAccepted` records that all clients share one authentication
  failure budget. `trustedProxy.fromSecret` requires `secretName`.
- **Demo Helm profiles.** `sqlite-pilot` and `synthetic-enterprise-story` no
  longer run without authentication. Add `AGENT_BOM_API_KEYS` to the
  `agent-bom-control-plane` Secret before upgrading; without it the pod stops at
  `CreateContainerConfigError`.
- **Teardown hook.** Its Role grants `deletecollection`, drops `get` and
  `list`, and holds `delete` on Secrets only for the names it removes. Review
  any policy that pins the previous Role.
- **Compose secrets and names.** Secret files are mode 0640 with your primary
  group and are read through `group_add`. For a direct `docker compose up`, set
  `AGENT_BOM_SECRETS_GID`. Fixed `container_name` values are removed; address
  containers through `docker compose` service names.
- **End-of-life Debian.** Scans of an end-of-life Debian release read `partial`
  until `agent-bom db update --source debian` loads the Debian Security Tracker
  data.
- **Health.** `/health` adds `sso_provider` (`okta`, `entra`, `google`,
  `generic` or null). It never includes the issuer, tenant or client id.
- **Persistence.** Apply Postgres migrations through `20261106_01`.
  `20261105_02` adds a dispatch attempt count, `20261105_03` adds per-finding
  lifecycle tables and cannot be downgraded (restore a reviewed backup to roll
  back), `20261105_04` adds AI assessment tables and `20261106_01` adds shared
  authentication state. The cleanup tick seeds lifecycle dates from retained
  scans after upgrade.
- **Finding counts.** `20261104_01` adds KEV, issue-group and coverage columns to
  current findings and backfills them in committed batches. Plan for up to one
  extra copy of `hub_findings_current` and its indexes on disk during the
  backfill. It stops after 30 minutes; a rerun or the control plane's cleanup tick
  continues, and until a tenant has no pending rows `finding_counts.kev_approximate`
  is true and the headline uses the exact occurrence counts. Rollback: the Alembic
  downgrade drops the columns, and a later upgrade recomputes them.
- **CVE records.** `20261105_01` links existing CVE findings to their CVE record
  and reconciles records whose column and payload disagree on KEV; KEV wins. It
  recomputes every current finding with no CVE link, including non-CVE findings,
  so plan for up to one extra copy of those rows and their indexes, and the same
  approximate KEV label until they finish. It stops after 30 minutes; a rerun or
  the cleanup tick continues. It changes no schema, so its downgrade does nothing
  and the values stay valid for earlier revisions. CVE fields a replacing writer
  already overwrote are not recoverable from the database: rescan to restore them
  (KEV flags and dates also return from a catalog sync).
- **KEV catalog.** The cleanup tick applies the newest fresh, complete CISA catalog
  it finds on that replica. See
  [STORAGE_BACKENDS.md](STORAGE_BACKENDS.md#kev-follows-the-cisa-catalog) for when
  one is available, and rerun `agent-bom db update` once to record completeness on
  an existing vulnerability database.

## Earlier changes from 0.113.0

- **Navigation.** The sidebar exposes all platform groups without a product-view
  preset. Retired browser preferences no longer hide pages or reporting.
  Permissions, deployment capabilities and local report scope still apply.
- **Continue discovery.** User-level `~/.continue/config.yaml` joins legacy
  JSON discovery. Review the discovered config paths after upgrading; inventory
  can now include previously missed servers. Discovery does not launch them.
- **Persistence.** Apply Postgres migrations through `20261102_10` using your
  deployment's migration procedure. `20261102_01` adds IaC exception scope
  columns; `20261102_10` brings existing databases up to the fleet endpoint and
  retry-safe trend scan schema. Both are additive and idempotent. Preserve the
  same database, identity settings, signing keys and retained reports.
- **Scheduled scans.** Dispatch rechecks leadership and the current tenant-owned
  schedule. This fails closed for stale due-list records, but does not guarantee
  exactly-once execution after a crash or leadership loss after the final check.
- **Graph investigations.** The shared graph retains explicit snapshot and tenant
  scope, partial-evidence notices and grouped findings. Review saved layouts and
  finding links against the same scan after upgrading.

## Earlier changes from 0.112.1

- **Compressed pushes.** CLI pushes are gzip-compressed by default. A control
  plane older than 2026-09-10 rejects them; set `AGENT_BOM_PUSH_GZIP=0` on
  collectors that still push to one, or upgrade the control plane first.
- **Push budget.** `POST /v1/results/push` accepts up to 256 MiB decoded
  (`AGENT_BOM_API_RESULT_PUSH_MAX_BYTES`) and refuses gzip bodies that expand
  beyond 100:1. Size worker memory for concurrent large pushes.
- **Postgres selector.** A `postgresql://` or `postgres://` URL in
  `AGENT_BOM_DB` is accepted as the alias of `AGENT_BOM_POSTGRES_URL`.
- **Local retention.** The local scan mirror drops whole runs older than
  `AGENT_BOM_ANALYTICS_MAX_RUN_AGE_DAYS` (90) or beyond
  `AGENT_BOM_ANALYTICS_MAX_BYTES` (2 GiB live), always keeping the newest run.
  Raise or disable (`<= 0`) these before upgrading if the mirror holds history
  you need. Current-estate projection caches are swept automatically; preview
  the sweep with `agent-bom db prune` and apply it with `--yes`.
- **Count changes.** npm workspace members are no longer reported as packages
  and model binaries are scanned by default, so package and finding totals can
  differ from a 0.112.1 scan of the same project. Compare scopes, not totals.

See [ENV_VARS](operations/ENV_VARS.md) for `AGENT_BOM_EXEC_PREWARM` and the
other new settings.

## Verify the upgraded scope

Run `agent-bom doctor --offline` to inspect local setup, then follow
[First run](FIRST_RUN.md) against the same authorized project or source used
before the upgrade. Retain the new report alongside the old one and inspect
collection warnings, findings and graph evidence. Offline checks do not prove
current advisory coverage or live provider access.

For a control plane, check health and intended docs exposure, authenticated
access and anonymous denial on protected routes, then confirm retained findings
and graph links. For MCP, reconnect the client and verify tool discovery and a
scoped scan. For runtime enforcement, repeat the configured allow/deny smoke
through the proxy or gateway. These checks verify only the tested scope.

First-run reports now organize details into tabs and expandable findings.
Missing scores are not zero; stale catalogs are labelled; possibly affected
distribution matches require more evidence. An unavailable explicitly selected
Ollama endpoint no longer falls back to inventory from the local machine.

If validation fails, stop rollout and retain diagnostics. Restore the previous
application image and a compatible database backup using the deployment's
rollback procedure; do not assume downgrading a package reverses migrations.
