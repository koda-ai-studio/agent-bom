# Upgrade to 0.114.0

These instructions target 0.114.0 once its artifacts are published.
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
version is 0.114.0 or a later release whose upgrade notes you have reviewed;
if it remains 0.113.2 or older, this upgrade has not been applied.

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

## Changes from 0.113.2

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
