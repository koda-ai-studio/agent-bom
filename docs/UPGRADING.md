# Upgrade to 0.113.0

These instructions target 0.113.0 once its artifacts are published.
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
version is 0.113.0 or a later release whose upgrade notes you have reviewed;
if it remains 0.112.1 or older, this upgrade has not been applied.

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

## Changes that affect an upgrade from 0.112.1

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
