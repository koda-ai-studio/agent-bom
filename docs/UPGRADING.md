# Upgrade to 0.112.1

These instructions target 0.112.1 once its patched artifacts are published.
The source version alone does not establish package or image availability.

## Preserve configuration and evidence

Record the running package version and image digests. Back up the configured
database and retained reports using your backend's supported backup procedure;
preserve encryption keys, identity configuration, tenant settings and audit
checkpoints in your existing secret store. Test restoration before upgrading.
Do not overwrite evidence from earlier scans.

## Select the installed surface

In the existing Python virtual environment, choose the same extras you use:

```bash
python -m pip install --upgrade 'agent-bom==0.112.1'
# API / dashboard deployment:
python -m pip install --upgrade 'agent-bom[ui]==0.112.1'
# MCP server:
python -m pip install --upgrade 'agent-bom[mcp-server]==0.112.1'
agent-bom --version
```

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
