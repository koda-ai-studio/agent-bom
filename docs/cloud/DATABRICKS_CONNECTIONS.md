# Databricks workspace connections

Install `agent-bom[api,databricks]` on the self-hosted control plane and configure
connection encryption before storing credentials. Use a dedicated workspace
identity with only the reads needed for your inventory. Admin APIs require
additional privileges; running read-only calls does not make an admin token a
read-only credential. Denied checks remain ERROR, not PASS.

First verify a workspace credential from a private token file:

```bash
agent-bom connect databricks --host https://example.cloud.databricks.com \
  --token-file /private/path/workspace-token
```

This performs a bounded cluster-list read. A successful probe proves that read
only, not permission to evaluate every security check. Token contents are never
printed. Workspace origins must use HTTPS on a hosted Databricks domain;
credentials, arbitrary paths, queries and custom endpoints are rejected.

To save the connection, add `--server https://control.example` and an authorized
API key using the CLI's `--api-key` option. The API encrypts the token at rest and
scopes every record, scan and result to the authenticated tenant. The broker uses
that stored token and workspace explicitly; it does not inherit the server's
ambient Databricks credentials. Missing encryption or credentials fails closed.

The Connections wizard provides the same workspace URL and token fields.
Verify, then run a scan or configure full scans on a cadence. Inventory and
Databricks Security Best Practices results persist in the ordinary scan and
graph stores. These checks are vendor guidance, **not an official CIS benchmark**.
Discovery warnings and denied or skipped checks mark the scan partial. Review
coverage before using results as governance evidence.

One workspace per connection is supported. Organization fan-out, region
selectors, workload identity and continuous change-event ingestion are not
implemented for this provider. No Terraform grant generator is advertised.

For a local scan using the SDK's standard environment configuration:

```bash
agent-bom scan --databricks -o workspace-report.json
```

Next: inspect findings, coverage and the selected workspace graph. The generated
[coverage matrix](../VENDOR_COVERAGE.md) distinguishes discovery, scheduling,
benchmarks, identity, data and runtime capabilities.

## OAuth profile inventory and security evidence

For a local SDK OAuth profile, select it explicitly and keep reports private:

```bash
DATABRICKS_CONFIG_PROFILE=workspace-read \
  agent-bom scan --databricks --databricks-security --no-discover \
  --offline --no-scan -f json -o workspace-inventory.json
```

This writes inventory and security-check evidence without scanning packages for
vulnerabilities. A nonzero exit can be the partial/security verdict; inspect the
report and errors before deciding what passed. Remove `--no-scan` and `--offline`
when ready to add online vulnerability checks.

The authenticated SDK client's workspace origin supplies inventory identity,
security-report attribution and discovery scope, including profiles that set no
`DATABRICKS_HOST`. Databricks uses the canonical origin as the cloud envelope's
`scope.project_id`; this is a workspace boundary, not a Databricks account ID.
Same-named resources in different workspaces retain distinct identities.

The PAT policy check reads `maxTokenLifetimeDays` from workspace configuration
and evaluates the 90-day recommendation for **new** tokens. It does not establish
the lifetime of existing tokens. Service-principal PAT checks match token owner
IDs; missing ownership or expiry data remains ERROR. A clean enumerated PAT set
does not prove OAuth use. See the [Databricks token management guide](https://docs.databricks.com/aws/en/admin/access-control/tokens).

Disk settings do not establish private networking. Missing network fields remain
ERROR. Billing-log delivery is not audit-log delivery, and workspace credentials
do not establish account-level audit configuration. Unsupported or denied reads
remain explicit evidence gaps. These checks make no changes to the workspace.
