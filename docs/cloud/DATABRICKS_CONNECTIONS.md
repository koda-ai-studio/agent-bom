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
