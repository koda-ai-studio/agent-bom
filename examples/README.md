# Public inventory examples

The bundled inventory files use synthetic identities. `123456789012` is the
sample AWS account; `EXAMPLE_ORG-EXAMPLE_ACCOUNT` is the sample Snowflake account.
Cloud endpoint examples use reserved `.invalid` hostnames and cannot connect to
an account. Credential values such as `***` are redacted placeholders.

Parse and inspect the Snowflake example locally without cloud credentials:

```bash
agent-bom agents --inventory examples/snowflake-inventory.json --offline --format json --output /tmp/snowflake-example-report.json
```

The artifact is a scan report of the supplied sample inventory and any discovered
local skill files, not evidence of live cloud discovery. Exit code `1` can indicate
findings or partial offline coverage; inspect the report. Next, follow the [cloud connection guide](../docs/CLOUD_CONNECT.md)
with your own account and keep collected inventories outside the public checkout.
Replace all account, endpoint and credential placeholders before a live connection.
Do not paste account identifiers or provider reports into public examples.
