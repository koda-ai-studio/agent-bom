# Provider workflow boundaries

The [generated matrix](../VENDOR_COVERAGE.md) records implemented surfaces, not
live-provider qualification. A provider appearing in inventory does not imply
support for every identity, data, disk or runtime workflow.

| Provider / workflow | Implemented boundary | Additional work required |
| --- | --- | --- |
| Databricks saved connections | Explicit workspace token, cluster-read verification, discovery, vendor security checks, full scheduled scans, CLI and wizard | Event ingestion, organization fan-out and workload identity require new adapters. |
| Snowflake inventory and identity | Saved connections already thread one brokered session through discovery, CIS and estate enrichment; warehouses, databases, roles, users, grants and memberships become graph evidence | A permission-decision evaluator equivalent to the cloud authorization evaluators requires new semantics and tests. Role inventory alone is not an effective-access verdict. |
| Snowflake data | Estate metadata, external-data surfaces and governance mining exist | Generic database content sampling is a separate opt-in path; neither metadata nor a connection label establishes full content coverage. |
| Snowflake disk / events / runtime | Disk lifecycle adapters, change-event adapters and workload runtime evidence currently target AWS, Azure and GCP | Snowflake query/access events and runtime identities need a dedicated source, freshness and permission model; disk snapshot scanning is not a Snowflake workspace operation. |
| Database connections | Manual brokered scans run bounded DSPM content sampling only with explicit sampling opt-in; otherwise coverage is skipped | Recurring sampling needs an explicit sampling-budget and consent contract. Database is intentionally absent from the scheduler allowlist. |
| OCI | Scope references can identify OCI evidence | No saved-credential broker, scan runner or scheduler exists. Adding a choice would not implement an integration. |
| CoreWeave / Nebius | Existing CLI discovery enumerates AI/GPU workload metadata and images through their configured Kubernetes/API credentials | Saved credentials, bounded verification, recurring scans, effective-access evaluation and runtime evidence need provider-specific adapters and tests. |

Source contracts: `api/routes/cloud_connections.py` (scan runners),
`api/connection_scheduler.py` (cadence allowlist), `cloud/connection_broker.py`
(credentials), `cloud/authorization_evidence.py` and `cloud/aws_iam_evaluator.py`
(authorization), `cloud/db_content_scan.py` (sampling),
`cloud/side_scan_provider_adapters.py`, `cloud/event_ingest.py`,
`cloud/azure_event_ingest.py`, `cloud/gcp_event_ingest.py` and
`cloud/runtime_workload_evidence.py` (provider-specific operations).
Paths are relative to `src/agent_bom/`.

For supported saved connections, start with `agent-bom connect` or Connections,
verify the scoped read, then scan and inspect its coverage artifact. Unavailable
or denied evidence remains a gap. Local fixtures and mocked clients validate
contracts; they do not prove access, completeness or performance in a customer
account.
