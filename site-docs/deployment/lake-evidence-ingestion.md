# Import findings already collected into a security lake

Use a customer-controlled lake query or export to select finding observations,
then map them into Agent-Bom's existing findings, compliance and graph views.
The original account, region, observation time, record ID, input digest and
mapping digest remain attached as evidence. Direct cloud collection can supply
current inventory and permissions that the exported records do not contain.

## First command → report → control plane

From a repository checkout:

```bash
agent-bom ingest lake examples/lake/findings.json \
  --mapping examples/lake/mapping.json -o lake-report.json
```

This sample contains one labelled finding observation. The command writes a
private JSON report (mode `0600`) and refuses to overwrite existing evidence.
Inspect its `findings`, `lake_receipt` and `coverage_warnings` fields.

For a customer snapshot, replace both inputs with your own files. To submit the
retained report through the existing authenticated results endpoint, set
`AGENT_BOM_PUSH_API_KEY` through your secret manager, then run with a fresh output
path:

```bash
agent-bom ingest lake findings.json --mapping mapping.json \
  -o retained-lake-report.json --push https://control-plane.example.com
```

The destination is explicit. The command uses `/v1/results/push`, the same tenant
scope, sanitization, graph persistence and replay handling as ordinary scan
results. Repeating identical input bytes, mapping and object receipt uses the
same replay key; different snapshots remain separate observations. A failed push
returns nonzero and leaves the report available. Reuse the saved report with
`POST /v1/results/push`, or retry the command with a new output path.

In the control plane, open the imported scan's findings and Investigation graph.
Source-declared framework/control tags support compliance drill-downs; they do
not establish a control pass, independent verification or auditor attestation.
Correlation with another snapshot requires the product's scoped correlation
workflow and matching identities. Import alone does not establish an attack path.

## Existing columns or explicit normalization

The input is a JSON array of finding objects, or NDJSON with
`--input-format ndjson`. Use one finding type and asset type per batch.
The default columns are:

| Field | Requirement |
| --- | --- |
| `finding_id`, `asset_id`, `title` | Nonempty stable source identifiers and title |
| `severity` | Label; unknown labels remain `unknown` |
| `observed_at` | Timestamp with timezone; no later than `exported_at` |
| `provider`, `account_id`, `region` | Required for cloud resources, data stores and identities; use explicit `global` for a global resource |
| `asset_name`, `environment`, `description` | Optional recorded context |
| `cve_id`, `fixed_version`, `remediation_guidance` | Optional source advisory/remediation evidence |
| `controls` | Optional array of `{framework, control, version?}`; source-declared only |

Already-shaped rows need no column mapping. Other schemas use `columns`, with
literal column names or JSON pointers into objects/arrays. There is no SQL or
expression execution. Unmapped fields are omitted, including producer claims
about graph reachability and exploitation.

For example, a JSON query export of selected OCSF finding records can use:

```json
{
  "schema_version": "agent-bom.lake-mapping/v1",
  "provider": "aws-security-lake",
  "source_instance": "sample-lake/security-findings",
  "exported_at": "2026-10-29T13:00:00Z",
  "finding_type": "CLOUD_BEST_PRACTICE_FAIL",
  "asset_type": "cloud_resource",
  "timestamp_format": "unix_ms",
  "columns": {
    "finding_id": "/finding_info/uid",
    "title": "/finding_info/title",
    "asset_id": "/resources/0/uid",
    "provider": "/cloud/provider",
    "account_id": "/cloud/account/uid",
    "region": "/cloud/region",
    "observed_at": "/time",
    "severity": "/severity_id"
  },
  "severity_values": {"1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical", "6": "critical", "0": "unknown", "99": "unknown"}
}
```

Select actual finding records of the declared type, including the intended
resource occurrence; do not map arbitrary activity logs to posture failures.
This example selects the first resource. For multi-resource findings, expand
resource occurrences in the customer query before export. Numeric severity
requires an explicit value mapping. ISO timestamps are the default;
`timestamp_format: unix_ms` accepts integer epoch milliseconds.

Provider labels also include `snowflake`, `databricks`, `bigquery`, `clickhouse`,
`s3` and `local`. These labels record provenance; they do not execute warehouse
queries or establish native connector qualification.

## Read an existing S3 snapshot

Install the AWS extra and grant read access to the exact object version. Supply
credentials through the AWS SDK credential chain, preferably a workload role.
No bucket listing or write permission is required.

```bash
agent-bom ingest lake s3://customer-evidence/exports/findings.ndjson \
  --s3-version-id '<version-id>' --s3-expected-owner '<bucket-owner-account-id>' \
  --input-format ndjson --mapping mapping.json -o lake-report.json
```

The reader issues `GetObject` with `VersionId` and `ExpectedBucketOwner`, rejects
missing/null/mismatched versions, and records bucket, key, owner and version with
the input digest. Required permission is `s3:GetObjectVersion` on that object;
SSE-KMS objects also need the applicable KMS permissions described by AWS. See the [AWS GetObject permission contract](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObject.html). SDK retries
and connection/read timeouts are bounded. Access failures produce no report.

This is **JSON/NDJSON snapshot ingestion**, including exports produced from AWS
Security Lake queries. It does not read native Security Lake Parquet partitions,
subscribe to SQS notifications, execute Athena queries, or claim continuous
checkpointed collection. Keep those extraction steps in the customer's existing
pipeline. The separate OCSF runtime-event endpoint accepts its documented
selected event fields; it is not a universal posture snapshot importer.

## Evidence boundaries and limits

- Maximum 16 MiB per input and 1,000 finding records per batch. Empty batches,
  duplicate finding/resource identities and invalid records fail as a whole.
- The mapping is explicit and versioned. Unknown mapped fields are rejected.
- Scoped identities keep same-named resources in different accounts or regions
  separate. Package occurrence findings retain account/region context.
- Source timestamps remain observation times. Import time does not make old
  evidence fresh; the report timestamp is the oldest observation in the batch.
- Collection completeness stays unknown. No absent-finding reconciliation runs.
- Input/mapping digests support traceability; they are unsigned local digests,
  not source authentication or independent verification.
- Findings already asserted by the source remain external findings. Current
  configuration, permissions, observed activity and successful exploitation
  remain separate evidence claims.

For inventory/relationship row exports, use `agent-bom ingest warehouse` and its
versioned graph mapping. For outbound findings delivery, see
[Backend and security lakes](backend-and-security-lakes.md).
