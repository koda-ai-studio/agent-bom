# OCSF boundary

**Principle:** OCSF (Open Cybersecurity Schema Framework) is an **optional
wire protocol for event ingestion and SIEM interop**, not agent-bom's internal data model.

## What this means

1. **Core scanning, enrichment, graph, and reporting code does not depend
   on the OCSF emission modules.** `siem/ocsf.py` and `siem/delta_stream.py`
   translate canonical product records for external consumers. The separate
   inbound adapter normalizes selected OCSF fields into canonical runtime
   observations; downstream code consumes those observations.
2. **Internal schemas are product-shaped, not OCSF-shaped.** Each
   finding source keeps the dataclass that best models its domain:
   - `CISCheckResult` — check_id, status, evidence, resource_ids, remediation
   - `SkillFinding` — category, context, ai_analysis, ai_adjusted_severity
   - `Finding` (graph) — blast_radius, reachability, kev, epss_percentile
   - `RuntimeAlert` — alert dict from proxy / MCP tool telemetry

   Forcing these into OCSF would drop fields OCSF does not model
   (`ai_analysis`, `blast_radius`, `reachability`) and is the wrong
   direction.
3. **Per-cloud code stays cloud-native.** AWS API response →
   `CISCheckResult` directly. Azure / GCP / Snowflake the same. No
   AWS-→-OCSF-→-internal double hop. Cloud scanners do not route native inventory through OCSF;
   OCSF adapters remain at the external ingestion and export boundaries.
4. **OCSF emission stays at the wire boundary.** Translators live
   in `siem/ocsf.py` (SIEM push, Detection Finding, `class_uid=2004`) and
   `siem/delta_stream.py` (finding delta-stream projection).
   Runtime alerts and finding-delta export batches are translated at the
   boundary; CIS / skills / CVE findings stay in internal JSON otherwise.

## Shipped inbound adapter

`POST /v1/ocsf/ingest` accepts an authenticated, tenant-scoped batch and returns
202 with the accepted count. `api/routes/observability.py` enforces the request
limit (`AGENT_BOM_API_MAX_OCSF_INGEST_EVENTS`, default 1,000).
`api/observability_events.py` normalizes selected fields and persists runtime
observations; analytics delivery is best-effort. A 202 receipt is not proof of
execution or successful SIEM delivery.

The adapter retains source/event identity, severity, timestamps, resource
labels and bounded attribution through `api/ocsf_fields.py`. Principal identifiers
are tenant-bound hashes. Missing native sessions receive an event-scoped
synthetic session; missing timestamps are marked as receipt time. This is a
selected-field adapter, not complete OCSF schema validation or a lossless
round-trip serializer.

Explicit graph coordinates in `unmapped["agent_bom.agent_ref"]` and
`unmapped["agent_bom.inventory_node_id"]` remain separate from native user and
resource identifiers. Graph projection requires exact inventory references and
consistent cloud scope. Unmatched identities remain unverified; recorded
activity never establishes execution, permission or a traversable attack path.
See [SIEM ingestion](../site-docs/deployment/siem-integration.md#inbound-ocsf-ingest) for the operator contract.

## What is allowed to depend on OCSF

- `siem/` — connector layer, may freely import OCSF.
- `api/observability_events.py` and `api/ocsf_fields.py` — inbound adapters;
  normalize external fields without importing the emission modules.
- `graph/ocsf.py` — a thin mapping table (`EntityType` → OCSF
  `category_uid` / `class_uid`) plus `ocsf_type_uid()`. The graph Node
  dataclass carries the resulting IDs as inert fields (reserved seats
  for SIEM export). **No core logic branches on these fields.**
- `core/severity.py` — `OCSFSeverity` IntEnum (UNKNOWN=0 … CRITICAL=5)
  used as a stable integer severity scale. Coincidence of convention,
  not a dependency; would stay even without OCSF.

## What is **not** allowed to depend on OCSF

Anything under `scan`, `enrichment`, `parsers`, `cli`, `cloud`
(CIS benchmarks and cloud asset models), `skills`, `analyzers`,
`api`, `dashboard`, `db`, `ingestion` must not import from
`agent_bom.siem.ocsf`. These modules
describe product behaviour; external OCSF payloads are normalized at the
API boundary before entering the internal model.

**Enforcement:** `tests/test_ocsf_boundary.py` checks the source tree with
Python AST parsing, including direct, relative and literal dynamic imports.
Run `uv run pytest -q tests/test_ocsf_boundary.py tests/test_ocsf_ci_selection.py`.
The CI selection tests also keep ingestion changes tied to tenant-isolation
contracts.

## When to add a new OCSF translator

Only when a real customer / integration asks. Do **not** pre-emptively
author:

- CIS → Compliance Finding (`class_uid=2003`)
- Skill → Security Finding (`class_uid=2001`)
- CVE / SAST → Vulnerability Finding (`class_uid=2002`)

These are legitimate follow-ups if and when a SIEM / XDR / Security
Lake integration needs them. Until then they are speculative work and
should stay off the roadmap.

## ClickHouse analytics persistence

ClickHouse stores **canonical product rows** built by
`analytics_contract.py` and `clickhouse_store.py` — scan findings,
runtime events, posture snapshots, and compliance measurements. OCSF is
not written to ClickHouse directly; SIEM export remains a separate
projection at the wire boundary (see above).

Buffered flushes and scan retries derive stable dedup keys
(`finding_key`, `event_id`, `entry_id`, etc.) so repeated inserts of
the same canonical row collapse under `ReplacingMergeTree` instead of
inflating trend queries (#3484).

## Why keep OCSF at all

AWS Security Lake stores supported and custom-source security events in OCSF,
and Google Security Operations can ingest OCSF JSON through its OCSF parser.
Other SIEM paths remain connector-specific. Keeping OCSF as an optional
projection preserves those interoperability paths without making it an
internal dependency or implying that every destination standardizes on it.
