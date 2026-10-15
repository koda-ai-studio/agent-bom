# Experimental features

> Generated from `src/agent_bom/core/experimental.py` by `scripts/generate_experimental_docs.py`.
> Do not edit by hand; CI fails when this page drifts from the registry.

Experimental features ship for evaluation. Their contracts, storage, and
output may change without a deprecation window, and they are not covered
by the supported-surface guarantees in the rest of the docs.

## Enabling flag-gated features

Flag-gated features are **off by default**. Enable them with one setting, `AGENT_BOM_EXPERIMENTAL`,
a comma-separated list of feature ids (`all` enables every flag-gated feature):

```bash
export AGENT_BOM_EXPERIMENTAL=traces
```

While a flag-gated feature is disabled, its API routes return `404` with an
enable hint, MCP tools return the same hint, trace collection and the graph
trace overlay do not run, and the dashboard labels the entry *Experimental*.
`agent-bom doctor` and `GET /v1/system/health` (`experimental_features`)
report the live state.

`POST /v1/traces` (OTLP ingest) stays available for runtime and cost
telemetry; with `traces` disabled it records no trace findings and the graph
does not overlay trace events.

Features that are not flag-gated keep the opt-in they shipped with and are
listed here so the experimental label is consistent everywhere.

## Registry

| Id | Feature | Surfaces | Flag-gated | Enabled by | Docs |
|---|---|---|---|---|---|
| `traces` | Trace pull, trace collection, and trace findings (Langfuse, LangSmith, OTel) | api, mcp, ui | yes | `AGENT_BOM_EXPERIMENTAL=traces` | [TRACE_CONNECTIONS.md](TRACE_CONNECTIONS.md) |
| `storage-snowflake` | Snowflake control-plane stores | api | no | SNOWFLAKE_ACCOUNT set on the control plane | [STORAGE_BACKENDS.md](STORAGE_BACKENDS.md) |
| `storage-neptune` | Neptune graph backend | api | no | AGENT_BOM_GRAPH_BACKEND=neptune with AGENT_BOM_EXPERIMENTAL_NEPTUNE_GRAPH=1 | [STORAGE_BACKENDS.md](STORAGE_BACKENDS.md) |
| `consequence-assessment` | Graph consequence assessment | cli, api, mcp | no | always available; output is labelled experimental | [GRAPH_CONSEQUENCES.md](GRAPH_CONSEQUENCES.md) |
| `agent-bom-profile-v1` | agent-bom.profile/v1 evidence profile | cli, api | no | always available; schema is labelled experimental | [AGENT_BOM_PROFILE.md](AGENT_BOM_PROFILE.md) |
| `gpu-psirt-seeds` | AMD and Intel PSIRT curated advisory seeds | cli, api | no | always available; matches are labelled experimental | [AI_INFRASTRUCTURE_SCANNING.md](AI_INFRASTRUCTURE_SCANNING.md) |
| `mcp-oauth-cimd` | MCP OAuth Client ID Metadata Document support | mcp | no | MCP OAuth configuration; CIMD clients are labelled experimental | [MCP_OAUTH.md](MCP_OAUTH.md) |
| `scan-evidence-journey` | Scan evidence journey export | cli, api | no | always available; export profile is labelled experimental | [SCAN_EVIDENCE_JOURNEY.md](SCAN_EVIDENCE_JOURNEY.md) |
