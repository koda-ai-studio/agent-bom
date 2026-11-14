# v2 Contracts

`scan-report.schema.json` describes the JSON scan report schema 2.0
(`schema_version: "2.0"`). In 0.115.x `agent-bom scan -f json --report-format v2`
writes it and scan pushes use it when the control plane accepts it; it becomes the
`-f json` default in 0.116.0. It carries the same evidence as
the [v1 report](../v1/scan-report.schema.json), with each shared record written
once and referenced by ID:

| Transform (`packing.transforms`) | 1.0 shape | 2.0 shape |
| --- | --- | --- |
| `compliance_control_refs` | `findings[].controls` lists every control inline | `findings[].control_refs` lists IDs into the top-level `compliance_controls` map |
| `blast_radius_finding_refs` | each `blast_radius` row repeats its finding's fields | the row keeps `finding_ref` (the finding `canonical_id`) and only the fields that differ |
| `asset_refs` | each `findings[].asset` repeats its `assets[]` row | the asset keeps `asset_ref` (the `assets[].stable_id`) and only the fields that differ, such as `source_ids` |
| `package_refs` | each `agents[].mcp_servers[].packages[]` occurrence repeats its entity row | the occurrence keeps `package_ref` (the `ai_bom_entities.packages[].id`) and only occurrence fields, such as `vulnerabilities` |
| `provenance_refs` | provenance objects are repeated wherever a package is mentioned | `<key>_ref` (for example `discovery_provenance_ref`) names an entry of the top-level `provenance` map |
| `root_packages_alias` | root `packages` repeats `ai_bom_entities.packages` | omitted |
| `inventory_snapshot_packages` | `inventory_snapshot.packages` repeats the packages under `inventory_snapshot.agents` | omitted |

A value is replaced by a reference only when the referenced record holds the
same value, so an occurrence that differs keeps its own value inline.

## Reading a 2.0 report

Expand it to 1.0 and read it as before:

```python
from agent_bom.output.report_packing import expand_report

legacy = expand_report(report)  # exact 1.0 document; a 1.x report is returned as is
```

Every in-repo reader (report commands, `--baseline`, `--inventory`, `graph`,
`mesh`, `attest`, MCP tools, the dashboard import and `POST /v1/results/push`)
expands on read. A reader in another language applies the transforms listed in
`packing.transforms` in reverse order of the table above, and must refuse a
document that lists a transform it does not know.

## Compatibility

- `agent-bom scan -f json` writes schema 1.0 by default in 0.115.x;
  `--report-format v2` (or `AGENT_BOM_REPORT_FORMAT=v2`) writes 2.0. From 0.116.0,
  `--report-format v1` (alias `legacy`) keeps writing 1.0.
- `GET /version` lists `report_schema_versions`. `scan --push-url` sends 2.0
  only to a control plane that lists `"2.0"`; any other control plane receives 1.0.
- `POST /v1/results/push` accepts both. A 2.0 push is expanded before it is
  validated and stored, so stored results, findings and graphs are identical
  for either version. A reference that names no record is refused (422); a
  document whose references would expand past the 240 MiB storage ceiling is
  refused as too large (413).
- The Python API (`to_json`, `to_redacted_json`, `export_json`) keeps returning
  1.0 unless called with `report_format="v2"`.
