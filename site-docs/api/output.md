# Output

Output formatters for console, JSON, HTML, SARIF, CycloneDX, SPDX, and other formats.

Generate reviewable artifacts from a scan:

```bash
agent-bom scan --demo --offline --format json --output findings.json
```

Review the finding's advisory, affected product and reachability before assigning
an impact. Missing impact metadata remains unspecified in SARIF; legacy scan
records use `unknown`. Broad input-validation CWEs alone do not establish data
loss or code execution. The original advisory description remains evidence for
reviewing the effect and its preconditions.

Generated VEX groups only equivalent assessments and retains every affected
product PURL. Different versions or suppression decisions are not discarded just
because they share a CVE. Review those product-specific statements before using
VEX to suppress findings downstream.

## Large results over the REST API

`GET /v1/scan/{job_id}` returns the complete AI-BOM document. For a bounded
read of a completed scan, fetch the index first:

```bash
curl -s "$API/v1/scan/$JOB/result" | jq '.summary.summary, .sections'
curl -s "$API/v1/scan/$JOB/result/blast_radius?offset=0&limit=100" | jq '.items | length, .next_offset'
```

The index returns scalar fields and the small summary objects (`summary`,
`finding_summary`, `scan_run`, ...) inline and lists every other top-level
section with its `kind` (`list` or `object`), item `count` and an `href`. A
list section is paged with `offset` and `limit` (1-1000, default 100) until
`next_offset` is `null`; an object section is returned whole in `value`. Items
are redacted exactly as in the full result, so paging every section reproduces
it. A scan that has not completed returns `409`; an unknown section `404`. For
filtered, cursor-paged findings across scans, use `GET /v1/findings`.

The full result is redacted and encoded in a worker thread, and responses of
128 KiB or more are gzip-compressed in a worker thread when the client sends
`Accept-Encoding: gzip`.

::: agent_bom.output
    options:
      members:
        - print_summary
        - print_compact_summary
        - print_compact_agents
        - print_compact_blast_radius
        - print_blast_radius
        - export_json
        - export_html
        - export_sarif
        - export_cyclonedx
        - export_spdx
        - SEVERITY_BADGES
        - SEVERITY_TEXT
