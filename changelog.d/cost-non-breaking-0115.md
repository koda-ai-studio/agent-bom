### Changed
- JSON written to a file (`-o report.json`, CycloneDX, SPDX, SARIF, badge and graph JSON) is compact, with no indentation, which makes a JSON report about a third smaller (the demo report: 1.40 MB to 0.91 MB for schema 1.0, 1.03 MB to 0.69 MB for 2.0). This is a format note, not a breaking change: the parsed document is identical, and JSON on stdout stays indented. `--pretty-json` or `AGENT_BOM_PRETTY_JSON=1` writes indented files.

### Fixed
- Packing a report that has no `schema_version` (such as a scanner-style estate document) and expanding it again returns the same document: expansion no longer adds `"schema_version": "1.0"`. The packing manifest leaves out `legacy_schema_version` in that case, and the dashboard's reader matches.

### Performance
- `GET /v1/scan/{job_id}?view=full` streams a large job (more than 20,000 values in its result) in 64 KiB chunks instead of encoding the whole response into one buffer; the bytes are identical and small jobs keep a single body with `Content-Length`. Page sections with `GET /v1/scan/{job_id}/result/{section}`.

### Docs
- The sizing guide has a "Cost to run" section with measured API memory, CPU-seconds per agent for scan and ingest, and storage per retained push, each with how it was measured.

### CI
- A main push whose commit already passed the merge queue no longer reruns the lanes the merge-group run proved; only the multi-arch Docker build and, on dependency changes, the full musl suite run after merge, cutting runner time per merged PR from about 464 to about 137 minutes. The four-interpreter suite and its combined coverage floor moved to a reusable workflow that runs nightly, on manual dispatch, and inside every release on the tagged commit before anything publishes; the release gate reads the merge-group run for lanes a queue-proven push skipped. CI's nightly run has its own failure-streak tracker.
