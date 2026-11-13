### Changed
- A `scan` JSON report counts code-analysis relationships instead of listing them: `ai_inventory.ast_analysis` carries `relationships_included: false` and its `stats` keep `total_call_edges`, `total_cfg_edges` and `total_dependency_symbol_reach`. Add `--include-code-graph` for every row. On this repository the report shrinks from 129 MB; findings and reachability are unchanged. API and repository scans keep the full lists.
- Top-level help keeps the five front-door commands first and lists every other command under one workflow group (setup, graph, MCP and runtime, governance, platform), with no catch-all section. No command is removed or renamed.
- A default `scan` stops code analysis after 500 source files (entrypoints first), and the secret and AI-component scans after 1,000 files each, in sorted path order. It reports each stop as incomplete coverage, on the console and in `coverage_warnings` and `scan_run.issues`, naming `--full-analysis`, which reads every eligible file. A first scan of this repository (8,700 files) takes a median of about 50 s instead of about 380 s; projects under the budget are unaffected, and `secrets`, `code` and API scans keep their own limits.

### Fixed
- An outbound request no longer waits on a stalled DNS resolver: the rebinding check's lookup gives up after 5 s and refuses the URL like an unresolvable name, so the scan reports that source as unavailable instead of hanging. A successful answer is reused for 60 s per host.

### Performance
- The CLI imports a command only when it runs: `agent-bom --help` takes about 0.25 s instead of 1.0 s and loads no scanner, and each command loads only its own modules.
- A scan inside a Git checkout lists tracked files from the scan root instead of the whole repository, so building ignore rules for the secret and code scans takes about 0.04 s instead of 0.4 s on an 8,700-file checkout and no longer grows with the surrounding monorepo.
- A plain scan downloads the CISA KEV catalog while the OSV and GHSA lookups run instead of after them.
