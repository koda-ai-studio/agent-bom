### Changed
- A `scan` JSON report counts code-analysis relationships instead of listing them: `ai_inventory.ast_analysis` carries `relationships_included: false` and its `stats` keep `total_call_edges`, `total_cfg_edges` and `total_dependency_symbol_reach`. Add `--include-code-graph` for every row. On this repository the report shrinks from 129 MB; findings and reachability are unchanged. API and repository scans keep the full lists.
- Top-level help keeps the five front-door commands first and lists every other command under one workflow group (setup, graph, MCP and runtime, governance, platform), with no catch-all section. Command names, options and help text are unchanged.

### Fixed
- An outbound request no longer waits on a stalled DNS resolver: the rebinding check's lookup gives up after 5 s and refuses the URL like an unresolvable name, so the scan reports that source as unavailable instead of hanging. A successful answer is reused for 60 s per host.

### Performance
- The CLI imports a command only when it runs: `agent-bom --help` takes about 0.25 s instead of 1.0 s and loads no scanner, and each command loads only its own modules.
- A scan inside a Git checkout lists tracked files from the scan root instead of the whole repository, so building ignore rules for the secret and code scans takes about 0.04 s instead of 0.4 s on an 8,700-file checkout and no longer grows with the surrounding monorepo.
- A plain scan downloads the CISA KEV catalog while the OSV and GHSA lookups run instead of after them.
