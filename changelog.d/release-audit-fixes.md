### Fixed

- `agent-bom auth mint-admin-key` reserves its raw-key file before minting, so a refused path or failed mint never leaves a stored admin key without its file, and `--force` keeps the old file if minting fails.
- The remote proxy redacts credentials and query strings from the upstream URL in tool-discovery logs and traces.
- Bound `scan_id` to 256 characters on graph node-aggregate and scope-finding reads.
- Correct nine documented commands that did not run as written (`mcp server --transport streamable-http`, `--warn-on`, `iac .`, `sbom <file>`, `code .`, `agent-shield`, and others), and document `findings affected`, `GET /v1/affected` and `findings list --fix`.
