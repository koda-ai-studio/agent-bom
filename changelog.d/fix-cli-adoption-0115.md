### Changed
- `agent-bom up` (and `serve`) without the `[ui]` extra prints the single command that starts the dashboard, `uvx --from 'agent-bom[ui]==<version>' agent-bom up`, with any `--host`, `--port` or `--persist` you typed and never `--api-key`. With the dashboard available it prints `Open: http://127.0.0.1:8422/`; on a loopback bind the browser signs in automatically.
- `quickstart --run` ends with the one command that opens the graph for the scan it just made (through `uvx` when the `[ui]` extra is not installed) and the graph URL. `--open` starts the server on the verified databases and opens that graph in the browser once the server listens.
- The quickstart's `AGENT_BOM_NO_AUTH_ROLE=analyst` guidance now says what happens: the server mints a new dev API key on every loopback start, the browser signs in automatically, and the variable sets the role of that key and session.
- `scan --help` shows `--quick`, `--full-analysis` and `--log-json` with the other everyday flags; the rest stay under `--help-all`.

### Fixed
- `scan -q` (and `fs`, `iac`, `image`, `sbom`, `agents` and the `cloud` commands, which share it) prints the result instead of nothing: a one-line verdict with counts by severity, the reason for a non-zero exit, and the report path. Progress and banners stay suppressed. When stdout carries a JSON or SARIF document, the summary goes to stderr. A scan stopped by missing vulnerability data under `-q` names that reason too.
- `code -q` prints one line of counts, `secrets -q` prints the findings and total, and `mcp inventory -q` prints agent, server and package counts; each previously printed nothing.
- The MCP server logs each record once in agent-bom's format. The SDK's constructor added a second, Rich-formatted root handler, so every line on stdio stderr appeared twice and SDK records ignored `--log-json`. `mcp server --log-json` also no longer reverts to plain text when the server is built.

### Security
- The loopback dev API key is printed only when stdout is an interactive terminal. Redirected output, `--log-json` records and log files say it was withheld instead.
