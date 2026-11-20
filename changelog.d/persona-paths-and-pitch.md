### Changed
- The end of a scan leads with the command that opens its security graph in the local dashboard, adding the `[ui]` extra through `uvx` when the API server is not installed.
- The scan footer states unique package CVEs beside per-copy instances, the demo advisory line says its count is the catalog size, and the findings table says it is ranked by contextual risk, so a reachable medium can sit above an isolated high.

### Docs
- A "Start here by role" page gives AppSec, platform, AI/ML, GRC and leadership readers a five-minute path each, including the `report brief` export for leadership; it leads Getting Started and is linked from the README.
- The README, PyPI page and docs home lead with the agent → MCP server → tool → package → credential chain and a short "why now". Runbook and specialized deployment pages move to an Operations section, and the authenticated deployment is named a self-hosted instance.
- Stale release references are corrected: the Action pin example, the upgrade guide (0.115.4), agent lifecycle availability (published since 0.107.0), the runtime injection default, the dated real-repository accuracy measurement with reproduction steps, and the OpenAI review cases rerun on 0.115.4. The version checker now also manages a bare `` `@vX.Y.Z` `` Action ref in prose.
