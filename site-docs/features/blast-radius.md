# Blast Radius

Maps the full impact chain from a CVE to the business assets at risk.

## How it works

```
Package → Vulnerability Finding → MCP Server → Agent → Credentials + Tools
```

For each vulnerability found, agent-bom traces:

1. **Which package** is affected
2. **Which MCP servers** depend on that package
3. **Which AI agents** (clients) connect to those servers
4. **Which credentials** are accessible through those agents
5. **Which tools** an attacker could invoke

## Usage

```bash
# CLI
agent-bom agents   # blast radius is included in scan output

# MCP tool
blast_radius(cve_id="CVE-2024-21538")
```

## In the JSON report

Each `blast_radius` row (`schema_version: "2"`) names its exposure path instead
of embedding a copy: `exposure_path_rank` is the 1-based position of the path in
`exposure_paths.paths`, and `exposure_path_id` is that path's `id`. Ids can repeat
when one package version is reached through several package keys; the rank
cannot. Schema `"1"` rows (reports from earlier releases) carry the path inline
under `exposure_path`. Python consumers can read either form with
`agent_bom.output.exposure_path.blast_radius_exposure_path(report, row)`; with
`jq`:

```bash
jq '.exposure_paths.paths as $p | .blast_radius[] | {vulnerability_id, path: $p[.exposure_path_rank - 1]}' report.json
```

SARIF results keep their own embedded `properties.exposure_path`, since SARIF
has no shared path table.

## Scoring

Each CVE gets a blast radius score (0–10) factoring in:

- CVSS base score
- EPSS exploit probability
- Number of affected agents
- Credential exposure count
- Tool access scope
- CISA KEV listing (known exploited)

## Context graph

The `context_graph` tool extends blast radius with lateral movement analysis — BFS traversal showing how compromising one server can reach others through shared agents.

```bash
# MCP tool
context_graph()
```
