<p align="center">
  <img src="docs/images/social-preview.svg" alt="agent-bom — Discover. Scan. Correlate. Act. Security evidence across repositories, software supply chains, AI and MCP, cloud, identity, and data." width="1280" />
</p>

<p align="center">
  <a href="https://github.com/koda-ai-studio/agent-bom/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/koda-ai-studio/agent-bom/ci.yml?branch=main&style=flat&label=Build" alt="Build"></a>
  <a href="https://pypi.org/project/agent-bom/"><img src="https://img.shields.io/pypi/v/agent-bom?style=flat&label=PyPI&cacheSeconds=60" alt="PyPI"></a>
  <a href="https://pypi.org/project/agent-bom/"><img src="https://img.shields.io/badge/Python-3.11%E2%80%933.14-blue?style=flat" alt="Python 3.11 through 3.14"></a>
  <a href="https://hub.docker.com/r/agentbom/agent-bom"><img src="https://img.shields.io/docker/pulls/agentbom/agent-bom?style=flat&label=Docker%20pulls" alt="Docker pulls"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=flat" alt="Apache-2.0 license"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/koda-ai-studio/agent-bom"><img src="https://img.shields.io/ossf-scorecard/github.com/koda-ai-studio/agent-bom?style=flat&label=OpenSSF%20scorecard" alt="OpenSSF Scorecard"></a>
  <a href="https://glama.ai/mcp/servers/msaad00/agent-bom"><img src="https://img.shields.io/badge/MCP-Glama-7c3aed?style=flat" alt="Glama MCP server"></a>
  <a href="https://smithery.ai/servers/agentbom/agent-bom"><img src="https://img.shields.io/badge/MCP-Smithery-1f6feb?style=flat" alt="Smithery MCP server"></a>
</p>
<!-- mcp-name: io.github.msaad00/agent-bom -->

<p align="center"><b>Find vulnerable software behind your AI agents—and trace the exposure evidence.</b></p>

For AppSec and platform engineers responsible for AI agents and MCP servers:
scan a repository, correlate its findings with agent and infrastructure context,
and prioritize fixes using blast radius and reachability evidence.
**Open security scanner and self-hosted control plane for AI, MCP, and cloud infrastructure.** Local scans need no account.

<p align="center">
  <a href="#quick-start"><b>Quick start</b></a> ·
  <a href="#open-the-sample-graph">Sample graph</a> ·
  <a href="#self-host-in-your-environment">Self-host</a> ·
  <a href="docs/PRODUCT_TOUR.md">Product tour</a> ·
  <a href="https://koda-ai-studio.github.io/agent-bom/">Docs</a>
</p>

## Quick start

From the repository you want to inspect:

```bash
pip install agent-bom
agent-bom scan .
```

Read the inventory, findings, coverage gaps, and remediation guidance in the terminal.
Save a report with `agent-bom scan . -f sarif -o findings.sarif`, then
[upload it and gate CI](docs/FIRST_RUN.md#5-gate-ci-on-the-result).
Run `agent-bom doctor` if setup fails.

No project handy? Run `agent-bom scan --demo --offline` for a bundled sample.
Exit `1` is expected: the sample trips the security gate. A non-zero exit can
also mean incomplete assessment; inspect the report and [exit codes](site-docs/reference/exit-codes.md).

<p align="center"><img src="docs/images/demo-latest.gif" alt="Recorded agent-bom v0.108.4 CLI showing sample findings and remediation guidance; no fix executed" width="920" /></p>

The recording uses labeled sample data and bundled advisories. Credential
references are names, not secret values. Recorded relationships do not prove
exploitation or successful data access.

## Investigate context and exposure

**Which agent uses the vulnerable component? What could it reach? What evidence supports that path?**
Correlate retained scans by exact, tenant-scoped identities; trace the recorded
blast radius across packages, workloads, tools, identities and resources.
Inspect each relationship's source and reachability basis, then rescan the same
scope to check what changed.

<p align="center"><a href="docs/images/graph-relationship-dark-live.png"><picture><source media="(prefers-color-scheme: light)" srcset="docs/images/graph-relationship-light-live.png"><img src="docs/images/graph-relationship-dark-live.png" alt="Focused investigation linking a service, workload and tool, with the selected relationship's runtime evidence open" width="1100"></picture></a></p>

*Current-source preview; the published `0.108.4` UI predates this investigation
workspace.* The reference lab combines real parsers and local gateway calls
with modeled infrastructure. A confirmed graph path means directed,
provenance-backed hops within recorded bounds; it does not prove exploitation
or successful data access. Missing or stale evidence remains explicit.

[Explore context, correlation and reachability](docs/PRODUCT_TOUR.md#context-correlation-and-reachability) · [Run the reference lab](examples/reference-evidence-lab/README.md)

## Open the sample graph

```bash
pip install 'agent-bom[ui]==0.108.4'
agent-bom quickstart --run --offline
```

The command writes a sample report and verifies its persisted graph. **Run the
server command it prints in another terminal, then open its exact graph URL.**
Keep that server running. The UI extra and server process are required.

Offline quickstart skips package-CVE lookup; zero CVEs is not a clean verdict.
Use the bundled demo above for advisory-backed findings. For your own offline
scan, first [populate the advisory database](docs/FIRST_RUN.md).

Next, [follow one component and a before/after rescan](examples/connected-bom/README.md).
That source-checkout example parses changed dependency inputs and retains both
snapshots; it does not install packages or change a running deployment.

## Self-host in your environment

**Your infrastructure, identity, database, and audit boundary.** Start a local
pilot from a [published release checkout](https://github.com/koda-ai-studio/agent-bom/releases):

```bash
git clone --depth 1 --branch v0.108.4 https://github.com/koda-ai-studio/agent-bom.git && cd agent-bom
AGENT_BOM_IMAGE_TAG=0.108.4 docker compose up -d
```

Open **http://localhost:3000**, then **Connections** or **New Scan**. The pilot
binds to loopback and retains state in a Docker volume. For cloud accounts, add a
scoped read-only connection, verify access, then start a scan. Use the
[authenticated deployment](site-docs/deployment/authenticated-hosted-instance.md).

- **Scan** with CLI or CI; export findings, SBOMs and reports.
- **Centralize** inventory, graph evidence, remediation and compliance in your own control plane.
- **Enforce** policy on selected live MCP tool calls through the proxy or gateway.

[Docker pilot guide](docs/DEPLOY_QUICKSTART.md) · [Choose a deployment](site-docs/deployment/overview.md) · [Enterprise controls](docs/ENTERPRISE.md) · [Connect cloud accounts](docs/CLOUD_CONNECT.md)

<details>
<summary>Work with your existing tools</summary>

Use **CLI or GitHub Action**, **REST API**, or **MCP**; export **SARIF, CycloneDX,
SPDX, JSON and HTML**. Cloud connectors and fleet sync collect inventory;
proxy and gateway deployments add runtime evidence.

For coding assistants, `agent-bom mcp server` starts with eight focused tools.
[Choose an MCP profile](docs/MCP_SERVER.md) for graph, cloud, runtime or audit work.
[Import existing scanner reports](docs/IMPORTERS.md) without replacing their source evidence.

[Integration capability matrix](docs/INTEGRATIONS.md) · [MCP client setup](docs/MCP_CLIENT_GUIDES.md) · [Smithery setup and manifest](site-docs/integrations/smithery.md)

</details>

## Trust and evidence

Discovery uses read-only access by default. Explicit disk side-scans create
temporary cloud resources. Missing evidence stays unavailable or partial;
control mappings are not audit certification.

[Product boundaries](docs/PRODUCT_BOUNDARIES.md) · [Permissions](docs/PERMISSIONS.md) · [Threat model](docs/THREAT_MODEL.md) · [Release verification](docs/RELEASE_VERIFICATION.md)

## Contributing and support

[Contributing](CONTRIBUTING.md) · [Capabilities and roadmap](docs/ROADMAP.md) · [Support](SUPPORT.md) · [Report an inaccurate finding](https://github.com/koda-ai-studio/agent-bom/issues/new?template=inaccurate_finding.yml) · [Apache-2.0](LICENSE)

Source version: **v0.108.4** · Latest release: **v0.108.4** · [Changelog](CHANGELOG.md)
