<p align="center">
  <img src="docs/images/social-preview.svg" alt="agent-bom — Discover. Scan. Correlate. Act. Security evidence across repositories, software supply chains, AI and MCP, cloud, identity, and data." width="1280" />
</p>

<p align="center">
  <a href="https://github.com/koda-ai-studio/agent-bom/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/koda-ai-studio/agent-bom/ci.yml?branch=main&style=flat&label=Build&logo=github" alt="Build"></a>
  <a href="https://pypi.org/project/agent-bom/"><img src="https://img.shields.io/pypi/v/agent-bom?style=flat&label=PyPI&logo=pypi&logoColor=white&cacheSeconds=60" alt="PyPI"></a>
  <a href="https://pypi.org/project/agent-bom/"><img src="https://img.shields.io/badge/Python-3.11%E2%80%933.14-blue?style=flat&logo=python&logoColor=white" alt="Python 3.11 through 3.14"></a>
</p>
<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=flat" alt="Apache-2.0 license"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/koda-ai-studio/agent-bom"><img src="https://img.shields.io/ossf-scorecard/github.com/koda-ai-studio/agent-bom?style=flat&label=OpenSSF%20scorecard" alt="OpenSSF Scorecard"></a>
</p>
<!-- mcp-name: io.github.koda-ai-studio/agent-bom -->

<p align="center"><b>AI supply-chain BOM: every agent, MCP server and AI package, and what each one can reach.</b></p>

For AppSec and platform engineers. Self-host free; local scans need no account.

<p align="center">
  <a href="#quick-start"><b>Quick start</b></a> ·
  <a href="#integrations">Integrations</a> ·
  <a href="#open-the-sample-graph">Sample graph</a> ·
  <a href="#self-host-in-your-environment">Self-host</a> ·
  <a href="docs/GALLERY.md">Product tour</a> ·
  <a href="https://koda-ai-studio.github.io/agent-bom/">Docs</a>
</p>

## Quick start

From the repository you want to inspect, with [uv installed](https://docs.astral.sh/uv/getting-started/installation/):

```bash
uvx agent-bom scan .
```

Measured on real repositories: [299 of 299 OSV advisories matched across seven
real repositories, no false positives](site-docs/features/real-repository-accuracy.md).

Read the discovered agents and MCP servers, prioritize the highest-severity
findings, and follow the affected package's fix guidance. Review coverage gaps
beside the verdict: incomplete evidence is not a clean assessment.
[What this scan does and does not establish](docs/FIRST_RUN.md#what-this-scan-does-and-does-not-establish).

No project handy? Run `uvx agent-bom scan --demo --offline` for a bundled sample.
Exit `1` is expected: the sample trips the security gate. A non-zero exit
can mean a security gate or incomplete assessment; inspect the report and coverage.
See the [exit codes](site-docs/reference/exit-codes.md).

<details>
<summary>Verify fixes, export reports, and add a CI gate</summary>

Apply a reviewed fix, update the lockfile, then rerun `uvx agent-bom scan .`
against the same repository to verify the finding changed.
Save a report with `uvx agent-bom scan . -f sarif -o findings.sarif`, then
[upload it and gate CI](docs/FIRST_RUN.md#5-gate-ci-on-the-result).
Run `uvx agent-bom doctor` if setup fails. See the [first-run guide](docs/FIRST_RUN.md)
for pip installation, or ask your coding agent with the [`checkup` skill](#integrations).

In GitHub Actions, the same scan uploads SARIF to code scanning and fails on
high or critical findings, the same default gate as the CLI:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v4
  - uses: koda-ai-studio/agent-bom@v0
    with:
      upload-sarif: 'true'
```

</details>



<p align="center"><img src="docs/images/demo-latest.gif" alt="Recorded agent-bom CLI showing sample findings and remediation guidance; no fix executed" width="920" /></p>

The recording uses labeled sample data and bundled advisories. Credential
references are names, not secret values. Recorded relationships do not prove
exploitation or successful data access.

## What it covers

| Area | What you get |
|---|---|
| Dependencies | Lockfiles and manifests across Python, JavaScript, Go, Java, .NET, Rust and more, matched against OSV, GitHub advisories and NVD with KEV and EPSS. Ask "am I affected by CVE-X" across every stored scan. |
| Code | Findings from Semgrep or any SARIF tool, plus native analysis of AI code (prompt-injection sinks, guardrails, tool exposure) and whether your code reaches the vulnerable function. |
| Containers and IaC | Images scanned in bounded memory and time; Dockerfile, Terraform, Kubernetes, Helm and compose risks with exact lines in SARIF. |
| AI agents and MCP | Agents, MCP servers, tools and credentials from local configs and agent frameworks, linked to what they can reach. |
| Cloud | Read-only collection from AWS, Azure, GCP, Databricks, Snowflake and more, with CIS and best-practice checks in the same graph. |
| Runtime | An MCP proxy and gateway that alert on poisoned tools and injected results, or block them with `--injection-mode enforce`. |

<details>
<summary>All supported sources and evidence destinations</summary>

Discovery and scanning read from these sources; the last row lists evidence destinations.

<!-- integrations:begin (generated by scripts/render_social_preview_svg.py; do not edit) -->
| Area | Integrations |
|---|---|
| AI clients + IDEs | Claude, Codex, Cursor, GitHub Copilot, Windsurf, Cortex Code, Gemini CLI, JetBrains AI, Junie, Amazon Q, Cline, Roo Code, Continue, Zed, Goose, Snowflake CLI, Docker MCP Toolkit, Tabnine, Sourcegraph Cody, Aider, Void, Aide, Trae, Pieces, OpenClaw, mcp-cli |
| AI platforms + model hubs | OpenAI, Hugging Face, Ollama, MLflow, W&B, Langfuse, LangSmith |
| GPU + neo clouds | CoreWeave, Nebius, Lambda, RunPod, Vast.ai, Crusoe, GPU containers + K8s GPU nodes |
| Hyperscalers + Kubernetes | AWS, Azure, GCP, Kubernetes |
| Data + vector stores | Snowflake, Databricks, Supabase, Pinecone, Qdrant, Weaviate, Chroma, Milvus |
| Identity + SaaS + dev | Okta, GitHub Actions, Vercel, Microsoft Entra ID, Jira, ServiceNow, Slack, Jamf |
| Evidence out | ClickHouse, BigQuery, S3, GCS, Azure Blob, Jira tickets, Slack alerts, Vanta, Drata, OCSF syslog |

Product names and logos are trademarks of their owners, used only to identify supported evidence sources. Their use does not imply endorsement or partnership.
<!-- integrations:end -->

</details>

## Investigate context and exposure

**Which agent uses the vulnerable component? What could it reach? What evidence supports that path?**
Correlate retained scans by exact, tenant-scoped identities; trace the recorded
blast radius from each agent through its MCP servers to packages, findings,
credentials and data stores. Inspect each relationship's source and evidence
kind, then rescan the same scope to check what changed.

<p align="center"><a href="docs/images/graph-environment-dark-live.png"><picture><source media="(prefers-color-scheme: light)" srcset="docs/images/graph-environment-light-live.png"><img src="docs/images/graph-environment-dark-live.png" alt="Sample production AI environment: Document Intake Agent uses a document-tools MCP server that depends on pillow 9.0.0, linked to KEV-listed CVE-2023-4863; Support Triage Agent uses a ticketing MCP server that references TICKETING_API_KEY, which can access a customer ticket archive" width="1100"></picture></a></p>

*Fictional sample estate. Dashed use, credential and access links are configured
or modeled, not observed at runtime; path analysis covers the collected snapshot only.*
[Open the full-size environment graph](docs/images/graph-environment-dark-live.png).

**From agent to verified fix:** select Document Intake Agent → inspect
CVE-2023-4863 (high, KEV-listed) and the evidence on each arrow → take the
proposed [remediation](docs/GALLERY.md#engineers-and-grc-fix-and-verify) →
[rescan the changed pin](examples/connected-bom/README.md) and compare snapshots.
The comparison verifies the changed input, not a running deployment.

<details>
<summary>Inspect the evidence: one package, three parsed inputs</summary>

**Supporting evidence: one package, three parsed inputs.** A repository pin, an
image SBOM and a modeled Kubernetes workload resolve to one `pillow@9.0.0`. The
image inventory and the deployment occurrence stay separate nodes; the advisory
receipt is open.

<p align="center"><a href="docs/images/graph-relationship-dark-live.png"><picture><source media="(prefers-color-scheme: light)" srcset="docs/images/graph-relationship-light-live.png"><img src="docs/images/graph-relationship-dark-live.png" alt="Repository pin, image inventory and Kubernetes deployment occurrence resolving to one pillow package linked to KEV-listed CVE-2023-4863, with the plain-language relationship evidence open" width="1100"></picture></a></p>

*Real parsers, modeled infrastructure; a graph path does not prove exploitation.*
[Open the full-size relationship graph](docs/images/graph-relationship-dark-live.png).

[Explore context, correlation and reachability](docs/GALLERY.md#context-correlation-and-reachability) · [Run the reference lab](examples/reference-evidence-lab/README.md) · [Reproduce these screenshots](docs/GALLERY.md#reproduce-the-readme-screenshots)

</details>

Explain a finding to your team: [create an impact brief](docs/operations/IMPACT_BRIEF.md)
with affected assets, source receipts, evidence gaps and the next action to review.

Am I affected by a new CVE? Match it against stored scans, including CVEs only
NVD has published, and get affected assets with their patch target, possibly
affected distro packages to verify, and the blast radius
([walkthrough](docs/RESPOND_TO_A_NEW_CVE.md)):

```bash
agent-bom db update                                   # refresh OSV, NVD, KEV and EPSS
agent-bom db advisory affected CVE-2026-109618        # most recent saved scan
agent-bom db advisory affected CVE-2026-109618 --report <scan-report.json> --format json   # a JSON report written by an earlier scan
```

From an MCP client, the read-only `affected_assets` tool (`graph` and `full`
profiles) takes the same `advisory_id`. In CI, run `uvx agent-bom db update`
before the GitHub Action step above (its `auto-update-db` default only
refreshes feeds older than seven days); the rescan then fails on the new
advisory at the configured severity.

<details>
<summary>Repository and cloud investigations</summary>

Trace source imports, deployment configuration and CI to a published container
and its vulnerable packages:

<p align="center"><a href="docs/images/graph-repository-dark-live.png"><picture><source media="(prefers-color-scheme: light)" srcset="docs/images/graph-repository-light-live.png"><img src="docs/images/graph-repository-dark-live.png" alt="Sample repository linking source, deployment configuration and a CI job to a container, vulnerable npm and PyPI packages, their advisories and a CI misconfiguration" width="1100"></picture></a></p>

Follow a public API gateway into a vulnerable workload, its role and a PII bucket:

<p align="center"><a href="docs/images/graph-cloud-dark-live.png"><picture><source media="(prefers-color-scheme: light)" srcset="docs/images/graph-cloud-light-live.png"><img src="docs/images/graph-cloud-dark-live.png" alt="Sample cloud account where a public API gateway exposes a workload with a critical advisory that authenticates as a role permitted to read a PII bucket" width="1100"></picture></a></p>

</details>


## Open the sample graph

[Try the demo in your browser](https://koda-ai-studio.github.io/agent-bom/demo/): a read-only copy of the UI on
labelled sample data, with no install and no backend. Scans, settings and
sign-in are turned off there. To open the same graph locally:

```bash
pip install 'agent-bom[ui]==0.111.0'
agent-bom quickstart --run --offline
```

Run the server command it prints, then open its graph URL. Offline quickstart
skips package-CVE lookup, so zero CVEs is not a clean verdict; use the bundled
demo for advisory-backed findings or [populate the advisory database](docs/FIRST_RUN.md).

## Self-host in your environment

**Your infrastructure, identity, database, and audit boundary.** Start a local
pilot from a [published release checkout](https://github.com/koda-ai-studio/agent-bom/releases):

```bash
git clone --depth 1 --branch v0.111.0 https://github.com/koda-ai-studio/agent-bom.git && cd agent-bom
AGENT_BOM_IMAGE_TAG=0.111.0 docker compose up -d
```

Open **http://localhost:3000**, then **Connections** or **New Scan**. The pilot
binds to loopback and retains state in a Docker volume. For cloud accounts, add a
scoped read-only connection, verify access, then start a scan. Use the
[authenticated deployment](site-docs/deployment/authenticated-hosted-instance.md).

- **Scan** with CLI or CI; export findings, SBOMs and reports.
- **Centralize** inventory, graph evidence, remediation and compliance in your own control plane.
- **Enforce** policy on selected live MCP tool calls through the proxy or gateway.

[Docker pilot guide](docs/DEPLOY_PLATFORM.md) · [Compose with PostgreSQL](deploy/docker-compose.platform.yml) · [Choose a deployment](site-docs/deployment/overview.md) · [Enterprise controls](docs/TRUST.md) · [Connect cloud accounts](docs/CLOUD_CONNECT.md)

<details>
<summary>Work with your existing tools</summary>

Use **CLI or GitHub Action**, **REST API**, or **MCP**; export **SARIF, CycloneDX,
SPDX, JSON and HTML**. Cloud connectors and fleet sync collect inventory;
proxy and gateway deployments add runtime evidence.

For other MCP clients, run `agent-bom mcp server`.
Start with eight focused tools in the default profile.
[Choose an MCP profile](docs/MCP_SERVER.md) for graph, cloud, runtime or audit work.
[Try three investigations](docs/MCP_SERVER.md#investigation-workflows): affected agents, exposure receipts and a before/after scan comparison.
[Import existing scanner reports](docs/IMPORTERS.md) without replacing their source evidence.

Check a dependency before installing it with
`uvx agent-bom check requests@2.33.0 --ecosystem pypi`. Add
[pre-commit and CI setup](docs/FIRST_RUN.md#pre-commit-hook) for repeated checks.

[Proxy, gateway and fleet](site-docs/deployment/proxy-vs-gateway-vs-fleet.md) · [Integration capability matrix](docs/CLOUD_CONNECT.md) · [MCP client setup](docs/MCP_SERVER.md) · [Smithery setup and manifest](site-docs/integrations/smithery.md)

</details>

## Integrations

<details>
<summary><b>Claude Code and Codex plugins</b>: ask your coding agent instead of reading a report</summary>

Ask your coding agent instead of reading a report. In Claude Code:

```text
/plugin marketplace add koda-ai-studio/agent-bom
/plugin install agent-bom@agent-bom
```

In Codex, run `codex plugin marketplace add koda-ai-studio/agent-bom`, then
install **agent-bom-local** from the Plugins Directory. Both plugins run the
pinned agent-bom release locally and send nothing to an agent-bom service.

| Ask | Skill |
|---|---|
| "Is this project safe to ship?" | `checkup`: one verdict and the three fixes that matter most |
| "Am I affected by CVE-2025-29927?" | `affected`: affected or not found in what was scanned, never "safe" |
| "What have my agents been doing?" | `activity`: MCP usage, unused servers, risky commands from local session history |
| "Are my agent settings too permissive?" | `audit-mcp` and `audit-skills` |
| "Give me an AI-BOM" | `bom`: CycloneDX or SPDX for this machine, a project, an image or a cloud account |

Add `/plugin install agent-bom-guard@agent-bom` to block malicious and
typosquatted package installs before Claude runs them.
[All skills and their permissions](integrations/claude-code/README.md) ·
[Guard details](integrations/agent-bom-guard/README.md)

</details>

## Trust and evidence

Discovery uses read-only access by default. Explicit disk side-scans create
temporary cloud resources. Missing evidence stays unavailable or partial;
control mappings are not audit certification.

<details>
<summary>Runtime evidence and MITRE mapping boundaries</summary>

Persisted runtime, proxy and gateway activity retains source receipts and
bounded time windows in the graph. Exact inventory references can bind records;
unresolved identities and collection gaps remain explicit. Recorded activity
does not prove execution or grant access. See the [runtime evidence boundaries](docs/TRACE_CONNECTIONS.md).

MITRE technique associations provide investigation context, not proof of an
attack. [ATLAS mapping receipts](docs/ATLAS_COVERAGE.md) retain the weakness
association and source catalog hashes; modeled graph paths do not establish
observed execution or effective access.

</details>

[Measured matcher proof](site-docs/features/scanning.md#reproducible-matching-evidence) · [Product boundaries](docs/PRODUCT_BOUNDARIES.md) · [Permissions](docs/PERMISSIONS.md) · [Threat model](docs/THREAT_MODEL.md) · [Release verification](docs/RELEASE_VERIFICATION.md) · [Graph data model](docs/graph/DATA_MODEL.md)

## Contributing and support

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/koda-ai-studio/agent-bom)

Start with the [first PR guide](CONTRIBUTING.md#your-first-pr-in-30-minutes)
or a [`good first issue`](https://github.com/koda-ai-studio/agent-bom/issues?q=is%3Aopen+label%3A%22good+first+issue%22).
Ask in [GitHub Discussions](https://github.com/koda-ai-studio/agent-bom/discussions) (or [Discord](https://discord.gg/3YmYPqKZh5)), share [feedback](https://github.com/koda-ai-studio/agent-bom/issues/new?template=feedback.yml),
or follow the [maintainer path](GOVERNANCE.md) ([review owners](MAINTAINERS.md)).

[Contributing](CONTRIBUTING.md) · [Capabilities and roadmap](docs/ROADMAP.md) · [Support](SUPPORT.md) · [Report an inaccurate finding](https://github.com/koda-ai-studio/agent-bom/issues/new?template=inaccurate_finding.yml) · [Apache-2.0](LICENSE)

Source version: **v0.111.0** · Latest release: **v0.111.0** · [Changelog](CHANGELOG.md)
