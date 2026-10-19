# agent-bom

<!-- mcp-name: io.github.koda-ai-studio/agent-bom -->

**Open security scanner and self-hosted control plane for AI, MCP, and cloud infrastructure.**

**Find vulnerable software behind your AI agents—and trace the exposure evidence.**

For AppSec and platform engineers: scan repositories and MCP configurations,
inspect connected findings, and verify a changed dependency with a rescan.
Credential references are names, not secret values. Recorded relationships do
not prove exploitation or successful data access.

```bash
pip install agent-bom
agent-bom scan .
```

The scan prints inventory, findings, recorded exposure, evidence coverage, and
the next remediation step. Run `agent-bom doctor` if the first scan cannot
start.

For a deterministic sample, use the built-in offline demo. It deliberately
contains blocking findings, so status `1` is the expected security verdict;
the printed report is complete.

```bash
agent-bom scan --demo --offline
```

The demo uses a curated sample for reproducible output within a release; advisory and severity updates can change later releases.

If you want an inspectable sample before scanning your own repo:

```bash
agent-bom samples first-run
agent-bom scan --inventory agent-bom-first-run/inventory.json -p agent-bom-first-run --enrich
```

The bundled first-run stack includes agent inventory, MCP server definitions,
placeholder credential environment variable names, Python/npm manifests, and a
prompt file. See `docs/FIRST_RUN.md` in the repository for the guided flow.

<details>
<summary><b>See the terminal demo</b></summary>

![agent-bom demo](https://raw.githubusercontent.com/koda-ai-studio/agent-bom/main/docs/images/demo-latest.gif)

</details>

## Follow one component

In the self-hosted dashboard, open **Inventory → component → Findings → Compliance**.
The views retain the exact component and scan snapshot, expose recorded relationships
and source evidence, and export loaded evidence with completeness receipts. Control
mappings do not establish evaluated passes or certification.

From a source checkout, [run the connected-BOM example](https://github.com/koda-ai-studio/agent-bom/tree/main/examples/connected-bom).
It retains before/after SQLite snapshots: a changed dependency input removes one
pinned advisory finding while an unrelated synthetic cloud check remains failed.
This bounded example does not change a deployment or qualify a cloud account.

## Recommended starting points

```bash
pip install agent-bom

agent-bom scan .                                 # Repo + MCP + package blast radius
agent-bom quickstart --dry-run --offline          # Sample-data and API/UI next steps
agent-bom samples first-run                      # Inspectable sample AI stack
agent-bom check flask@2.2.0 --ecosystem pypi     # Pre-install package verdict
agent-bom image nginx:latest                     # Container image scan
agent-bom scan . --remediate remediation.md       # Fix-first remediation plan
pip install 'agent-bom[ui]'                      # once, if you want the dashboard
agent-bom serve --persist ~/.agent-bom/control-plane.db  # restart-safe local control plane
```

The base wheel is the scanner/CLI path and includes MCP server mode
(`agent-bom mcp server`). Install optional surfaces explicitly:
`pip install 'agent-bom[ui]'` for the local API/dashboard process. Use
`pip install 'agent-bom[all]'` for supported first-run extras; MLflow remains
separate until its upstream CVE backlog is fixed. If an extra is missing, the
command exits with the matching install hint.

Self-hosted pilot:

```bash
curl -fsSL https://raw.githubusercontent.com/koda-ai-studio/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
# Dashboard -> http://localhost:3000
```

Production chart from a checked-out repo:

```bash
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-production-values.yaml
```

## Product views

### Dashboard

![agent-bom dashboard overview](https://raw.githubusercontent.com/koda-ai-studio/agent-bom/main/docs/images/dashboard-live.png)

### Follow an agent to its findings

![Sample production environment showing agents, MCP servers, dependencies and findings, with modeled access labeled](https://raw.githubusercontent.com/koda-ai-studio/agent-bom/main/docs/images/graph-environment-dark-live.png)

Follow Document Intake Agent → document-tools MCP → pillow@9.0.0 → CVE-2023-4863. This is a fictional sample estate; dashed access and credential links are modeled, not observed execution.

### Inspect why two records are linked

![Repository pin, image inventory and deployment occurrence resolve to one package, with relationship evidence open](https://raw.githubusercontent.com/koda-ai-studio/agent-bom/main/docs/images/graph-relationship-dark-live.png)

Real parsers, modeled local infrastructure: a repository pin, image SBOM and Kubernetes workload resolve to one package. The image inventory and deployment occurrence stay distinct. Select an arrow to inspect its source and evidence; a graph path does not prove execution or exploitation.

[Explore the reference evidence lab](https://github.com/koda-ai-studio/agent-bom/tree/main/examples/reference-evidence-lab) · [Graph guide](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/GALLERY.md)

## What it scans

- **Agents + MCP** — MCP clients, servers, tools, transports, trust posture
- **Skills + instructions** — `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.windsurfrules`, `skills/*`
- **Package risk** — supply-chain scanning across 15 package ecosystems (including `mix.lock` / `pubspec.lock` for Hex and Pub) with OSV/GHSA enrichment and blast radius
- **AI models + datasets** — malicious-model detection via safe pickle-opcode disassembly (no execution), model/dataset cards, and target-scoped PII/PHI dataset-file scanning
- **Container images + IaC** — native OCI parsing plus Dockerfile, Terraform, CloudFormation, Helm, and Kubernetes coverage
- **Cloud estate** — read-only, gated asset inventory across AWS/Azure/GCP plus AI/GPU posture and CIS benchmarks
- **Identity (NHI)** — non-human identity discovery (Okta/Entra), credential-expiry posture, and access-review campaigns
- **LLM cost** — spend forecasting, budget runway, chargeback/allocation, and seasonal-aware spend-anomaly detection
- **Secrets + runtime** — MCP proxy/gateway, inline firewall enforcement, A2A/MCP auth posture, Shield SDK, secrets, and redaction surfaces
- **Compliance + evidence** — mapped governance plus ZIP evidence bundles for auditors

## Key features

- **Blast radius + attack-path fusion** — multi-hop exposure paths over one `UnifiedGraph`, from package → finding → MCP server → credentials → connected agents
- **CWE-aware impact** — RCE shows credential exposure, DoS does not; symbol-level CVE reachability joins CWE/CVE/CPE advisory context when OSV/GHSA carry affected symbols (Python, npm, Go)
- **Portable outputs** — SARIF, CycloneDX, SPDX, OCSF, HTML, graph, JSON, ZIP evidence bundles, and more
- **MCP server mode** — start with 8 scan-profile tools; use `agent-bom mcp server --profile full` for the complete catalog of 94 MCP tools, 7 resources, and 8 workflow prompts in Claude, Cursor, Windsurf, and Cortex CoCo / Cortex Code
- **Skill bundle identity** — stable bundle hashes for skill and instruction file review
- **Dependency confusion detection** — flags internal naming patterns
- **VEX generation** — auto-triage with CWE/CVE/CPE-aware reachability (package + function-level when advisory symbols exist)

Discovery and static/cloud scanning are read-only and agentless. Proxy,
gateway, Shield, and control-plane write tools are separate, explicit runtime
or authenticated operations. No secrets leave your machine unless you
explicitly enable an outbound integration.

## How the data moves

![How agent-bom works](https://raw.githubusercontent.com/koda-ai-studio/agent-bom/main/docs/images/scan-pipeline-light.svg)

## Blast radius

![Blast radius](https://raw.githubusercontent.com/koda-ai-studio/agent-bom/main/docs/images/blast-radius-light.svg)

## Links

- [GitHub](https://github.com/koda-ai-studio/agent-bom)
- [Docker Hub](https://hub.docker.com/r/agentbom/agent-bom)
- [Documentation](https://github.com/koda-ai-studio/agent-bom#readme)
- [Product brief](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/ARCHITECTURE.md)
- [Verified metrics](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/PRODUCT_METRICS.md)
- [Enterprise controls map](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/TRUST.md)
- [Discord](https://discord.gg/3YmYPqKZh5)
