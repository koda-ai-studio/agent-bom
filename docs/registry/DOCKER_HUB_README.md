# agent-bom

**AI supply-chain BOM: every agent, MCP server and AI package, and what each one can reach.**

For AppSec and platform engineers. Self-host free; local scans need no account.

`agent-bom` follows package, agent, MCP, credential-name, cloud estate,
non-human identity, runtime, and skill evidence into one reachability-backed AI
BOM, then tells humans and AI agents which multi-hop exposure path to fix first.

The shared security graph connects packages, workloads, agents, tools, identities, and data assets through typed relationships with source evidence and explicit completeness. Recorded relationships do not establish execution or successful data access.

Blast radius is the core idea:

```text
CVE -> package -> MCP server -> agent -> credentials -> tools
```

This container is the quickest way to run the same scanner, MCP tools, runtime
surfaces, and self-hosted operator path described in the main repository
README.

## Image Model

`agent-bom` is one product with two deployable container images:

- **`agentbom/agent-bom`** — API/runtime image for CLI, API, scanner jobs, gateway, proxy, and MCP server mode
- **`agentbom/agent-bom-ui`** — UI companion image for the self-hosted control plane

Deploy the API and UI images together for the control plane, or use the API
image alone for CLI and runtime workloads. Each can be scaled and patched independently.

## Run This First

Pilot on one workstation:

```bash
curl -fsSL https://raw.githubusercontent.com/koda-ai-studio/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
# Dashboard -> http://localhost:3000
```

For production, configure the database, identity and ingress settings in a
release checkout. Follow the [required secret bootstrap](https://github.com/koda-ai-studio/agent-bom/tree/main/deploy/helm/agent-bom#production-externalsecrets-are-a-separate-stage)
and wait for all four target Secrets before installing the workload:

```bash
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-production-values.yaml
```

References:

- GitHub README: https://github.com/koda-ai-studio/agent-bom/blob/main/README.md
- Product brief: https://github.com/koda-ai-studio/agent-bom/blob/main/docs/ARCHITECTURE.md
- Verified metrics: https://github.com/koda-ai-studio/agent-bom/blob/main/docs/PRODUCT_METRICS.md

## Follow one component

In the self-hosted dashboard, open **Inventory → component → Findings → Compliance**.
The views retain the component and selected evidence scope: the current tenant estate
by default, or an explicit historical scan. They expose recorded relationships and
source evidence, and export loaded evidence with completeness receipts. Control
mappings do not establish evaluated passes or certification.

From a source checkout, [run the connected-BOM example](https://github.com/koda-ai-studio/agent-bom/tree/main/examples/connected-bom).
It retains before/after SQLite snapshots: a changed dependency input removes one
pinned advisory finding while an unrelated synthetic cloud check remains failed.
This bounded example does not change a deployment or qualify a cloud account.

## Choose Your Path

Start with one lane. The scanner, API, UI, gateway, proxy, and MCP tools all
feed the same evidence model.

| Lane | Start with | Produces |
|------|------------|----------|
| **Try the sample** | `docker run --rm -v agentbom-state:/home/abom/.agent-bom agentbom/agent-bom:latest scan --demo --offline` | bundled sample findings in the terminal; security-verdict exit `1` is expected |
| **Send evidence to a control plane** | `docker compose -f docker-compose.pilot.yml up -d` | fleet inventory, scan jobs, graph state, compliance exports |
| **Enforce runtime behavior** | Configure `agent-bom proxy` for a selected MCP server | policy decisions, audit JSONL and runtime alerts; MCP server mode separately exposes scanner tools |

## CLI And Runtime Quick Start

The `agentbom-state` named volume reuses vulnerability and scan state across
disposable containers. Keep this mount on project scans so later runs can use
the existing advisory cache instead of downloading it again.

**Scan agent configuration visible inside the container**

```bash
docker run --rm -v agentbom-state:/home/abom/.agent-bom agentbom/agent-bom:latest agents
```

This container cannot discover host configuration that has not been mounted. For a repository scan, use the explicit project mount below.

**Container-visible posture summary**

```bash
docker run --rm agentbom/agent-bom:latest agents --posture
```

**Pre-install CVE check**

```bash
docker run --rm agentbom/agent-bom:latest check flask@2.0.0
```

**Scan a project directory**

```bash
docker run --rm \
  -v agentbom-state:/home/abom/.agent-bom \
  -v "$(pwd):/workspace" \
  agentbom/agent-bom:latest scan -p /workspace
```

**Export AI BOM (CycloneDX / SPDX)**

```bash
docker run --rm \
  -v agentbom-state:/home/abom/.agent-bom \
  -v "$(pwd):/workspace" \
  agentbom/agent-bom:latest scan -p /workspace -f cyclonedx -o /workspace/ai-bom.json
```

**IaC misconfiguration scan**

```bash
docker run --rm -v "$(pwd):/workspace" agentbom/agent-bom:latest iac /workspace
```

## What You Get

- Blast radius from package to server to agent to credentials and tools
- AI/MCP coverage across agents, MCP, skills, AI models/datasets, runtime,
  containers, cloud, IaC, and GPU
- Supply-chain scanning across 15 package ecosystems with OSV/GHSA enrichment
- Cloud estate inventory (AWS/Azure/GCP/Snowflake) using scoped provider
  credentials, CIS benchmarks and registry-wide image sweeps (ECR/ACR/GAR).
  Inventory is read-only by default. Explicit AWS EBS disk side-scans create
  temporary cloud resources, including snapshots and analysis volumes; they
  require additional permissions and can incur provider charges.
- Non-human identity governance (NHI discovery, credential-expiry, access
  review) and LLM cost forecasting with chargeback and spend-anomaly detection
- Malicious-model detection via safe pickle-opcode disassembly (no execution)
- One unified `Finding` model and `ContextGraph` across CLI, CI, API,
  dashboard, reports, and MCP tools — with ASPM correlation around applications,
  LLM cost fused onto resources, read-only audit-trail behavioral edges, and an
  estate-scale `CONTAINS` roll-up with drill-down for large clouds
- Multi-hop attack-path fusion plus advisory, blast-radius-ordered remediation
  plans for humans and headless agent workflows
- Runtime MCP protection — inline firewall enforcement, secure-by-default
  gateway, A2A/MCP auth-posture checks — plus tamper-evident evidence exports

## Supported Sources

Discovery and scanning read from these sources today; the last row lists where evidence can be sent. The list is generated from a code-backed manifest (`docs/images/integrations-manifest.json`); a test fails if it names anything without an implementation.

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

## Product Surfaces

The promoted self-hosted rollout is a scoped operator stack, not one forced
runtime monolith. Teams typically deploy only the surfaces they need:

- **scan**: discovery, inventory, CVE, image, IaC, Kubernetes, cloud estate (with registry-wide image sweep and agentless EBS disk side-scan), AI model/dataset, and supply-chain analysis
- **fleet**: endpoint and collector inventory pushed into the control plane
- **identity / cost**: non-human identity governance and LLM spend forecasting, chargeback, and anomaly detection
- **proxy / runtime**: inline MCP firewall enforcement near selected workloads
- **gateway**: secure-by-default central policy management for those runtime paths
- **API + UI**: the operator plane for findings, graph, remediation, audit, and policy workflows

## Control-Plane Contract

The API is the source of truth for auth, tenant resolution, RBAC, quotas,
SCIM posture, fleet inventory, graph selectors, policy, secret posture, and
audit. UI displays that posture from the API instead of inventing a parallel
role or tenant model. MCP Gateway consumes the same tenant, policy, audit,
secret-manager, and lifecycle posture model as the API. CLI and local MCP
modes stay low-friction, but label local/dev behavior clearly when they are not
enterprise-controlled.

Helm, EKS examples, Docker metadata, and GitHub Actions should expose the same
environment variable names, fail-closed defaults, and required checks. The
runtime image and UI image are separate deployment units for scaling and patch
cadence, not separate security products.

## OTEL and Policy

OpenTelemetry support includes:

- API request tracing with W3C trace context
- OTLP export for operator telemetry
- OTEL trace ingest through `/v1/traces`
- experimental trace collection and graph workflows, enabled with
  `AGENT_BOM_EXPERIMENTAL=traces`; see the [trace connection guide](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/TRACE_CONNECTIONS.md)

Policy is native by default. The shipped gateway and proxy use the repo's JSON
policy engine. An OPA/Rego runtime is not included.

## Deploy In Your Own Infra

`agent-bom` is designed to run inside your own AWS account, VPC, EKS cluster,
IAM boundary, databases, and SSO stack.

Recommended shape:

- stateless API + UI deployments behind your ingress
- Postgres for transactional state and graph metadata
- optional ClickHouse only when audit and analytics volume justifies it
- scheduled scan jobs for cluster, image, and discovery work
- endpoint fleet sync for laptops and collectors
- selected `agent-bom proxy` sidecars or local wrappers for the MCP workloads that need inline enforcement
- gateway-backed policy pull so runtime controls stay centralized without hairpinning all traffic through one shared chokepoint

Everything stays in your infrastructure by default; optional egress for DB
refresh, enrichment, SIEM, OTLP, and webhooks is operator-controlled.

## Security Posture

- HTTPS for every external hop
- private in-cluster traffic or service-mesh mTLS for internal hops
- auth on every non-loopback control-plane surface
- production profiles set `AGENT_BOM_DISABLE_DOCS=1` so `/docs`, `/redoc`, and `/openapi.json` are not exposed as unauthenticated helper routes
- shared control-plane profiles set `AGENT_BOM_API_LOCAL_PATH_SCANS=disabled`; enable API-local filesystem scans only for an explicit single-tenant mounted workspace
- RBAC and tenant scoping on sensitive routes
- rate limiting, audit trails, and signed release artifacts
- HMAC-backed tamper evidence for exported bundles

## Dashboard Views

Dashboard overview:

![agent-bom dashboard overview](https://raw.githubusercontent.com/koda-ai-studio/agent-bom/main/docs/images/dashboard-live.png)

Attack paths and exposure:

![agent-bom dashboard attack paths and exposure](https://raw.githubusercontent.com/koda-ai-studio/agent-bom/main/docs/images/dashboard-paths-live.png)

Focused agent mesh graph:

![agent-bom agent mesh graph](https://raw.githubusercontent.com/koda-ai-studio/agent-bom/main/docs/images/mesh-live.png)

## Tags

| Tag | Description |
|-----|-------------|
| `latest` | Most recent stable release |
| `0.112.1` | Version used by the examples below; verify registry availability before pinning |

Published images:

- `agentbom/agent-bom` — main runtime image for CLI scans, API/control-plane
  jobs, gateway, proxy-adjacent entrypoints, and MCP server mode
- `agentbom/agent-bom-ui` — standalone Next.js browser UI image for
  self-hosted deployments that run the UI separately from the API

For local Docker Compose examples, the repo may use local-built image aliases
such as `agent-bom:latest` and `agent-bom-ui:latest`. Those are compose-facing
names for local builds from this repo, not a second published product line.

## Links

- GitHub: https://github.com/koda-ai-studio/agent-bom
- PyPI: https://pypi.org/project/agent-bom/
- Docs: https://koda-ai-studio.github.io/agent-bom/
- GitHub Action: https://github.com/marketplace/actions/agent-bom
- Pre-commit hooks: https://github.com/koda-ai-studio/agent-bom/blob/main/.pre-commit-hooks.yaml
