# Deployment Modes and Alignment

Use the [Deployment Overview](overview.md#choose-your-workflow) to choose a
starting path. This page explains how workflow, hosting, evidence sources and
runtime surfaces relate. They are independent choices within one product.

## Four different choices

| Choice | Examples | What it determines |
|---|---|---|
| **Workflow** | individual project review, team investigation, organization governance | Which tasks and evidence are useful first. It does not grant permissions. |
| **Hosting** | CLI process, loopback dashboard pilot, authenticated single host, Kubernetes | Where processes and data run, and which storage, identity and operations must be configured. |
| **Evidence sources** | local, CI, fleet, cluster, imported artifacts | What collection is recorded. These labels do not identify the audience or hosting topology. |
| **Runtime enforcement** | selected local proxy, shared gateway, neither | Whether selected tool traffic passes through an enforcement surface. Scanning alone does not enable it. |

A developer can scan cloud infrastructure without adopting organization
governance. A team can review local and CI scans without running a gateway.
An organization can use a single authenticated host; Kubernetes is a hosting
choice, not a requirement for compliance.

## Start with the relevant product surfaces

| Workflow | First surface and result | Expand when needed |
|---|---|---|
| **Individual / developer** | CLI or assistant workflow → report → finding → reviewed fix → rescan | Add CI checks, browser report review or a local MCP proxy for selected tool traffic. |
| **Team** | CLI/CI reports, or shared Findings and Investigation over retained scans | Add connected sources, endpoint fleet inventory, job review and shared runtime controls. |
| **Organization** | Team evidence plus scoped access and operating controls | Use compliance assessments, audit review, retention/export integrations and executive reporting for governance needs. |

These are adoption paths, not separate editions or license gates. Compliance frameworks and executive reporting are optional
workflows. Framework mappings in findings remain investigation context and do
not establish certification. An individual scan needs no shared control-plane
database, identity provider or governance configuration.

Authentication, role permissions and tenant scope apply independently of which
workflow a user follows. A simpler presentation must not imply broader access
or that shared evidence has become private to the current user.

## Hosting profiles

| Host | Starting point | Boundary |
|---|---|---|
| **CLI only** | [First Run Guide](https://github.com/koda-ai-studio/agent-bom/blob/main/docs/FIRST_RUN.md) | Writes reports without deploying an API or UI. Advisory lookups may use the network; use the documented offline path when required. |
| **Loopback dashboard pilot** | `scripts/deploy/install.sh pilot` | API + UI with SQLite for one-workstation evaluation. The shipped no-auth pilot is not a shared service. |
| **Authenticated single host** | Compose platform, with the documented product overlay where needed | Configure authentication, TLS, PostgreSQL and operational secrets before exposing the service. |
| **Customer Kubernetes** | Helm chart; EKS reference installer | Customer-operated identity, stores, workers and optional runtime services. Follow the profile's prerequisites. |

See the [deployment support tiers](overview.md#support-tiers) for AKS/GKE,
Snowflake, air-gapped packaging and community targets. Preview packaging is not
proof of a validated deployment. The product does not currently include a
managed cloud offering.

## Observed evidence modes

The API's `deployment_mode` field describes observed evidence sources, not a
configuration switch. Its name is retained for API compatibility.

| Value | Meaning |
|---|---|
| `local` | Local discovery sources are recorded. |
| `fleet` | Fleet inventory is recorded. |
| `cluster` | Cluster collection or a recognized cluster environment is recorded. |
| `ci` | CI/CD collection sources are recorded. |
| `hybrid` | More than one of local, fleet, cluster or CI collection is recorded. |
| `ingest` | Scan or runtime evidence is recorded without those collection signals. |
| `unknown` | Collection is not observed. This is missing evidence, not proof that no assets exist. |

`has_local_scan` requires an explicit local discovery source; imported SBOMs or
agent relationships do not establish that a local scan ran. An ingestion-only
control plane can still display recorded agents and their evidence.

These values do not choose databases, enable enforcement, identify an individual
versus a team, or change permissions. A policy record or runtime-related flag
also does not by itself prove a proxy or gateway is currently running. Review
runtime receipts and health separately.

The source contract lives in
[`compliance_routes/common.py`](https://github.com/koda-ai-studio/agent-bom/blob/main/src/agent_bom/api/routes/compliance_routes/common.py);
browser labels and evidence-based surface availability live in
[`deployment-context.ts`](https://github.com/koda-ai-studio/agent-bom/blob/main/ui/lib/deployment-context.ts).
## Dashboard navigation

The sidebar exposes the platform's navigation groups without a product-view
preset. Use search to find a page, or expand its group. Permissions and actual
deployment capabilities still determine which actions are available.

Deployment mode describes where services run and which evidence is available.
It does not select an audience or hide platform pages. Local report previews
remain scoped to the imported report and do not load tenant compliance.
