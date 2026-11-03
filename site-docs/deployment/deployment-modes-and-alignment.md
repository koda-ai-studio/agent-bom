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
## Choose a dashboard view

Use **Product view** in the expanded sidebar (or the navigation menu on mobile):

- **Personal** is the default. Get started leads with a local command and report
  preview. Governance and Operations stay out of the primary navigation.
- **Shared** brings Operations into the primary navigation for shared scan jobs
  and integrations. Get started opens the shared-source paths.
- **Governance** also brings Governance forward, with compliance and executive
  reporting on Overview. Local report previews still omit tenant compliance.

Use **Show all pages** or search to find additional pages. A direct link keeps
its active group visible. Role, tenant and demo restrictions still apply in
every view. A view does not grant access, change a scan target, enable a service
or filter shared evidence down to the current user. Personal does not mean a
private workspace.

These names describe the work, not company size or a deployment tier. Shared
was previously labelled Team, and Governance was Organization; existing saved
preferences keep working. Personal and Shared skip optional compliance loading
on Overview. Select Governance when that review is useful.

The preference is saved in this browser, not to the control plane. It applies
across tabs on the same origin; if browser storage is unavailable, it lasts only
for the current page session. Choose it explicitly rather than inferring it from
a source label or account role.

## Runtime and packaging

The primary control-plane images are:

- `agentbom/agent-bom`: scanner, API, jobs, proxy, gateway and MCP server runtimes.
- `agentbom/agent-bom-ui`: the browser dashboard companion.

CLI installation does not require either image. The separately packaged
collector serves collection deployments; it is not required for every control
plane. See [Product surfaces](overview.md#product-surfaces) for the owning
commands and [Proxy vs Gateway vs Fleet](proxy-vs-gateway-vs-fleet.md) for runtime
choices. Fleet collection is inventory intake, not inline enforcement.

## Keep the surfaces aligned

Public entry points should lead to a command, an artifact and a next step:

- **Individual:** scan a chosen project, open the report, fix and rescan.
- **Team:** retain a scan, review its source and scope, investigate and compare.
- **Organization:** configure shared access and operations, review scoped
  evidence, then use the governance workflows required by the organization.

Hosting documentation owns deployment prerequisites. API evidence labels own
collection semantics. UI navigation owns task discovery while preserving
server-side authorization. None should infer the other choices from a local,
fleet or cluster label. Keep optional services out of the first-run requirement
unless the selected workflow actually depends on them.
