# Product tour

This tour follows current source. The published `0.108.4` release predates
the newer investigation workspace and managed trace enhancements. For commands
that start with the published package, use the [README](../README.md).

<p align="center"><a href="images/graph-environment-dark-live.png"><picture><source media="(prefers-color-scheme: light)" srcset="images/graph-environment-light-live.png"><img src="images/graph-environment-dark-live.png" alt="Environment graph connecting AI agents, models, MCP tools, dependencies and deployed workloads" width="1440"></picture></a></p>

**See your AI environment in context.** Follow workloads, agents, models, MCP servers, tools and dependencies in one graph. Switch to **Repository** or **Cloud estate** to inspect code, build configuration, accounts, identities and storage. The graph above uses labeled sample data. Click any screenshot to view it at full size.

**One investigation workspace:** follow a finding with **Find a path**, or inspect a snapshot with **Explore connections**. Select nodes and relationship arrows for details, expand the connections you need, and carry the finding into remediation. [Repository, environment and cloud gallery](GALLERY.md#explore-connections-and-inspect-evidence) · [Try the connected-BOM walkthrough](../examples/connected-bom/README.md).

These graph enhancements are merged in current source; the published `0.108.4` release predates them. Recorded relationships do not by themselves prove execution or data access.

## Context, correlation and reachability

The useful result is a supported investigation and a next action:

| Operator question | Evidence to inspect |
|---|---|
| **Why does this finding matter here?** | Exact component, affected agent/workload, tool and resource context in the selected snapshot. |
| **Do these records describe the same entity?** | Canonical identifiers, tenant scope and retained source scans; similar names alone do not establish a correlation. |
| **What is the recorded blast radius?** | Directed connections to affected agents, tools, credential references and resources, with collection and traversal limits visible. |
| **Is this path supported?** | Per-hop direction, provenance, freshness and reachability basis; distinguish dependency reachability, recorded permissions and observed runtime activity. |
| **Did the change remove this exposure?** | Re-scan the same scope, compare retained snapshots and inspect remaining findings before closing the work. |

A confirmed graph path describes provenance-backed traversal within collected
evidence. It does not prove exploitation, effective access to every resource,
or complete estate coverage. The experimental [consequence assessment](GRAPH_CONSEQUENCES.md)
keeps assumed compromise, exploitation prerequisites, stopping controls and
missing evidence separate. [Evidence boundaries](PRODUCT_BOUNDARIES.md) ·
[Measure an investigation](operations/INVESTIGATION_MEASUREMENT.md).

## Built for the teams that build, secure and govern AI

| Your team | What you can do |
|---|---|
| **Developers & AI engineers** | Inspect repositories, dependencies and MCP configuration; bring findings into CI and coding assistants. |
| **AppSec & cloud security** | Connect cloud accounts, trace findings through workloads and identities, and prioritize fixes using recorded exposure and evidence gaps. |
| **Platform & DevOps** | Run a shared control plane, collect fleet evidence, and apply policy to MCP traffic through the proxy or gateway. |
| **GRC & audit** | Open **Compliance** to review mappings and [export scan evidence](GALLERY.md#scan-a-repository-before-shipping) with its source, freshness and assessment gaps. |
| **Security & engineering leaders** | Open **Overview** to review posture, remediation priorities and tracked AI spend across connected sources. |
| **AI assistants & automation** | Use [MCP workflows](MCP_WORKFLOWS.md) to query evidence and inspect findings within the caller’s permissions. |

## Product tour

### Security, engineering and GRC: prioritize findings

Start with **Posture**, inspect **Top risks**, and scope **Assets & coverage**. **Compliance** separates evaluated-control pass rate from assessment coverage; OWASP and MITRE ATLAS mappings show applicability. Results from this offline synthetic enterprise estate do not establish certification or an audit opinion.

<p align="center"><a href="images/dashboard-live.png"><img src="images/dashboard-live.png" alt="Posture and open findings with compliance and security-area disclosures collapsed in a labeled sample environment" width="1440"></a></p>

Explore [expanded framework evidence](images/dashboard-paths-live.png), [Top risks](images/dashboard-risks-live.png), [scoped Inventory](images/inventory-live.png), [recorded scan history](GALLERY.md#compare-recorded-scan-history), [framework controls and evidence](../site-docs/features/compliance.md), and the [per-agent BOM preview](SCAN_EVIDENCE_JOURNEY.md).

### AppSec and cloud teams: investigate a finding

Follow **CVE-2023-4863 in pillow@9.0.0** through recorded relationships between the service, workload, container, tool and modeled data asset. Inspect the source receipts and carry the selected finding into remediation. A recorded path does not by itself prove exploitation or successful data access.

<a href="images/correlation-graph-live.png"><img src="images/correlation-graph-live.png" alt="Reference lab graph linking a Pillow advisory, workload, container, tool and modeled data asset" width="1440"></a>

**Inspect the evidence behind an arrow.** Select a relationship to see its direction, retained snapshot, timestamps and recorded source evidence. This focused view shows the reference lab's local gateway invocation; modeled cloud permissions and downstream effects remain separate claims.

<p align="center"><a href="images/graph-relationship-dark-live.png"><picture><source media="(prefers-color-scheme: light)" srcset="images/graph-relationship-light-live.png"><img src="images/graph-relationship-dark-live.png" alt="Reference lab workload and tool relationship with the recorded gateway runtime evidence open beside the graph" width="1440"></picture></a></p>

**Find a path → Explore connections → Inspect evidence → Remediate.** Keep the snapshot and selected finding in scope as you move through the workflow. Expand within a hop limit and browse relationships in bounded pages; incomplete views remain labeled. Configured permissions, observed activity and downstream effects have separate evidence requirements.

[Explore the graph gallery](GALLERY.md#explore-connections-and-inspect-evidence) · [View the mobile graph](images/correlation-path-mobile-live.png) · [Run the reference lab](../examples/reference-evidence-lab/README.md)


### Engineers and GRC: fix and verify

Connect the upgrade decision, the responsible owner and the evidence needed to close the risk.

| Decision | Engineering and governance evidence |
|---|---|
| **What do we fix first?** | Prioritize package upgrades using severity, recorded agent and credential associations, and available fixes. |
| **Who owns the work?** | Assign owners and SLAs, link tickets, and track remediation campaigns. |
| **Did the fix hold?** | Re-scan the same scope, compare retained findings, and verify the campaign before closing it. |
| **What supports the control review?** | Review evaluated checks, source receipts and assessment gaps; export scoped evidence. A control mapping alone is not a passing check. |

<p align="center"><a href="images/remediation-live.png"><img src="images/remediation-live.png" alt="Sample remediation plan with package fixes, affected agents, credential associations and an owner/SLA verification workflow" width="1440"></a></p>

[Run the before-and-after dependency example](../examples/connected-bom/README.md) · [Review component control evidence](images/component-controls-dark-live.png) · [Compliance evidence workflow](../site-docs/features/compliance.md)

These are application captures, not mockups. Overview, Findings and remediation use labeled sample data. Re-scan your own scope for current versions and fixes. The investigation graph uses the reproducible reference lab: real parsers, a pinned advisory scan and authenticated gateway calls, with modeled infrastructure. A blocked call does not establish that the underlying package was fixed.

[Discover and scan](GALLERY.md) · [Runtime policy and agent workflows](../site-docs/deployment/proxy-vs-gateway-vs-fleet.md) ·
[Run the reference evidence lab](../examples/reference-evidence-lab/README.md) ·
[Evidence workflow](HOW_IT_WORKS.md) · [Control-plane architecture](ARCHITECTURE.md)


### Deployment models

| Start with | Guide |
|---|---|
| Local evaluation | [Docker pilot](DEPLOY_QUICKSTART.md) |
| Shared control plane | [Authenticated deployment](../site-docs/deployment/authenticated-hosted-instance.md) · [Compose with PostgreSQL](../deploy/docker-compose.platform.yml) |
| Kubernetes or AWS | [Helm](../site-docs/deployment/control-plane-helm.md) · [EKS Terraform](../deploy/terraform/platform-eks) |
| Restricted networks | [Air-gapped bundle](../site-docs/deployment/airgapped-image-bundle.md) |
| Snowflake preview | [Native App installation](snowflake-native-app/INSTALL.md) |

[Choose a deployment](../site-docs/deployment/overview.md) · [Enterprise configuration](ENTERPRISE.md) · [Connect cloud accounts](CLOUD_CONNECT.md)
