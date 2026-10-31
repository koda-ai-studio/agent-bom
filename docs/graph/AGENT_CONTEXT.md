# Read agent context without inferring a deployment

Open **Investigation → Explore connections**, select an agent, then inspect its
agent kind, platform association, execution host, model links and environment
membership. The canvas keeps the agent kind and hosting status visible. An AWS
badge on an environment describes that environment; it does not establish that
its agents are Bedrock agents or that a model runs in that AWS account.

| Fact | Evidence used | What it does not establish |
| --- | --- | --- |
| Agent kind / client | The recorded `agent_type` | The model, endpoint or machine used |
| Platform association | Provider → agent `platform_for` | Physical hosting or model invocation |
| Execution host | Agent → infrastructure `hosted_on`, or infrastructure → agent `hosts` | An observed invocation or effective permissions |
| Model links | A direct agent → model `serves_model` relationship | A verified endpoint, model publisher or runtime invocation |
| Environment membership | Recorded containment, ownership or membership relationships | Deployment location or network reachability |

A missing value reads **Not recorded in this evidence**. It does not mean the
agent has no host or model. Review the linked asset and relationship evidence,
then collect the missing configuration or runtime evidence from an authorized
source. Do not infer a host from an agent's vendor, name or environment badge.

## Shared graph representation

Report projection stores `agent_context` under an agent node's attributes with
`schema_version: agent.context.v1`. The full graph persisted by CLI `scan --context-graph`, retained unified-graph
API/MCP consumers and the dashboard receive this direct-relationship summary.
The separate `agent-bom graph REPORT.json` command exports a dependency graph;
it does not include this unified-graph context. Its canonical `relationship`
field uses `platform_for`; the legacy JSON `kind` retains `hosts` for older
consumers. Exported diagrams label the association `platform_for`.

Each context category retains up to 16 references, its recorded count and a
truncation indicator. References include the node identity, label, relationship,
source, evidence kind, recorded account/region and observation time. The summary
does not authorize actions or create an attack path; `platform_for` is structural and non-traversable. Correlation and
current-estate projection recompute the summary from their final relationships,
so references use the resulting node identities and retain hosts from all
selected sources. Historical snapshots remain unchanged.

Existing snapshots remain readable. Historical provider → agent `hosts` links
are interpreted as platform associations in the agent context display. Actual
infrastructure hosting links retain their meaning. An endpoint inventory linked
by an exact source ID records a workstation association; a logical fleet alone
does not establish a host. Neither association proves runtime execution.
When a snapshot has no
context summary, the dashboard derives direct relationships only from the
loaded graph and says so; this fallback does not claim complete inventory.

## Sample environment

The README's Production AI environment is fictional. Its workflow and assistant
agents have no recorded execution host or model endpoint. The AWS badge belongs
to the environment, and its containment arrows mean membership. Dashed tool,
credential and data-access links are configured or modeled evidence, not proof
that access occurred. Follow the CVE impact workspace to distinguish recorded
relationships, advisory conditions and remaining exploitability unknowns.
