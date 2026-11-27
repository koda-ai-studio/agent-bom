import fs from "node:fs/promises";
import path from "node:path";
import { CREATED_AT } from "./product-proof-fixtures.mjs";
import riskFixture from "../tests/fixtures/product-proof-rollup.json" with { type: "json" };
import layerByEntityType from "../tests/fixtures/product-proof-layers.json" with { type: "json" };

const UI_ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");

// The generated taxonomy owns direction and traversal, including correlations.
const graphSchemaSource = await fs.readFile(path.join(UI_ROOT, "lib/graph-schema.generated.ts"), "utf8");
const graphRelationshipJson = graphSchemaSource.match(/export const GRAPH_EDGE_KIND_META:[^\n]+ = (\{[\s\S]*?\n\});/);
if (!graphRelationshipJson) throw new Error("Generated graph relationship taxonomy is missing");
// The TypeScript generator appends a comma after the final dictionary entry.
export const graphRelationshipSpecs = JSON.parse(graphRelationshipJson[1].replace(/,\s*}$/, "\n}"));
const galleryAdvisories = JSON.parse(await fs.readFile(path.join(UI_ROOT, "fixtures/gallery-advisories.json"), "utf8")).advisories;
const advisoryById = new Map(galleryAdvisories.map((item) => [item.id, item]));
export function advisory(id) {
  const item = advisoryById.get(id);
  if (!item) throw new Error(`Gallery advisory is not verified: ${id}`);
  return item;
}

export const SCAN_ID = "scan-proof-ai-platform";
export const SCENARIO_ID = "scenario-upgrade-next";

export function severityId(severity) {
  return { none: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity] ?? 0;
}

export function node(id, entityType, label, severity = "none", riskScore = 0, attributes = {}) {
  return {
    id,
    entity_type: entityType,
    label,
    category_uid: 0,
    class_uid: 0,
    type_uid: 0,
    status: "active",
    risk_score: riskScore,
    severity,
    severity_id: severityId(severity),
    first_seen: CREATED_AT,
    last_seen: CREATED_AT,
    attributes,
    // The layer the API stamps on every node: a recorded layer, else the backend legend's layer for the kind.
    semantic_layer: attributes.semantic_layer ?? layerByEntityType[entityType] ?? "asset",
    compliance_tags: attributes.compliance_tags ?? [],
    data_sources: attributes.data_sources ?? ["demo-scan", "gateway-runtime", "fleet-sync"],
    dimensions: {
      owner: String(attributes.owner ?? "platform-security"),
      environment: String(attributes.environment ?? "prod"),
    },
  };
}

export function edge(source, target, relationship, weight = 1, evidence = {}) {
  const spec = graphRelationshipSpecs[relationship];
  if (!spec) throw new Error(`Unknown sample relationship: ${relationship}`);
  return {
    id: `${source}->${target}:${relationship}`,
    source,
    target,
    relationship,
    direction: spec.direction,
    weight,
    traversable: spec.traversable,
    first_seen: CREATED_AT,
    last_seen: CREATED_AT,
    // Hand-authored sample topology is modeled; it is not a runtime receipt.
    evidence: { tier: "modeled_infrastructure", source: "gallery-fixture", ...evidence },
    activity_id: 1,
  };
}

const SEVERITIES = ["critical", "high", "medium", "low"];

function advisoryNode(id, cveId, extra = {}) {
  const facts = advisory(cveId);
  return node(id, "vulnerability", cveId, facts.severity, facts.cvss_score, { ...facts, simulated: true, ...extra });
}

// A package carries the worst severity and score of the advisories recorded against it.
function packageNode(id, name, version, ecosystem, cveIds = []) {
  const [worst] = cveIds.map(advisory).sort((left, right) => right.cvss_score - left.cvss_score);
  return node(id, "package", `${name}@${version}`, worst?.severity ?? "none", worst?.cvss_score ?? 0, { ecosystem, version });
}

export function severityCounts(nodes) {
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
  for (const item of nodes) if (item.severity in counts) counts[item.severity] += 1;
  return counts;
}

// The recorded-signal boosts of src/agent_bom/graph/path_derivation.py
// (_fusion_signals_for_path); each signal counts once per path.
const PATH_SIGNAL_BOOSTS = [
  ["internet_exposed", 15],
  ["admin_equivalent", 18],
];

// Path risk on the canonical 0-100 scale: the target finding's score
// (CVSS x 10 for an advisory, node risk x 10 otherwise) plus recorded signals.
export function pathRisk(graphNodes, hops) {
  const byId = new Map(graphNodes.map((item) => [item.id, item]));
  const target = byId.get(hops[hops.length - 1]);
  const base = (target.entity_type === "vulnerability" ? target.attributes.cvss_score : target.risk_score) * 10;
  const boosts = PATH_SIGNAL_BOOSTS
    .filter(([attribute]) => hops.some((id) => byId.get(id)?.attributes?.[attribute] === true))
    .reduce((sum, [, boost]) => sum + boost, 0);
  return Math.round(Math.min(100, base + boosts) * 10) / 10;
}

// Labels of the credentials/tools a path touches: hop nodes of that type plus
// what each hop exposes or provides directly.
function pathExposure(byId, links, hops, relationship, type) {
  const labels = [];
  for (const id of hops) {
    const reached = byId.get(id)?.type === type ? [id]
      : links.filter((item) => item.source === id && item.relationship === relationship).map((item) => item.target);
    for (const candidate of reached) {
      const label = byId.get(candidate)?.label;
      if (label && !labels.includes(label)) labels.push(label);
    }
  }
  return labels;
}

export function hopsAreConnected(graphEdges, hops) {
  return hops.slice(0, -1).every((source, index) =>
    graphEdges.some((item) => item.source === source && item.target === hops[index + 1]));
}

// Synthetic configuration records exercise static-scan presentation; these are not live scan receipts.
const SAMPLE_CONFIG_EVIDENCE = { tier: "static_scan", source: "synthetic-config-scan", simulated: true };

export function buildGraph() {
  const nodes = [
    node("provider:aws-prod", "provider", "AWS prod account", "medium", 5.4, { environment: "prod", owner: "cloud-platform" }),
    node("env:prod-ai", "environment", "prod-ai-control-plane", "high", 7.8, { environment: "prod", owner: "ai-platform" }),
    node("cluster:eks-ai", "cluster", "eks-ai-runtime", "high", 7.5, { environment: "prod", owner: "platform-security" }),
    node("container:agent-gateway", "container", "agent-gateway:0.91.0", "high", 7.6, { container_kind: "workload", image: "agent-bom/gateway:0.91.0", internet_exposed: false }),
    node("container:copilot-portal", "container", "copilot-portal:2.4.0", "critical", 9.1, { container_kind: "workload", image: "registry.example.com/ai-platform/copilot-portal:2.4.0", internet_exposed: true, owner: "platform-security", environment: "prod" }),
    node("agent:developer-copilot", "agent", "Developer Copilot", "critical", 9.4, { agent_type: "ide", owner: "platform-security", environment: "prod" }),
    node("agent:sre-runbook", "agent", "SRE Runbook Agent", "high", 8.6, { agent_type: "runbook", owner: "sre", environment: "prod" }),
    node("agent:finance-rag", "agent", "Finance RAG Agent", "high", 8.2, { agent_type: "rag", owner: "finance-data", environment: "prod" }),
    node("user:contractor", "user", "contractor-reviewer", "high", 8.4, { owner: "identity", environment: "prod" }),
    node("sa:jit-review", "service_account", "jit-prod-reviewer", "high", 8.1, { owner: "identity", environment: "prod" }),
    node("role:prod-admin", "role", "prod-ai-admin", "critical", 9.2, { owner: "identity", environment: "prod", admin_equivalent: true, privilege_level: "admin" }),
    node("policy:gateway-default-deny", "policy", "default-deny gateway policy", "medium", 4.8, { owner: "platform-security" }),
    node("server:github", "server", "github-enterprise MCP", "critical", 9.1, { transport: "sse", registry_verified: true }),
    node("server:filesystem", "server", "filesystem MCP", "critical", 9.0, { transport: "stdio", scope: "/workspace/prod" }),
    node("server:snowflake", "server", "snowflake-rag MCP", "high", 8.4, { transport: "sse", scope: "finance_warehouse" }),
    node("server:slack", "server", "incident-slack MCP", "high", 7.8, { transport: "sse" }),
    node("tool:repo-write", "tool", "create_pull_request", "high", 8.2, { tool_class: "repo-write" }),
    node("tool:exec", "tool", "execute_command", "critical", 9.5, { tool_class: "shell", capabilities: ["execute"] }),
    node("tool:query", "tool", "run_sql", "high", 8.3, { tool_class: "data-query" }),
    node("tool:post", "tool", "post_incident_update", "medium", 4.8, { tool_class: "messaging" }),
    node("cred:github", "credential", "GITHUB_ENTERPRISE_TOKEN", "critical", 9.1, { safe_to_store: false }),
    node("cred:snowflake", "credential", "SNOWFLAKE_PROD_KEY", "critical", 9.3, { safe_to_store: false }),
    node("cred:aws", "credential", "AWS_ROLE_SESSION", "high", 8.1, { safe_to_store: false, risk_context: { crown_jewel: true, data_sensitivity: "secret", source: "synthetic-asset-classification", simulated: true } }),
    node("cred:incident-webhook", "credential", "INCIDENT_WEBHOOK_TOKEN", "high", 7.4, { safe_to_store: false }),
    packageNode("pkg:next", "next", "15.2.2", "npm", ["CVE-2025-29927"]),
    packageNode("pkg:urllib3", "urllib3", "2.2.1", "pypi", ["CVE-2024-37891"]),
    packageNode("pkg:protobuf", "protobuf", "6.31.0", "pypi", ["CVE-2025-4565"]),
    packageNode("pkg:langchain", "langchain", "0.3.21", "pypi"),
    advisoryNode("cve:next", "CVE-2025-29927", { compliance_tags: ["NIST-RA-5"] }),
    advisoryNode("cve:urllib3", "CVE-2024-37891"),
    advisoryNode("cve:protobuf", "CVE-2025-4565"),
    node("dataset:finance-docs", "dataset", "finance-board-rag-index", "high", 8.0, { data_classification: "confidential" }),
    node("model:gpt-prod", "model", "prod-reasoning-model", "medium", 4.8, { provider: "customer-managed" }),
  ];

  const edges = [
    edge("provider:aws-prod", "env:prod-ai", "hosts"),
    edge("env:prod-ai", "cluster:eks-ai", "hosts"),
    edge("cluster:eks-ai", "container:agent-gateway", "hosts"),
    edge("cluster:eks-ai", "container:copilot-portal", "hosts"),
    edge("container:agent-gateway", "policy:gateway-default-deny", "manages"),
    edge("user:contractor", "sa:jit-review", "acted_as"),
    edge("sa:jit-review", "role:prod-admin", "assumes"),
    edge("role:prod-admin", "agent:developer-copilot", "can_access"),
    edge("agent:developer-copilot", "container:copilot-portal", "hosted_on", 1, SAMPLE_CONFIG_EVIDENCE),
    edge("agent:developer-copilot", "server:github", "uses", 1, SAMPLE_CONFIG_EVIDENCE),
    edge("agent:developer-copilot", "server:filesystem", "uses", 1, SAMPLE_CONFIG_EVIDENCE),
    edge("agent:sre-runbook", "server:filesystem", "uses", 1, SAMPLE_CONFIG_EVIDENCE),
    edge("agent:sre-runbook", "server:slack", "uses"),
    edge("agent:finance-rag", "server:snowflake", "uses"),
    edge("agent:finance-rag", "server:slack", "uses"),
    edge("agent:developer-copilot", "agent:sre-runbook", "shares_server", 1, { server: "server:filesystem" }),
    edge("agent:sre-runbook", "agent:finance-rag", "shares_cred", 1, { credential: "INCIDENT_WEBHOOK_TOKEN" }),
    edge("server:github", "tool:repo-write", "provides_tool"),
    edge("server:filesystem", "tool:exec", "provides_tool", 1, SAMPLE_CONFIG_EVIDENCE),
    edge("server:snowflake", "tool:query", "provides_tool"),
    edge("server:slack", "tool:post", "provides_tool"),
    edge("server:github", "cred:github", "exposes_cred"),
    edge("server:snowflake", "cred:snowflake", "exposes_cred"),
    edge("server:filesystem", "cred:aws", "exposes_cred", 1, SAMPLE_CONFIG_EVIDENCE),
    edge("server:slack", "cred:incident-webhook", "exposes_cred"),
    edge("container:copilot-portal", "pkg:next", "depends_on"),
    edge("server:filesystem", "pkg:urllib3", "depends_on"),
    edge("server:snowflake", "pkg:protobuf", "depends_on"),
    edge("server:snowflake", "pkg:langchain", "depends_on"),
    edge("pkg:next", "cve:next", "vulnerable_to", 1.6, { cvss_score: advisory("CVE-2025-29927").cvss_score }),
    edge("pkg:urllib3", "cve:urllib3", "vulnerable_to", 1.4, { cvss_score: advisory("CVE-2024-37891").cvss_score }),
    edge("pkg:protobuf", "cve:protobuf", "vulnerable_to", 1.2, { cvss_score: advisory("CVE-2025-4565").cvss_score }),
    edge("cred:snowflake", "dataset:finance-docs", "can_access"),
    edge("server:snowflake", "dataset:finance-docs", "accessed"),
    edge("agent:finance-rag", "model:gpt-prod", "uses"),
    edge("policy:gateway-default-deny", "tool:exec", "manages"),
  ];
  for (const item of nodes) {
    const assessment = riskFixture.mcp_risk?.[item.id];
    if (assessment) item.attributes.capability_risk = assessment.capability_risk;
  }
  const attackPaths = buildAttackPaths(nodes, edges);
  const stats = {
    total_nodes: nodes.length,
    total_edges: edges.length,
    node_types: nodes.reduce((acc, item) => ({ ...acc, [item.entity_type]: (acc[item.entity_type] ?? 0) + 1 }), {}),
    severity_counts: severityCounts(nodes),
    relationship_types: edges.reduce((acc, item) => ({ ...acc, [item.relationship]: (acc[item.relationship] ?? 0) + 1 }), {}),
    attack_path_count: attackPaths.length,
    // The typed count /v1/graph serves; every derived path is retained, so assessed equals retained.
    attack_paths: { retained_count: attackPaths.length, assessed_count: attackPaths.length, basis: "derived_graph_paths" },
    interaction_risk_count: 0,
    max_attack_path_risk: Math.max(...attackPaths.map((item) => item.composite_risk)),
    highest_interaction_risk: 0,
    analysis_status: {
      attack_path_fusion: {
        status: "complete",
        reason_codes: [],
        limits: { max_nodes: 5000, max_paths: 1000 },
        observed: { nodes: nodes.length, paths: attackPaths.length },
      },
    },
  };

  return {
    scan_id: SCAN_ID,
    tenant_id: "default",
    created_at: CREATED_AT,
    nodes,
    edges,
    attack_paths: attackPaths,
    interaction_risks: [],
    stats,
    pagination: { total: nodes.length, offset: 0, limit: nodes.length, has_more: false },
  };
}

const ATTACK_PATH_SPECS = [
  {
    hops: ["user:contractor", "sa:jit-review", "role:prod-admin", "agent:developer-copilot", "container:copilot-portal", "pkg:next", "cve:next"],
    analysis: { status: "complete" },
    reachability: "confirmed",
    summary: "JIT reviewer identity assumes the admin-equivalent role and reaches the internet-exposed Developer Copilot portal, which runs next@15.2.2 (CVE-2025-29927 middleware authorization bypass).",
  },
  {
    hops: ["agent:sre-runbook", "server:filesystem", "pkg:urllib3", "cve:urllib3"],
    summary: "SRE Runbook Agent reaches a medium urllib3 proxy-header disclosure through filesystem MCP; shell access is not established by this vulnerability.",
  },
  {
    hops: ["agent:finance-rag", "server:snowflake", "cred:snowflake", "dataset:finance-docs"],
    summary: "Finance RAG Agent can query confidential board material through Snowflake MCP and a production key reference.",
  },
];

function buildAttackPaths(nodes, edges) {
  const byId = new Map(nodes.map((item) => [item.id, { ...item, type: item.entity_type }]));
  const graphEdge = (source, target) => edges.find((item) => item.source === source && item.target === target);
  const hopEvidenceFor = (hops) =>
    hops.slice(0, -1).map((source, index) => {
      const target = hops[index + 1];
      const recorded = graphEdge(source, target);
      return {
        source_node_id: source,
        target_node_id: target,
        relationship: recorded?.relationship ?? "related",
        source_snapshot_ids: [SCAN_ID],
        evidence_tier: "static_scan",
        confidence: 1,
        freshness: "fresh",
        runtime_observed_state: "not_observed",
        direction: recorded?.direction ?? "unknown",
        traversable: recorded?.traversable === true,
        complete: true,
        relationship_provenance: recorded ? "recorded" : "unavailable",
        correlation_identity_status: "current",
        truncated: false,
      };
    });
  return ATTACK_PATH_SPECS.map(({ hops, ...rest }) => {
    const target = byId.get(hops[hops.length - 1]);
    const vulnIds = hops.map((id) => byId.get(id)).filter((item) => item.type === "vulnerability").map((item) => item.label);
    return {
      source: hops[0],
      target: target.id,
      hops,
      edges: hops.slice(0, -1).map((source, index) => graphEdge(source, hops[index + 1])?.relationship ?? "related"),
      hop_evidence: hopEvidenceFor(hops),
      ...rest,
      composite_risk: pathRisk(nodes, hops),
      credential_exposure: pathExposure(byId, edges, hops, "exposes_cred", "credential"),
      tool_exposure: pathExposure(byId, edges, hops, "provides_tool", "tool"),
      vuln_ids: vulnIds,
      severity: vulnIds.length ? advisory(vulnIds[0]).severity : target.severity,
    };
  });
}

export function graphScenario() {
  const fixed = advisory("CVE-2025-29927").fixed_version;
  return {
    scenario_id: SCENARIO_ID,
    tenant_id: "default",
    base_scan_id: SCAN_ID,
    revision: 1,
    name: `Upgrade next to ${fixed}`,
    description: `Upgrade the copilot portal to next@${fixed}, which removes the CVE-2025-29927 hop.`,
    assumptions: [`The portal image is rebuilt with next@${fixed} and redeployed.`],
    changes: [],
    created_by: "platform-security",
    created_at: CREATED_AT,
    updated_at: CREATED_AT,
  };
}

export function graphScenarioComparison(graph = buildGraph()) {
  const facts = advisory("CVE-2025-29927");
  const scenario = graphScenario();
  const proposedNode = node(`proposal:${SCENARIO_ID}:next-upgrade`, "package", `next@${facts.fixed_version}`, "none", 0, {
    ecosystem: facts.ecosystem,
    version: facts.fixed_version,
    evidence_state: "proposed",
    observed: false,
    deployed: false,
    scenario_id: SCENARIO_ID,
    scenario_revision: 1,
    assumption: scenario.assumptions[0],
  });
  proposedNode.status = "proposed";
  // The rebuilt portal depends on the fixed release instead of 15.2.2; the advisory stays true of
  // 15.2.2, which is simply no longer deployed. Every derived number below follows from that swap.
  const removedEdge = "container:copilot-portal->pkg:next:depends_on";
  const addedEdge = edge("container:copilot-portal", proposedNode.id, "depends_on", 1, { evidence_state: "proposed" });
  const proposedEdges = [...graph.edges.filter((item) => item.id !== removedEdge), addedEdge];
  const proposedNodes = [...graph.nodes, proposedNode];
  const modeledPaths = graph.attack_paths.filter((item) => hopsAreConnected(proposedEdges, item.hops));
  const touchedPaths = graph.attack_paths.filter((item) => !modeledPaths.includes(item));
  const maxRisk = (paths) => Math.max(0, ...paths.map((item) => item.composite_risk));
  const completeness = (total) => ({ status: "complete", complete: true, sampled: false, truncated: false, returned: total, total });
  return {
    schema: "graph.scenario-comparison.v1",
    available: true,
    base_status: "available",
    stale: false,
    scenario,
    current: {
      scan_id: SCAN_ID,
      node_count: graph.nodes.length,
      edge_count: graph.edges.length,
      completeness: completeness(graph.nodes.length),
    },
    proposed: {
      scan_id: SCAN_ID,
      node_count: proposedNodes.length,
      edge_count: proposedEdges.length,
      modeled: true,
      nodes: proposedNodes,
      edges: proposedEdges,
      completeness: completeness(proposedNodes.length),
    },
    difference: {
      nodes_added: [proposedNode.id],
      nodes_removed: [],
      nodes_changed: ["container:copilot-portal"],
      edges_added: [addedEdge.id],
      edges_removed: [removedEdge],
      touched_observed_path_count: touchedPaths.length,
      touched_observed_path_ids: touchedPaths.map((item) => `${item.source}->${item.target}`),
    },
    comparison: {
      observed_path_count: graph.attack_paths.length,
      modeled_path_count: modeledPaths.length,
      path_delta: modeledPaths.length - graph.attack_paths.length,
      risk_delta: Math.round((maxRisk(modeledPaths) - maxRisk(graph.attack_paths)) * 10) / 10,
    },
    completeness: completeness(proposedNodes.length),
  };
}

// Context-graph lateral paths keep the backend 0-10 scale and formula
// (src/agent_bom/context_graph.py): worst advisory + 0.3 per credential + 0.2 per execute tool.
const CONTEXT_SEVERITY_SCORE = { critical: 8.0, high: 6.0, medium: 4.0, low: 2.0 };

export function contextLateralRisk(contextNodes, contextEdges, hops) {
  const byId = new Map(contextNodes.map((item) => [item.id, item]));
  const creds = new Set();
  const execTools = new Set();
  let worst = 0;
  const visit = (item) => {
    if (!item) return;
    if (item.kind === "credential") creds.add(item.id);
    if (item.kind === "tool" && item.metadata.capabilities?.includes("execute")) execTools.add(item.id);
    if (item.kind === "vulnerability") worst = Math.max(worst, CONTEXT_SEVERITY_SCORE[item.metadata.severity] ?? 0);
  };
  for (const id of hops) {
    const item = byId.get(id);
    visit(item);
    if (item?.kind !== "server") continue;
    for (const link of contextEdges.filter((candidate) => candidate.source === id)) visit(byId.get(link.target));
  }
  return Math.round(Math.min(10, worst + creds.size * 0.3 + execTools.size * 0.2) * 10) / 10;
}

export function contextGraph() {
  const cveNode = (id, cveId) => ({ id, kind: "vulnerability", label: cveId, metadata: { severity: advisory(cveId).severity, cvss_score: advisory(cveId).cvss_score } });
  const nodes = [
    { id: "agent:developer-copilot", kind: "agent", label: "Developer Copilot", metadata: { severity: "critical", agent_type: "ide" } },
    { id: "agent:sre-runbook", kind: "agent", label: "SRE Runbook Agent", metadata: { severity: "high", agent_type: "runbook" } },
    { id: "agent:finance-rag", kind: "agent", label: "Finance RAG Agent", metadata: { severity: "high", agent_type: "rag" } },
    { id: "iam:jit-review", kind: "iam_role", entity_type: "service_account", label: "jit-prod-reviewer", metadata: { severity: "high" } },
    { id: "server:github", kind: "server", label: "github-enterprise MCP", metadata: { severity: "critical" } },
    { id: "server:filesystem", kind: "server", label: "filesystem MCP", metadata: { severity: "critical" } },
    { id: "server:snowflake", kind: "server", label: "snowflake-rag MCP", metadata: { severity: "high" } },
    { id: "cred:github", kind: "credential", label: "GITHUB_ENTERPRISE_TOKEN", metadata: { severity: "critical" } },
    { id: "cred:snowflake", kind: "credential", label: "SNOWFLAKE_PROD_KEY", metadata: { severity: "critical" } },
    { id: "cred:aws", kind: "credential", label: "AWS_ROLE_SESSION", metadata: { severity: "high" } },
    { id: "tool:repo-write", kind: "tool", label: "create_pull_request", metadata: { severity: "high" } },
    { id: "tool:exec", kind: "tool", label: "execute_command", metadata: { severity: "critical", capabilities: ["execute"] } },
    { id: "tool:query", kind: "tool", label: "run_sql", metadata: { severity: "high" } },
    cveNode("cve:urllib3", "CVE-2024-37891"),
    cveNode("cve:protobuf", "CVE-2025-4565"),
  ];
  const link = (source, target, kind, metadata = {}) => ({ source, target, kind, relationship: kind, weight: 1, metadata });
  const packageRef = (cveId) => `${advisory(cveId).package}@${advisory(cveId).version}`;
  const edges = [
    link("iam:jit-review", "agent:developer-copilot", "member_of"),
    link("agent:developer-copilot", "server:github", "uses", { effective_reach_score: 9.4 }),
    link("agent:developer-copilot", "server:filesystem", "uses", { effective_reach_score: 9.1 }),
    link("server:github", "cred:github", "exposes_cred", { effective_reach_score: 9.2 }),
    link("server:github", "tool:repo-write", "provides_tool", { effective_reach_score: 8.3 }),
    link("server:filesystem", "tool:exec", "provides_tool", { effective_reach_score: 9.5 }),
    link("server:filesystem", "cred:aws", "exposes_cred", { effective_reach_score: 8.1 }),
    link("server:filesystem", "cve:urllib3", "vulnerable_to", { effective_reach_score: advisory("CVE-2024-37891").cvss_score, package: packageRef("CVE-2024-37891") }),
    link("agent:sre-runbook", "server:filesystem", "uses", { effective_reach_score: 8.5 }),
    link("agent:finance-rag", "server:snowflake", "uses", { effective_reach_score: 8.4 }),
    link("server:snowflake", "cred:snowflake", "exposes_cred", { effective_reach_score: 9.0 }),
    link("server:snowflake", "tool:query", "provides_tool", { effective_reach_score: 8.4 }),
    link("server:snowflake", "cve:protobuf", "vulnerable_to", { effective_reach_score: advisory("CVE-2025-4565").cvss_score, package: packageRef("CVE-2025-4565") }),
    link("agent:developer-copilot", "agent:sre-runbook", "shares_server", { server: "server:filesystem" }),
    link("agent:sre-runbook", "agent:finance-rag", "shares_credential", { credential: "INCIDENT_WEBHOOK_TOKEN" }),
  ];
  const byId = new Map(nodes.map((item) => [item.id, { ...item, type: item.kind }]));
  const links = edges.map((item) => ({ ...item, relationship: item.kind }));
  const lateral = (hops, summary) => ({
    source: hops[0],
    target: hops[hops.length - 1],
    hops,
    edges: [],
    composite_risk: contextLateralRisk(nodes, edges, hops),
    summary,
    credential_exposure: pathExposure(byId, links, hops, "exposes_cred", "credential"),
    tool_exposure: pathExposure(byId, links, hops, "provides_tool", "tool"),
    vuln_ids: pathExposure(byId, links, hops, "vulnerable_to", "vulnerability"),
  });
  const lateralPaths = [
    lateral(["agent:developer-copilot", "server:filesystem", "tool:exec"], "Configured filesystem MCP advertises an execution tool and ships a medium urllib3 advisory; invocation is not established."),
    lateral(["agent:developer-copilot", "server:github", "tool:repo-write"], "Configured GitHub MCP exposes a repo-write tool and an enterprise token reference; tool execution is not established."),
  ].sort((left, right) => right.composite_risk - left.composite_risk);
  const interactionRisks = [
    {
      pattern: "shared_server_lateral_path",
      agents: ["Developer Copilot", "SRE Runbook Agent"],
      risk_score: 8.9,
      description: "Two high-trust agents share filesystem MCP command tooling; scope narrowing is the lowest-cost choke point.",
      owasp_agentic_tag: "ASI07",
    },
    {
      pattern: "credential_reuse",
      agents: ["SRE Runbook Agent", "Finance RAG Agent"],
      risk_score: 8.2,
      description: "Incident workflow and RAG workflow share the INCIDENT_WEBHOOK_TOKEN credential reference.",
      owasp_agentic_tag: "ASI07",
    },
  ];
  return {
    nodes,
    edges,
    lateral_paths: lateralPaths,
    interaction_risks: interactionRisks,
    stats: {
      total_nodes: nodes.length,
      total_edges: edges.length,
      agent_count: nodes.filter((item) => item.kind === "agent").length,
      shared_server_count: edges.filter((item) => item.kind === "shares_server").length,
      shared_credential_count: edges.filter((item) => item.kind === "shares_credential").length,
      lateral_path_count: lateralPaths.length,
      max_lateral_depth: Math.max(...lateralPaths.map((item) => item.hops.length - 1)),
      highest_path_risk: Math.max(...lateralPaths.map((item) => item.composite_risk)),
      interaction_risk_count: interactionRisks.length,
    },
  };
}

export function vuln(id) {
  const item = advisory(id);
  return {
    id, severity: item.severity, summary: item.summary,
    description: `${item.summary}. Simulated exposure condition: ${item.precondition}`,
    references: [item.reference], advisory_sources: ["github-advisory-database"],
    cvss_score: item.cvss_score, cvss_vector: item.cvss_vector,
    fixed_version: item.fixed_version,
  };
}

export const DEMO_AGENT_SPECS = [
  { name: "data-pipeline-agent", agent_type: "etl", owner: "data-platform", environment: "prod-analytics", server: "warehouse MCP", pkg: "pyyaml", version: "5.3", ecosystem: "pypi", cve: ["CVE-2020-14343"] },
  { name: "customer-support-bot", agent_type: "support", owner: "cx-ops", environment: "prod-support", server: "zendesk MCP", pkg: "requests", version: "2.30.0", ecosystem: "pypi", cve: ["CVE-2023-32681"] },
  { name: "legal-review-agent", agent_type: "review", owner: "legal", environment: "prod-legal", server: "docusign MCP", pkg: "cryptography", version: "41.0.7", ecosystem: "pypi", cve: ["CVE-2023-50782"] },
  { name: "hr-onboarding-agent", agent_type: "hr", owner: "people-ops", environment: "prod-hr", server: "workday MCP", pkg: "pillow", version: "11.1.0", ecosystem: "pypi", cve: null },
  { name: "marketing-copilot", agent_type: "marketing", owner: "growth", environment: "staging", server: "hubspot MCP", pkg: "axios", version: "1.4.0", ecosystem: "npm", cve: ["CVE-2023-45857"] },
  { name: "incident-commander", agent_type: "runbook", owner: "sre", environment: "prod-ai-control-plane", server: "pagerduty MCP", pkg: "aiohttp", version: "3.9.1", ecosystem: "pypi", cve: ["CVE-2024-23334"] },
  { name: "platform-ops-agent", agent_type: "ops", owner: "platform", environment: "prod-ai-control-plane", server: "kubernetes MCP", pkg: "urllib3", version: "2.0.5", ecosystem: "pypi", cve: ["CVE-2023-43804"] },
  { name: "ml-training-agent", agent_type: "ml", owner: "ml-platform", environment: "prod-ml", server: "wandb MCP", pkg: "torch", version: "2.5.1", ecosystem: "pypi", cve: ["CVE-2025-32434"] },
  { name: "code-review-bot", agent_type: "ide", owner: "engineering", environment: "prod-ai-control-plane", server: "gitlab MCP", pkg: "eslint", version: "9.21.0", ecosystem: "npm", cve: null },
  { name: "compliance-auditor", agent_type: "audit", owner: "grc", environment: "prod-grc", server: "grc MCP", pkg: "idna", version: "3.6", ecosystem: "pypi", cve: ["CVE-2024-3651"] },
  { name: "vendor-risk-agent", agent_type: "risk", owner: "security", environment: "staging", server: "vendor MCP", pkg: "starlette", version: "0.39.2", ecosystem: "pypi", cve: ["CVE-2024-47874"] },
  { name: "research-assistant", agent_type: "rag", owner: "research", environment: "staging", server: "arxiv MCP", pkg: "pillow", version: "9.2.0", ecosystem: "pypi", cve: ["CVE-2022-45199"] },
  { name: "sales-enablement-bot", agent_type: "sales", owner: "revenue", environment: "prod-sales", server: "salesforce MCP", pkg: "simple-salesforce", version: "1.12.6", ecosystem: "pypi", cve: null },
  { name: "devops-release-agent", agent_type: "release", owner: "devops", environment: "prod-ai-control-plane", server: "argocd MCP", pkg: "jinja2", version: "3.1.4", ecosystem: "pypi", cve: ["CVE-2024-56326"] },
  { name: "shadow-copilot", agent_type: "shadow", owner: "unknown", environment: "unmanaged", server: "openai MCP", pkg: "langchain", version: "0.0.150", ecosystem: "pypi", cve: ["CVE-2023-36258"] },
];

export function demoScanAgent(spec) {
  const vulnerabilities = spec.cve
    ? [vuln(spec.cve[0])]
    : [];
  return {
    name: spec.name,
    agent_type: spec.agent_type,
    owner: spec.owner,
    environment: spec.environment,
    tags: ["simulated", spec.environment.startsWith("prod") ? "prod" : "staging"],
    mcp_servers: [
      {
        name: spec.server,
        transport: "sse",
        config_path: `/workspace/${spec.name}/mcp.json`,
        has_credentials: spec.name !== "code-review-bot",
        credential_env_vars: spec.name !== "code-review-bot" ? [`${spec.name.toUpperCase().replace(/-/g, "_")}_TOKEN`] : [],
        tools: [{ name: "query" }, { name: "read_context" }],
        packages: [
          {
            name: spec.pkg,
            version: spec.version,
            ecosystem: spec.ecosystem,
            purl: `pkg:${spec.ecosystem}/${spec.pkg}@${spec.version}`,
            vulnerabilities,
          },
        ],
      },
    ],
  };
}

const CORE_BLAST_SPECS = [
  { id: "CVE-2025-29927", agents: ["developer-copilot"], servers: [], credentials: [], tools: [] },
  { id: "CVE-2024-37891", agents: ["sre-runbook-agent", "developer-copilot"], servers: ["filesystem MCP"], credentials: ["AWS_ROLE_SESSION"], tools: ["execute_command"] },
  { id: "CVE-2025-4565", agents: ["finance-rag-agent"], servers: ["snowflake-rag MCP"], credentials: ["SNOWFLAKE_PROD_KEY"], tools: ["run_sql"] },
];

// Every severity, score, package and fix comes from the verified advisory facts.
export function buildBlastRadius() {
  const specs = [...CORE_BLAST_SPECS];
  const seenIds = new Set(specs.map((item) => item.id));
  for (const spec of DEMO_AGENT_SPECS) {
    if (!spec.cve || seenIds.has(spec.cve[0])) continue;
    seenIds.add(spec.cve[0]);
    specs.push({
      id: spec.cve[0],
      agents: [spec.name],
      servers: [spec.server],
      credentials: [`${spec.name.toUpperCase().replace(/-/g, "_")}_TOKEN`],
      tools: ["query"],
    });
  }
  return specs.map((spec) => {
    const facts = advisory(spec.id);
    const contained = ["availability", "client-side"].includes(facts.impact_category);
    return {
      vulnerability_id: spec.id,
      severity: facts.severity,
      package: `${facts.package}@${facts.version}`,
      ecosystem: facts.ecosystem,
      affected_agents: spec.agents,
      affected_servers: spec.servers,
      exposed_credentials: contained ? [] : spec.credentials,
      reachable_tools: contained ? [] : spec.tools,
      blast_score: Math.round(facts.cvss_score * 10),
      risk_score: facts.cvss_score,
      cvss_score: facts.cvss_score,
      cvss_vector: facts.cvss_vector,
      fixed_version: facts.fixed_version,
      impact_category: facts.impact_category,
      attack_vector_summary: `Simulated exposure condition: ${facts.precondition}`,
    };
  });
}
