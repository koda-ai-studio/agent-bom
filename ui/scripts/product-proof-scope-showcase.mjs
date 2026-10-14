// Explicitly synthetic estates for the README scope previews (environment,
// repository, cloud). Every identifier is fictional. Advisory facts come from
// the verified gallery catalog; attack paths, severities and analysis counts
// are derived from the fixture's own edges below, never written by hand.

export const SCOPE_SHOWCASE_PRESETS = [
  ["cloud", "Cloud estate"],
  ["repository", "Repository"],
  ["environment", "Environment"],
];

const FINDING_TYPES = new Set(["vulnerability", "misconfiguration"]);
// Mirrors graph/attack_path_fusion.py traversal plus agent tool use.
const TRAVERSABLE = new Set([
  "uses", "depends_on", "contains", "vulnerable_to", "exploitable_via", "exposes_cred", "reaches_tool",
  "provides_tool", "authenticates_as", "assumes", "inherits", "can_access", "has_permission", "exposed_to",
  "stores", "accessed", "serves_model",
]);
const SEVERITY_RANK = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };
const MAX_PATH_DEPTH = 8;

function definitions({ cve, kevCve }) {
  return {
    environment: {
      nodes: [
        ["env:prod-ai", "environment", "Production AI", { environment: "production", cloud_provider: "aws" }],
        ["agent:intake", "agent", "document-intake-agent", { agent_type: "workflow" }],
        ["agent:triage", "agent", "support-triage-agent", { agent_type: "assistant" }],
        ["container:serving", "container", "model-serving", { environment: "production", internet_exposed: true }],
        ["server:docs", "server", "document-tools MCP", { transport: "stdio" }],
        ["server:tickets", "server", "ticketing MCP", { transport: "sse" }],
        ["pkg:torch", "package", "torch@2.5.1", { ecosystem: "pypi", version: "2.5.1", purl: "pkg:pypi/torch@2.5.1" }],
        ["pkg:pillow", "package", "pillow@9.0.0", { ecosystem: "pypi", version: "9.0.0", purl: "pkg:pypi/pillow@9.0.0" }],
        ["cred:tickets", "credential_ref", "TICKETING_API_KEY", { safe_to_store: false }],
        cve("cve:torch", "CVE-2025-32434"),
        kevCve("cve:webp"),
        ["data:tickets", "data_store", "customer-ticket-archive", { environment: "production", cloud_provider: "aws", data_sensitivity: "pii" }],
      ],
      edges: [
        ["env:prod-ai", "container:serving", "hosts"], ["env:prod-ai", "agent:intake", "contains"],
        ["env:prod-ai", "agent:triage", "contains"], ["agent:intake", "server:docs", "uses"],
        ["agent:triage", "server:tickets", "uses"], ["container:serving", "pkg:torch", "contains"],
        ["server:docs", "pkg:pillow", "depends_on"], ["server:tickets", "cred:tickets", "exposes_cred"],
        ["pkg:torch", "cve:torch", "vulnerable_to"], ["pkg:pillow", "cve:webp", "vulnerable_to"],
        ["cred:tickets", "data:tickets", "can_access"],
      ],
    },
    repository: {
      nodes: [
        ["repo:payments", "directory", "payments-service/", { path: "payments-service/" }],
        ["finding:ci-token", "misconfiguration", "Workflow uses a long-lived registry token", { severity_source: "synthetic-policy" }],
        ["source:server", "source_file", "src/server.ts", { language: "TypeScript" }],
        ["config:values", "config_file", "deploy/values.yaml"],
        ["ci:publish", "ci_job", "build-and-publish"],
        ["pkg:next", "package", "next@15.2.2", { ecosystem: "npm", version: "15.2.2", purl: "pkg:npm/next@15.2.2" }],
        ["container:api", "container", "payments-api", { internet_exposed: true, environment: "production" }],
        ["cred:db", "credential_ref", "PAYMENTS_DB_PASSWORD", { safe_to_store: false }],
        cve("cve:next", "CVE-2025-29927"),
        ["pkg:cryptography", "package", "cryptography@41.0.7", { ecosystem: "pypi", version: "41.0.7", purl: "pkg:pypi/cryptography@41.0.7" }],
        cve("cve:cryptography", "CVE-2023-50782"),
      ],
      edges: [
        ["repo:payments", "source:server", "contains"], ["repo:payments", "config:values", "contains"],
        ["repo:payments", "ci:publish", "contains"], ["finding:ci-token", "ci:publish", "affects"],
        ["source:server", "pkg:next", "imports"], ["ci:publish", "container:api", "configures"],
        ["config:values", "cred:db", "exposes_cred"], ["pkg:next", "cve:next", "vulnerable_to"],
        ["container:api", "pkg:cryptography", "contains"], ["pkg:cryptography", "cve:cryptography", "vulnerable_to"],
      ],
    },
    cloud: {
      nodes: [
        ["account:prod", "account", "prod-workloads", { cloud_provider: "aws", account_id: "123456789012" }],
        ["finding:waf", "misconfiguration", "Public API stage has no WAF association", { severity_source: "synthetic-policy" }],
        ["gateway:public", "api_gateway", "public-api-gateway", { cloud_provider: "aws", environment: "production", internet_exposed: true }],
        ["cluster:payments", "cluster", "payments-eks", { cloud_provider: "aws", environment: "production" }],
        ["container:checkout", "container", "checkout-api", { environment: "production" }],
        ["container:ledger", "container", "ledger-worker", { environment: "staging" }],
        ["pkg:next", "package", "next@15.2.2", { ecosystem: "npm", version: "15.2.2", purl: "pkg:npm/next@15.2.2" }],
        ["pkg:urllib3", "package", "urllib3@2.0.5", { ecosystem: "pypi", version: "2.0.5", purl: "pkg:pypi/urllib3@2.0.5" }],
        ["role:checkout", "role", "checkout-runtime-role", { cloud_provider: "aws" }],
        cve("cve:next", "CVE-2025-29927"),
        cve("cve:urllib3", "CVE-2023-43804"),
        ["data:pii", "data_store", "customer-pii-bucket", { cloud_provider: "aws", environment: "production", service: "S3", data_sensitivity: "pii" }],
      ],
      edges: [
        ["account:prod", "gateway:public", "contains"], ["account:prod", "cluster:payments", "contains"],
        ["finding:waf", "gateway:public", "affects"], ["gateway:public", "container:checkout", "exposed_to"],
        ["cluster:payments", "container:checkout", "hosts"], ["cluster:payments", "container:ledger", "hosts"],
        ["container:checkout", "pkg:next", "contains"], ["container:ledger", "pkg:urllib3", "contains"],
        ["container:checkout", "role:checkout", "authenticates_as"], ["role:checkout", "data:pii", "has_permission"],
        ["pkg:next", "cve:next", "vulnerable_to"], ["pkg:urllib3", "cve:urllib3", "vulnerable_to"],
      ],
    },
  };
}

function isEntry(node) {
  return node.entity_type === "agent" || node.attributes.internet_exposed === true;
}

function isTarget(node) {
  return FINDING_TYPES.has(node.entity_type)
    || (node.entity_type === "data_store" && Boolean(node.attributes.data_sensitivity));
}

/** Shortest traversable path from every entry to every reachable finding or sensitive store. */
export function deriveAttackPaths(nodes, edges, scanId) {
  const byId = new Map(nodes.map((item) => [item.id, item]));
  const outgoing = new Map();
  for (const item of edges) {
    if (!item.traversable || !TRAVERSABLE.has(item.relationship)) continue;
    outgoing.set(item.source, [...(outgoing.get(item.source) ?? []), item]);
  }
  const paths = [];
  for (const entry of nodes.filter(isEntry)) {
    const previous = new Map([[entry.id, null]]);
    let frontier = [entry.id];
    for (let depth = 0; depth < MAX_PATH_DEPTH && frontier.length; depth += 1) {
      const next = [];
      for (const id of frontier) {
        for (const item of outgoing.get(id) ?? []) {
          if (previous.has(item.target)) continue;
          previous.set(item.target, item);
          next.push(item.target);
        }
      }
      frontier = next;
    }
    for (const [id] of previous) {
      const target = byId.get(id);
      if (id === entry.id || !isTarget(target)) continue;
      const hopEdges = [];
      for (let cursor = previous.get(id); cursor; cursor = previous.get(cursor.source)) hopEdges.unshift(cursor);
      const hops = [entry.id, ...hopEdges.map((item) => item.target)];
      const onPath = hops.map((hop) => byId.get(hop));
      paths.push({
        source: entry.id,
        target: id,
        hops,
        edges: hopEdges.map((item) => item.relationship),
        analysis: { status: "complete" },
        hop_evidence: hopEdges.map((item) => ({
          source_node_id: item.source, target_node_id: item.target, relationship: item.relationship,
          source_snapshot_ids: [scanId], evidence_tier: "modeled_infrastructure", confidence: 1,
          freshness: "fresh", runtime_observed_state: "not_observed", direction: item.direction,
          traversable: true, complete: true, relationship_provenance: "recorded",
          correlation_identity_status: "current", truncated: false,
        })),
        composite_risk: Math.max(...onPath.map((item) => item.risk_score)),
        reachability: "modeled",
        summary: `${entry.label} reaches ${target.label} through ${hopEdges.length} recorded hop${hopEdges.length === 1 ? "" : "s"}.`,
        credential_exposure: onPath.filter((item) => item.entity_type === "credential_ref").map((item) => item.label),
        tool_exposure: onPath.filter((item) => item.entity_type === "tool").map((item) => item.label),
        vuln_ids: onPath.filter((item) => item.entity_type === "vulnerability").map((item) => item.label),
      });
    }
  }
  return paths.sort((left, right) => right.composite_risk - left.composite_risk || left.hops.length - right.hops.length);
}

/** Highest finding severity reachable from each node over traversable edges. */
function propagateSeverity(nodes, edges) {
  const byId = new Map(nodes.map((item) => [item.id, item]));
  const outgoing = new Map();
  for (const item of edges) {
    if (TRAVERSABLE.has(item.relationship)) outgoing.set(item.source, [...(outgoing.get(item.source) ?? []), item.target]);
  }
  for (const start of nodes) {
    if (FINDING_TYPES.has(start.entity_type)) continue;
    const seen = new Set([start.id]);
    let frontier = [start.id];
    let worst = null;
    while (frontier.length) {
      const next = [];
      for (const id of frontier) for (const target of outgoing.get(id) ?? []) {
        if (seen.has(target)) continue;
        seen.add(target);
        next.push(target);
        const reached = byId.get(target);
        if (FINDING_TYPES.has(reached.entity_type) && (!worst || reached.risk_score > worst.risk_score)) worst = reached;
      }
      frontier = next;
    }
    if (!worst) continue;
    start.severity = worst.severity;
    start.severity_id = worst.severity_id;
    start.risk_score = worst.risk_score;
    start.risk_assessment = { status: "assessed", basis: "max_reachable_finding_risk", scope: "synthetic_fixture_traversal" };
  }
}

export function buildScopeShowcase(kind, { node, edge, base, advisory, referenceCve }) {
  const cve = (id, advisoryId) => {
    const facts = advisory(advisoryId);
    return [id, "vulnerability", advisoryId, { ...facts, simulated: true }, facts.severity, facts.cvss_score];
  };
  const kevCve = (id) => [id, "vulnerability", referenceCve.label, {
    canonical_id: referenceCve.attributes.canonical_id, is_kev: referenceCve.attributes.is_kev === true, simulated: true,
  }, referenceCve.severity, referenceCve.risk_score];
  const fixture = definitions({ cve, kevCve })[kind];
  if (!fixture) throw new Error(`Unknown scope showcase: ${kind}`);
  const nodes = fixture.nodes.map(([id, type, label, attributes = {}, severity, riskScore]) => {
    const findingSeverity = severity ?? (type === "misconfiguration" ? "medium" : "none");
    const created = node(id, type, label, findingSeverity, riskScore ?? (type === "misconfiguration" ? 5.3 : 0),
      { ...attributes, simulated: true, data_sources: ["synthetic-scope-fixture"] });
    const dimensions = {};
    if (attributes.environment) dimensions.environment = String(attributes.environment);
    if (attributes.cloud_provider) dimensions.cloud_provider = String(attributes.cloud_provider);
    if (attributes.ecosystem) dimensions.ecosystem = String(attributes.ecosystem);
    return { ...created, dimensions };
  });
  const edges = fixture.edges.map(([source, target, relation]) => edge(source, target, relation, 1,
    { evidence_tier: "modeled_infrastructure", modeled: true, source_kind: "synthetic-scope-fixture" }));
  propagateSeverity(nodes, edges);
  const attackPaths = deriveAttackPaths(nodes, edges, base.scan_id);
  const count = (key) => nodes.reduce((acc, item) => ({ ...acc, [item[key]]: (acc[item[key]] ?? 0) + 1 }), {});
  const findings = nodes.filter((item) => FINDING_TYPES.has(item.entity_type));
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const item of findings) if (item.severity in severityCounts) severityCounts[item.severity] += 1;
  return {
    ...base, nodes, edges, attack_paths: attackPaths, interaction_risks: [],
    stats: {
      total_nodes: nodes.length, total_edges: edges.length, node_types: count("entity_type"),
      severity_counts: severityCounts,
      relationship_types: edges.reduce((acc, item) => ({ ...acc, [item.relationship]: (acc[item.relationship] ?? 0) + 1 }), {}),
      attack_path_count: attackPaths.length, interaction_risk_count: 0,
      max_attack_path_risk: attackPaths[0]?.composite_risk ?? 0,
      analysis_status: {
        attack_path_fusion: {
          status: "complete", reason_codes: [],
          limits: { max_depth: MAX_PATH_DEPTH, max_nodes: 5000, max_paths: 1000 },
          observed: { nodes: nodes.length, paths: attackPaths.length },
        },
      },
    },
    pagination: { total: nodes.length, offset: 0, limit: nodes.length, has_more: false },
  };
}

/** Fail capture when a showcase drifts from its advisory catalog or edges. */
export function checkScopeShowcase(fixture, advisory, referenceCve) {
  const byId = new Map(fixture.nodes.map((item) => [item.id, item]));
  for (const item of fixture.nodes.filter((entry) => entry.entity_type === "vulnerability")) {
    if (item.label === referenceCve.label) continue;
    const facts = advisory(item.label);
    const pkg = fixture.edges.find((entry) => entry.target === item.id && entry.relationship === "vulnerable_to");
    const pkgNode = pkg && byId.get(pkg.source);
    if (item.severity !== facts.severity || item.risk_score !== facts.cvss_score
      || pkgNode?.label !== `${facts.package}@${facts.version}` || pkgNode.attributes.ecosystem !== facts.ecosystem) {
      throw new Error(`Scope showcase advisory disagrees with verified fixture: ${item.label}`);
    }
  }
  const links = new Set(fixture.edges.map((entry) => `${entry.source}→${entry.target}`));
  for (const item of fixture.attack_paths) {
    if (item.hops.slice(1).some((hop, index) => !links.has(`${item.hops[index]}→${hop}`))) {
      throw new Error("Scope showcase path contains an unrecorded relationship");
    }
  }
  if (fixture.attack_paths.length === 0 || !fixture.nodes.some((entry) => FINDING_TYPES.has(entry.entity_type))) {
    throw new Error("Scope showcase must carry findings and at least one derived path");
  }
  if (SEVERITY_RANK[fixture.nodes.find((entry) => entry.entity_type === "vulnerability")?.severity] === undefined) {
    throw new Error("Scope showcase vulnerability severity is not recognised");
  }
}
