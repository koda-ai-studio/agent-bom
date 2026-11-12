import type { AttackPath, UnifiedEdge, UnifiedGraphData, UnifiedNode } from "@/lib/graph-schema";

export function node(id: string, entity_type: string, label: string, attributes: Record<string, unknown> = {}, severity = "none"): UnifiedNode {
  return {
    id, entity_type, label, severity, risk_score: 0, status: "active",
    first_seen: "2026-11-01T00:00:00Z", last_seen: "2026-11-01T00:00:00Z",
    attributes, compliance_tags: [], data_sources: [], dimensions: {},
  } as unknown as UnifiedNode;
}

export function edge(source: string, target: string, relationship: string, tier: string | null = "static_scan"): UnifiedEdge {
  return {
    id: `${source}->${target}:${relationship}`, source, target, relationship, direction: "directed",
    weight: 1, traversable: true, first_seen: "2026-11-01T00:00:00Z", last_seen: "2026-11-01T00:00:00Z",
    evidence: tier ? { tier, source: "test" } : {},
  } as unknown as UnifiedEdge;
}

export function path(hops: string[], relationships: string[], composite_risk = 9): AttackPath {
  return { source: hops[0]!, target: hops.at(-1)!, hops, edges: relationships, composite_risk, summary: "", credential_exposure: [], tool_exposure: [], vuln_ids: [] } as unknown as AttackPath;
}

const SELECTED_HOPS = ["user:contractor", "sa:jit", "role:admin", "agent:copilot", "server:github", "pkg:next", "cve:next"];

/** The demo's headline path plus a second path that shares a real edge with it. */
export function branchingFixture(): { graph: UnifiedGraphData; selected: AttackPath } {
  const nodes = [
    node("user:contractor", "user", "contractor-reviewer"),
    node("sa:jit", "service_account", "jit-prod-reviewer"),
    node("role:admin", "role", "prod-ai-admin", { is_admin: true }),
    node("agent:copilot", "agent", "developer-copilot"),
    node("server:github", "server", "github-enterprise MCP", { internet_exposed: true }),
    node("pkg:next", "package", "next@15.2.2"),
    node("cve:next", "vulnerability", "CVE-2025-29927", {}, "critical"),
    node("cve:next-2", "vulnerability", "CVE-2025-00001", {}, "medium"),
    node("server:filesystem", "server", "filesystem MCP", { internet_exposed: "unknown" }),
    node("pkg:urllib3", "package", "urllib3@2.2.1"),
    node("cve:urllib3", "vulnerability", "CVE-2024-37891", {}, "high"),
    node("agent:sre", "agent", "sre-runbook-agent"),
    node("dataset:finance", "dataset", "finance-board-index", { data_sensitivity: "pii" }),
    node("dataset:clean", "dataset", "public-docs", { data_sensitivity: "none" }),
    node("agent:unrelated", "agent", "unrelated-agent"),
  ];
  const edges = [
    edge("user:contractor", "sa:jit", "acted_as"),
    edge("sa:jit", "role:admin", "assumes"),
    edge("role:admin", "agent:copilot", "can_access", "modeled_infrastructure"),
    edge("agent:copilot", "server:github", "uses"),
    edge("server:github", "pkg:next", "depends_on", null),
    edge("pkg:next", "cve:next", "vulnerable_to"),
    edge("pkg:next", "cve:next-2", "vulnerable_to"),
    edge("agent:copilot", "server:filesystem", "uses", "modeled_infrastructure"),
    edge("agent:sre", "server:filesystem", "uses"),
    edge("server:filesystem", "pkg:urllib3", "depends_on"),
    edge("pkg:urllib3", "cve:urllib3", "vulnerable_to"),
    edge("server:filesystem", "dataset:finance", "accessed"),
    edge("agent:unrelated", "dataset:clean", "accessed"),
  ];
  const selected = path(SELECTED_HOPS, ["acted_as", "assumes", "can_access", "uses", "depends_on", "vulnerable_to"]);
  const other = path(["agent:sre", "server:filesystem", "pkg:urllib3", "cve:urllib3"], ["uses", "depends_on", "vulnerable_to"], 8);
  const data = path(["agent:sre", "server:filesystem", "dataset:finance"], ["uses", "accessed"], 7);
  const unrelated = path(["agent:unrelated", "dataset:clean"], ["accessed"], 3);
  return {
    selected,
    graph: { scan_id: "scan-1", tenant_id: "t", created_at: "", nodes, edges, attack_paths: [selected, other, data, unrelated], interaction_risks: [], stats: {} } as unknown as UnifiedGraphData,
  };
}

/** One shared server with `count` sibling endpoints, each on its own recorded path. */
export function fanOutFixture(count: number): { graph: UnifiedGraphData; selected: AttackPath } {
  const nodes = [
    node("agent:a", "agent", "agent-a"),
    node("server:s", "server", "shared-server"),
    node("pkg:p", "package", "pkg@1"),
    node("cve:p", "vulnerability", "CVE-1", {}, "high"),
  ];
  const edges = [edge("agent:a", "server:s", "uses"), edge("server:s", "pkg:p", "depends_on"), edge("pkg:p", "cve:p", "vulnerable_to")];
  const paths = [path(["agent:a", "server:s", "pkg:p", "cve:p"], ["uses", "depends_on", "vulnerable_to"])];
  for (let index = 0; index < count; index += 1) {
    const id = `endpoint:${index}`;
    nodes.push(node(id, "cloud_resource", `endpoint-${index}`));
    edges.push(edge("server:s", id, "exposes", "static_scan"));
    paths.push(path(["agent:a", "server:s", id], ["uses", "exposes"], 5));
  }
  return {
    selected: paths[0]!,
    graph: { scan_id: "scan-1", tenant_id: "t", created_at: "", nodes, edges, attack_paths: paths, interaction_risks: [], stats: {} } as unknown as UnifiedGraphData,
  };
}
