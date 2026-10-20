import { buildGraphInvestigationHref } from "@/lib/attack-paths";

type GraphLike = { nodes: Array<{ id: string; entity_type: string; label: string }> };

function agentNode(graph: GraphLike | undefined) {
  return graph?.nodes.find((node) => node.entity_type === "agent");
}

/** The agent's display name: its graph node label, else the requested name (which may be a raw id). */
export function lifecycleAgentLabel(graph: GraphLike | undefined, requested: string): string {
  return agentNode(graph)?.label || requested;
}

/** Lineage rooted at this agent, keeping the agent scope. */
export function agentLineageHref(graph: GraphLike | undefined, requested: string): string {
  const node = agentNode(graph);
  const name = node?.label || requested;
  // The lifecycle view keys agents by config; the estate graph keys them by name.
  return buildGraphInvestigationHref({ rootId: `agent:${name}`, rootLabel: name, agentName: name });
}

/**
 * A blast-radius CVE opened on this agent's own path: the agent's graph node
 * plus the occurrence's advisory, which the attack-path focus resolves to the
 * paths through that agent carrying it.
 */
export function agentBlastPathHref(
  agentName: string,
  entry: { vulnerability_id: string; canonical_id?: string | null | undefined; package?: string | null | undefined },
): string {
  const params = new URLSearchParams({ lens: "attack-path", node: `agent:${agentName}`, cve: entry.vulnerability_id, agent: agentName });
  if (entry.canonical_id) params.set("finding", entry.canonical_id);
  return `/security-graph?${params}`;
}
