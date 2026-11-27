import type { UnifiedGraphData } from "@/lib/graph-schema";

const SERVERS = new Set(["server", "mcp_server"]);
const FINDINGS = new Set(["vulnerability", "misconfiguration", "finding", "iac_finding"]);

/** A bounded original-edge neighborhood; only suppress a shared-server shortcut when both uses edges are present. */
export function scopeEvidenceGraph(graph: UnifiedGraphData, root: string, includeImpact = false): UnifiedGraphData {
  const byId = new Map(graph.nodes.map(node => [node.id, node]));
  const incident = graph.edges.filter(edge => edge.source === root || edge.target === root);
  const neighbors = incident.map(edge => edge.source === root ? edge.target : edge.source)
    .filter(id => byId.has(id) && !FINDINGS.has(byId.get(id)!.entity_type));
  const chosen = new Set([root, ...[...new Set(neighbors)].sort((a, b) => Number(SERVERS.has(byId.get(b)!.entity_type)) - Number(SERVERS.has(byId.get(a)!.entity_type)) || a.localeCompare(b)).slice(0, 7)]);
  const servers = new Set([...chosen].filter(id => SERVERS.has(byId.get(id)?.entity_type ?? "")));
  for (const edge of graph.edges) {
    if (chosen.size >= 10) break;
    if (edge.relationship === "uses" && servers.has(edge.target) && byId.get(edge.source)?.entity_type === "agent") chosen.add(edge.source);
  }
  // Include one recorded assumption hop into an access-granting role.
  const assumption = graph.edges.find(edge => edge.relationship === "assumes" && chosen.has(edge.target)
    && byId.get(edge.target)?.entity_type === "role" && byId.has(edge.source));
  if (assumption && chosen.size < 10) chosen.add(assumption.source);
  if (includeImpact) {
    const impactServer = [...servers].sort((a, b) => {
      const shell = (id: string) => graph.edges.some(edge => edge.source === id && edge.relationship === "provides_tool" && byId.get(edge.target)?.attributes.tool_class === "shell");
      return Number(shell(b)) - Number(shell(a)) || a.localeCompare(b);
    })[0];
    const impact = graph.edges.filter(edge => edge.source === impactServer && ["provides_tool", "exposes_cred"].includes(edge.relationship) && byId.has(edge.target)).map(edge => edge.target);
    for (const id of impact) chosen.add(id);
    // What an exposed credential can open is the end of the story, so its recorded access is included.
    for (const edge of graph.edges) if (edge.relationship === "can_access" && impact.includes(edge.source) && byId.get(edge.source)?.entity_type === "credential" && byId.has(edge.target)) chosen.add(edge.target);
  }
  const edges = graph.edges.filter(edge => chosen.has(edge.source) && chosen.has(edge.target)).filter(edge => {
    if (edge.relationship !== "shares_server") return true;
    return ![...servers].some(server => [edge.source, edge.target].every(agent =>
      graph.edges.some(link => link.source === agent && link.target === server && link.relationship === "uses")));
  });
  return { ...graph, nodes: graph.nodes.filter(node => chosen.has(node.id)), edges };
}
