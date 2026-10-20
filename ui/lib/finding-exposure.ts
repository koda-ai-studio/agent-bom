const NODE_KINDS: [RegExp, string][] = [
  [/^(pkg|package):.*:image:/, "Package in container image"],
  [/^(pkg|package):/, "Package"],
  [/^server:/, "MCP server"],
  [/^agent:/, "Agent"],
  [/^(container|image):/, "Container image"],
  [/^cloud_resource:/, "Cloud resource"],
];

function words(value: string): string {
  const text = value.replace(/[_-]+/g, " ").trim();
  return text ? text[0]!.toUpperCase() + text.slice(1) : "Asset";
}

/**
 * The affected asset's kind. The canonical node id names it reliably; a
 * record's entity_type can describe the reporting surface instead (a package
 * occurrence reported through an MCP server arrives as "server").
 */
export function findingAssetKind(vuln: { node_id?: string | undefined; entity_type?: string | undefined; asset_type?: string | undefined }): string {
  const node = vuln.node_id?.trim() ?? "";
  for (const [pattern, kind] of NODE_KINDS) if (pattern.test(node)) return kind;
  return words(vuln.entity_type || vuln.asset_type || "asset");
}

export interface ReachabilityVerdict {
  label: string;
  basis: string;
  tone: "reachable" | "none" | "unknown";
}

const agentName = (id: string) => id.replace(/^agent:/, "");
const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

/** The graph reachability verdict for one occurrence, with what it rests on. */
export function reachabilityVerdict(vuln: {
  graph_reachable?: boolean | null | undefined;
  graph_min_hop_distance?: number | null | undefined;
  graph_reachable_from_agents?: string[] | undefined;
}): ReachabilityVerdict {
  if (vuln.graph_reachable === true) {
    const agents = (vuln.graph_reachable_from_agents ?? []).map(agentName);
    const hops = typeof vuln.graph_min_hop_distance === "number" ? `, shortest ${plural(vuln.graph_min_hop_distance, "hop")}` : "";
    return {
      label: agents.length ? `Reachable from ${plural(agents.length, "agent")}` : "Reachable from an agent",
      basis: `Recorded attack-graph path${hops}. Structural reachability; it does not prove exploitation.`,
      tone: "reachable",
    };
  }
  if (vuln.graph_reachable === false) {
    return {
      label: "No agent path recorded",
      basis: "The graph walk found no path from an agent to this asset. That is not proof the vulnerable code is unreachable.",
      tone: "none",
    };
  }
  return { label: "Reachability not assessed", basis: "No graph evidence was recorded for this occurrence.", tone: "unknown" };
}
