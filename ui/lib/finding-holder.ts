import { agentDisplayName } from "@/lib/display-name";
import { findingAssetKind } from "@/lib/finding-exposure";

export interface ReachingEntity {
  kind: "agent" | "workload" | "MCP server" | "cloud resource" | "asset";
  name: string;
  id: string;
}

const lastSegment = (value: string) => value.split(/[/:]/).filter(Boolean).pop() ?? value;

/** Kind and short name of a graph node that reaches an occurrence. */
export function reachingEntity(id: string): ReachingEntity {
  const trimmed = id.trim();
  if (trimmed.startsWith("agent:")) return { kind: "agent", name: agentDisplayName(trimmed.slice(6)), id: trimmed };
  if (/^(kubernetes:)?workload:/.test(trimmed)) return { kind: "workload", name: lastSegment(trimmed), id: trimmed };
  if (trimmed.startsWith("server:")) return { kind: "MCP server", name: trimmed.slice(7), id: trimmed };
  if (trimmed.startsWith("cloud_resource:")) return { kind: "cloud resource", name: lastSegment(trimmed), id: trimmed };
  return { kind: "asset", name: lastSegment(trimmed), id: trimmed };
}

export interface FindingHolder {
  label: string;
  kind: "agents" | "server" | "reacher" | "none";
  title: string;
}

type HolderInput = {
  agents?: string[] | undefined;
  affected_servers?: string[] | undefined;
  graph_reachable_from?: string[] | undefined;
  node_id?: string | undefined;
  entity_type?: string | undefined;
  asset_type?: string | undefined;
};

/** Who holds an occurrence: its agents, else its MCP server, else the graph's reacher, else why none. */
export function findingHolder(vuln: HolderInput): FindingHolder {
  const agents = vuln.agents ?? [];
  if (agents.length) return { label: agents.map((agent) => agentDisplayName(agent)).join(", "), kind: "agents", title: agents.join(", ") };
  const server = vuln.affected_servers?.[0];
  if (server) return { label: `MCP server ${server}`, kind: "server", title: server };
  const reacher = vuln.graph_reachable_from?.[0];
  if (reacher) {
    const entity = reachingEntity(reacher);
    const kind = entity.kind.charAt(0).toUpperCase() + entity.kind.slice(1);
    return { label: `${kind} ${entity.name}`, kind: "reacher", title: entity.id };
  }
  const assetKind = findingAssetKind(vuln);
  return { label: `${assetKind} · no agent linked`, kind: "none", title: `No agent, MCP server or reaching workload is recorded for this ${assetKind.toLowerCase()}.` };
}
