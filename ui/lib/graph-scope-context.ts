import { entitySource } from "@/lib/agent-source";
import { nodeBadges, type NodeBadgeInput } from "@/lib/graph-node-badges";

/**
 * What a node's parent scope already says, so the canvas states a vendor or an
 * environment once at scope level and repeats it only where a node differs.
 * `null` means no reference: the node is a scope root, its parents disagree,
 * or nothing anchors the canvas, and its own badge shows.
 */
export interface ScopeContext {
  provider: string | null;
  environment: string | null;
}

type ScopedData = NodeBadgeInput & {
  agentType?: string | undefined;
  dataSources?: string[] | undefined;
  scopeContext?: ScopeContext | undefined;
};
type ScopedNode = { id: string; data: ScopedData };
type ScopedEdge = { source: string; target: string; relationship?: unknown; data?: unknown };

const SCOPE_TYPES = new Set(["provider", "org", "account", "environment", "cluster", "fleet"]);
const PARENT_TO_CHILD = new Set(["contains", "owns", "hosts"]);
const CHILD_TO_PARENT = new Set(["hosted_on", "part_of"]);
const CONFLICT = "\u0000conflict";

export function nodeProvider(data: ScopedData): string {
  return entitySource(data as Parameters<typeof entitySource>[0])?.id ?? "";
}

export function nodeEnvironment(data: ScopedData): string {
  return nodeBadges(data).badges.find((badge) => badge.kind === "environment")?.value ?? "";
}

function relationshipOf(edge: ScopedEdge): string {
  const data = edge.data as { relationship?: unknown } | undefined;
  return String(edge.relationship ?? data?.relationship ?? "");
}

function unique(values: string[]): string | undefined {
  const present = [...new Set(values.filter(Boolean))];
  if (present.length === 0) return undefined;
  return present.length === 1 ? present[0] : CONFLICT;
}

function references(nodes: ScopedNode[], edges: ScopedEdge[], valueOf: (data: ScopedData) => string): Map<string, string | null> {
  const values = new Map(nodes.map((item) => [item.id, valueOf(item.data)]));
  const types = new Map(nodes.map((item) => [item.id, String(item.data.nodeType)]));
  const parents = new Map<string, string[]>();
  const inbound = new Map<string, string[]>();
  for (const edge of edges) {
    if (!values.has(edge.source) || !values.has(edge.target) || edge.source === edge.target) continue;
    const relationship = relationshipOf(edge);
    if (PARENT_TO_CHILD.has(relationship)) parents.set(edge.target, [...(parents.get(edge.target) ?? []), edge.source]);
    else if (CHILD_TO_PARENT.has(relationship)) parents.set(edge.source, [...(parents.get(edge.source) ?? []), edge.target]);
    else inbound.set(edge.target, [...(inbound.get(edge.target) ?? []), edge.source]);
  }
  // Nearest containment ancestors that record a value; a tie that disagrees is a conflict.
  const ancestorValue = (id: string): string | undefined => {
    const seen = new Set([id]);
    let frontier = parents.get(id) ?? [];
    while (frontier.length) {
      const found = unique(frontier.map((parent) => values.get(parent) ?? ""));
      if (found) return found;
      frontier = frontier.flatMap((parent) => parents.get(parent) ?? []).filter((parent) => !seen.has(parent) && seen.add(parent));
    }
    return undefined;
  };
  const direct = new Map<string, string | undefined>();
  for (const item of nodes) {
    direct.set(item.id, ancestorValue(item.id) ?? unique((inbound.get(item.id) ?? []).map((source) => values.get(source) ?? "")));
  }
  const scopeRoots = nodes.filter((item) => SCOPE_TYPES.has(types.get(item.id)!) && values.get(item.id) && direct.get(item.id) === undefined);
  const canvas = unique(scopeRoots.map((item) => values.get(item.id)!));
  const result = new Map<string, string | null>();
  for (const item of nodes) {
    const reference = direct.get(item.id);
    if (reference !== undefined) result.set(item.id, reference === CONFLICT ? null : reference);
    else if (SCOPE_TYPES.has(types.get(item.id)!)) result.set(item.id, null);
    else result.set(item.id, canvas && canvas !== CONFLICT ? canvas : null);
  }
  return result;
}

/** Stamp each visible node with the vendor and environment its scope already shows. */
export function assignScopeContext(nodes: ScopedNode[], edges: ScopedEdge[]): void {
  const providers = references(nodes, edges, nodeProvider);
  const environments = references(nodes, edges, nodeEnvironment);
  for (const item of nodes) {
    item.data.scopeContext = { provider: providers.get(item.id) ?? null, environment: environments.get(item.id) ?? null };
  }
}

export function showsProviderMark(data: ScopedData): boolean {
  const provider = nodeProvider(data);
  if (!provider) return false;
  return !data.scopeContext || data.scopeContext.provider !== provider;
}

export function showsEnvironmentChip(data: ScopedData): boolean {
  const environment = nodeEnvironment(data);
  if (!environment) return false;
  return !data.scopeContext || data.scopeContext.environment !== environment;
}
