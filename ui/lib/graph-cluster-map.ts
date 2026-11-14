/**
 * The grouped full map: request state, bundled-edge labels and a tier-column layout.
 *
 * The server groups the snapshot and counts every bundled edge exactly; this
 * module only decides where each group, member and "+K more" card sits.
 * Groups read left to right in the order an exposure travels (scope, AI layer,
 * MCP servers, packages, findings, identities, cloud and data); within a
 * column risky groups lead and the rest are ordered to cross as few bundles
 * as possible. On a phone the tiers stack top to bottom instead.
 */
import type { components } from "@/lib/api-schema.generated";
import { GRAPH_EDGE_KIND_META, isGraphEdgeKind } from "@/lib/graph-schema.generated";

export type ClusterMapResponse = components["schemas"]["GraphClusterMapResponse"];
export type ClusterMapNode = components["schemas"]["GraphClusterMapNode"];
export type ClusterMapEdge = components["schemas"]["GraphClusterMapEdge"];

/** Mirrors the server's FIRST_FRAME_ELEMENT_BUDGET: what a first frame may draw. */
export const CLUSTER_MAP_ELEMENT_BUDGET = 60;
export const CLUSTER_MAP_MEMBER_LIMIT = 8;

export interface ClusterMapState {
  expanded: string[];
  pages: Record<string, number>;
  riskyOnly: boolean;
  focus: string | null;
}

export const INITIAL_CLUSTER_MAP_STATE: ClusterMapState = { expanded: [], pages: {}, riskyOnly: false, focus: null };

export function clusterMapParams(scanId: string | undefined, state: ClusterMapState, memberLimit = CLUSTER_MAP_MEMBER_LIMIT): URLSearchParams {
  const params = new URLSearchParams();
  if (scanId) params.set("scan_id", scanId);
  for (const id of state.expanded) params.append("expand", id);
  for (const [id, offset] of Object.entries(state.pages)) if (offset > 0 && state.expanded.includes(id)) params.append("page", `${offset}:${id}`);
  if (state.riskyOnly) params.set("risky_only", "true");
  if (state.focus) params.set("focus", state.focus);
  params.set("member_limit", String(memberLimit));
  return params;
}

/** Expanding opens a group in place; collapsing it forgets its page and any focus inside it. */
export function toggleClusterExpanded(state: ClusterMapState, id: string, focusClusterId?: string | null): ClusterMapState {
  if (state.expanded.includes(id) || focusClusterId === id) {
    const pages = { ...state.pages };
    delete pages[id];
    return { ...state, expanded: state.expanded.filter(item => item !== id), pages, focus: focusClusterId === id ? null : state.focus };
  }
  return { ...state, expanded: [...state.expanded, id] };
}

export function pageCluster(state: ClusterMapState, id: string, offset: number): ClusterMapState {
  return { ...state, expanded: state.expanded.includes(id) ? state.expanded : [...state.expanded, id], pages: { ...state.pages, [id]: Math.max(0, offset) } };
}

export function relationshipLabel(relationship: string): string {
  return isGraphEdgeKind(relationship) ? GRAPH_EDGE_KIND_META[relationship].label : relationship.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

/** "Depends On ×38"; a bundle of several kinds names the largest and how many others it carries. */
export function bundleLabel(edge: Pick<ClusterMapEdge, "count" | "relationships">): string {
  const [top, ...rest] = edge.relationships;
  if (!top) return `×${edge.count.toLocaleString()}`;
  const head = `${relationshipLabel(top.relationship)} ×${top.count.toLocaleString()}`;
  return rest.length ? `${head} +${rest.length} more` : head;
}

export function bundleTitle(edge: Pick<ClusterMapEdge, "count" | "relationships">): string {
  return `${edge.count.toLocaleString()} relationships: ${edge.relationships.map(item => `${relationshipLabel(item.relationship)} ×${item.count.toLocaleString()}`).join(", ")}`;
}

export interface ClusterMapGateInput {
  hasScan: boolean;
  /** `?grouping=off`: the operator asked for every edge. */
  groupingOff: boolean;
  /** The grouped read failed for this snapshot; the ungrouped map stands in. */
  unavailable: boolean;
  /** A focused surface (investigation, attack path, scenario, reachability, blast radius) owns the canvas. */
  focusedSurface: boolean;
  /** The containment scope navigation owns the canvas. */
  scopeNavigation: boolean;
  /** The bounded connection preview is on screen (not yet expanded to the full map). */
  previewing: boolean;
  /** Nodes plus edges the ungrouped map would draw. */
  elements: number;
  webgl: boolean;
}

/** The grouped map replaces the ungrouped full map whenever that map would draw more than one frame's budget. */
export function clusterMapEligible(input: ClusterMapGateInput): boolean {
  if (!input.hasScan || input.groupingOff || input.unavailable) return false;
  if (input.focusedSurface || input.scopeNavigation || input.previewing) return false;
  return input.webgl || input.elements > CLUSTER_MAP_ELEMENT_BUDGET;
}

/** Scope-tier groups a roll-up ranks: organizations, accounts, environments and fleets (a provider alone is not a scope to rank). */
const RANKABLE_SCOPE_GROUPS: ReadonlySet<string> = new Set(["type:org", "type:account", "type:environment", "type:fleet"]);

/** Whether a grouped-map frame shows a scope hierarchy, the cheap signal for a large estate's landing. */
export function clusterMapHasScopeGroups(view: Pick<ClusterMapResponse, "clusters">): boolean {
  return (view.clusters ?? []).some(cluster => RANKABLE_SCOPE_GROUPS.has(cluster.cluster_key) && cluster.member_count > 0);
}

export function severityWords(node: Pick<ClusterMapNode, "worst_severity" | "severity">): string {
  const word = node.worst_severity ?? node.severity ?? "none";
  return word === "none" || word === "info" ? "No critical or high findings" : `Worst: ${word}`;
}
