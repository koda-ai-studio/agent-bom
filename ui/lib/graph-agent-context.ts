/** Direct recorded relationships; environment or vendor membership never proves hosting. */
import type { UnifiedEdge, UnifiedNode } from "./graph-schema";

export interface AgentContextReference {
  node_id: string; label: string; entity_type: string; relationship: string;
  evidence_kind: string; source: string; provider: string; service: string;
  account_id: string; region: string; last_seen: string; source_scan_id: string;
}
export interface AgentContextGroup {
  status: "recorded" | "not_recorded"; items: AgentContextReference[]; recorded_count: number; truncated: boolean;
}
export interface AgentContext {
  agentKind: string; basis: "snapshot" | "loaded_graph";
  platforms: AgentContextGroup; execution: AgentContextGroup; models: AgentContextGroup; membership: AgentContextGroup;
}
type ContextCategory = "platforms" | "execution" | "models" | "membership";
const LIMIT = 16;
const text = (value: unknown, limit = 200): string => typeof value === "string" ? value.trim().slice(0, limit) : "";
const object = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const empty = (): AgentContextGroup => ({ status: "not_recorded", items: [], recorded_count: 0, truncated: false });
function reference(value: unknown): AgentContextReference | null {
  const row = object(value);
  if (typeof row.node_id !== "string" || !row.node_id || row.node_id.length > 4096 || !text(row.label)) return null;
  return Object.fromEntries(["node_id", "label", "entity_type", "relationship", "evidence_kind", "source", "provider", "service", "account_id", "region", "last_seen", "source_scan_id"].map(key => [key, key === "node_id" ? row.node_id : text(row[key])])) as unknown as AgentContextReference;
}
function persisted(value: unknown): AgentContextGroup {
  const row = object(value);
  const items = Array.isArray(row.items) ? row.items.slice(0, LIMIT).map(reference).filter((item): item is AgentContextReference => item !== null) : [];
  const count = typeof row.recorded_count === "number" && Number.isSafeInteger(row.recorded_count) ? Math.max(items.length, row.recorded_count) : items.length;
  return { status: count > 0 ? "recorded" : "not_recorded", items, recorded_count: count, truncated: count > items.length || row.truncated === true };
}
export function retainedAgentContext(attributes: Record<string, unknown>): AgentContext | null {
  const raw = object(attributes.agent_context);
  if (raw.schema_version !== "agent.context.v1") return null;
  return { agentKind: text(raw.agent_kind || attributes.agent_type, 80) || "unknown", basis: "snapshot", platforms: persisted(raw.platforms), execution: persisted(raw.execution), models: persisted(raw.models), membership: persisted(raw.membership) };
}
export function graphAgentContext(agent: UnifiedNode, outgoing: UnifiedEdge[], incoming: UnifiedEdge[], nodes: Map<string, UnifiedNode>): AgentContext {
  const retained = retainedAgentContext(agent.attributes ?? {});
  if (retained) return retained;
  const context: AgentContext = { agentKind: text(agent.attributes?.agent_type, 80) || "unknown", basis: "loaded_graph", platforms: empty(), execution: empty(), models: empty(), membership: empty() };
  // Legacy snapshots can supply direct context, bounded to the loaded graph.
  for (const [edges, isOutgoing] of [[outgoing, true], [incoming, false]] as const) {
    for (const edge of edges) {
      const other = nodes.get(isOutgoing ? edge.target : edge.source);
      if (!other) continue;
      const relation = String(edge.relationship), kind = String(other.entity_type);
      const endpointHost = kind === "fleet" && !!text(other.attributes?.endpoint_id) && edge.evidence?.source === "endpoint_inventory" && edge.evidence?.identity_match_basis === "exact_source_id";
      let category: ContextCategory | undefined;
      if (!isOutgoing && kind === "provider" && ["platform_for", "hosts"].includes(relation)) category = "platforms";
      else if ((["cloud_resource", "container", "cluster"].includes(kind) || endpointHost) && (isOutgoing ? relation === "hosted_on" : relation === "hosts")) category = "execution";
      else if (["org", "account", "environment", "fleet", "cluster"].includes(kind) && (isOutgoing ? ["part_of", "belongs_to", "member_of"].includes(relation) : ["contains", "owns"].includes(relation))) category = "membership";
      else if (isOutgoing && kind === "model" && relation === "serves_model") category = "models";
      if (!category) continue;
      const group = context[category]; group.status = "recorded"; group.recorded_count++;
      if (group.items.length >= LIMIT) { group.truncated = true; continue; }
      const scope = object(other.attributes?.scope);
      group.items.push({ node_id: other.id, label: text(other.label), entity_type: kind, relationship: relation, evidence_kind: text(edge.evidence?.tier) || "unknown", source: text(edge.evidence?.source) || "unknown", provider: text(other.attributes?.cloud_provider || other.dimensions?.cloud_provider), service: text(other.attributes?.cloud_service || other.attributes?.service), account_id: text(other.attributes?.account_id || scope.account_id), region: text(other.attributes?.region || scope.region || other.attributes?.location), last_seen: text(edge.last_seen), source_scan_id: text(edge.source_scan_id) });
    }
  }
  return context;
}
export function agentExecutionCaption(context: AgentContext | undefined): string {
  if (!context?.execution.items.length) return "Host not recorded";
  const first = context.execution.items[0]!;
  const host = [first.provider, first.service].filter(Boolean).join(" · ") || first.label;
  return `Host: ${host}${context.execution.recorded_count > 1 ? ` +${context.execution.recorded_count - 1}` : ""}`;
}

export function agentRelationshipLabel(relationship: string, sourceType?: string, targetType?: string): string | undefined {
  if (targetType !== "agent") return undefined;
  if (sourceType === "provider" && ["hosts", "platform_for"].includes(relationship)) return "Platform for";
  if (["org", "account", "environment", "fleet", "cluster"].includes(sourceType ?? "") && ["contains", "owns"].includes(relationship)) return "Includes · membership";
  return undefined;
}
export function agentContextRelationshipLabel(edge: UnifiedEdge, nodes: Map<string, UnifiedNode>): string | undefined {
  return agentRelationshipLabel(String(edge.relationship), String(nodes.get(edge.source)?.entity_type), String(nodes.get(edge.target)?.entity_type));
}

export function platformAgentCount(edges: UnifiedEdge[], nodes: Map<string, UnifiedNode>): number {
  return new Set(edges.filter(edge => ["platform_for", "hosts"].includes(String(edge.relationship)) && String(nodes.get(edge.target)?.entity_type) === "agent").map(edge => edge.target)).size;
}
