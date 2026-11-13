"use client";

import type { Edge, Node } from "@xyflow/react";
import { ArrowDown } from "lucide-react";

import type { LineageNodeData } from "@/components/lineage-nodes";
import { entityIcon } from "@/lib/entity-icons";
import { graphChains } from "@/lib/graph-chains";
import { isBlockedIdentityHop, isInternalService } from "@/lib/graph-flow-model";
import { LINEAGE_NODE_GRAPH_KIND, relationshipLegendItem } from "@/lib/graph-utils";
import { GRAPH_NODE_KIND_META } from "@/lib/graph-schema.generated";

function kindLabel(data: LineageNodeData): string {
  const kind = LINEAGE_NODE_GRAPH_KIND[data.nodeType];
  return (kind && GRAPH_NODE_KIND_META[kind]?.label) || data.entityType || data.nodeType;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low"];

/** Worst rating anywhere on the chain, so the screen opens on what matters; unrated chains keep their reading order. */
function chainRank(ids: string[], byId: Map<string, Node<LineageNodeData>>) {
  const ranks = ids.map(id => SEVERITY_ORDER.indexOf(byId.get(id)?.data.severity?.toLowerCase() ?? "")).filter(rank => rank >= 0);
  return ranks.length ? Math.min(...ranks) : SEVERITY_ORDER.length;
}

const ratedSeverity = (severity: string | undefined) =>
  severity && !["none", "unknown", ""].includes(severity.toLowerCase()) ? severity : null;

/** The same plain caveats the canvas gives: a route inside the cluster is not exposure, and an unmounted token is not a step. */
function hopLabel(relationship: string | undefined, source: Node<LineageNodeData>, targetId: string | undefined, edges: Edge[]): string {
  if (!relationship) return "linked to";
  if (relationship === "exposed_to" && isInternalService(source)) return "Routes in cluster to";
  const edge = edges.find(item => item.source === source.id && item.target === targetId && item.data?.relationship === relationship);
  const label = relationshipLegendItem(relationship).label;
  return edge && isBlockedIdentityHop(edge) && source.data.attributes?.token_mounted === false ? `${label} · token not mounted` : label;
}

/**
 * The phone reading of a loaded graph: each root-to-leaf chain as one readable
 * column, the same order the canvas draws left to right. A row opens details.
 */
export function GraphPathList({ nodes, edges, onSelect }: {
  nodes: Node<LineageNodeData>[];
  edges: Edge[];
  onSelect: (nodeId: string) => void;
}) {
  const byId = new Map(nodes.map(node => [node.id, node]));
  const { chains: inOrder, truncated } = graphChains(nodes, edges);
  const chains = inOrder.map(chain => ({ chain, rank: chainRank(chain.ids, byId) })).sort((a, b) => a.rank - b.rank).map(item => item.chain);
  return (
    <section aria-label="Graph paths" data-testid="graph-path-list" className="mt-2 space-y-3">
      <p className="text-xs text-ink-secondary">
        {nodes.length.toLocaleString()} nodes · {chains.length.toLocaleString()} {chains.length === 1 ? "path" : "paths"}
        {truncated ? " · first paths shown; open Graph for the rest" : ""}
      </p>
      <ol className="space-y-3">
        {chains.map(chain => (
          <li key={chain.ids.join(">")} data-testid="graph-path-list-chain" className="rounded-lg border border-outline bg-surface p-2">
            <ol>
              {chain.ids.map((id, index) => {
                const node = byId.get(id);
                if (!node) return null;
                const Icon = entityIcon(node.data.nodeType);
                const severity = ratedSeverity(node.data.severity);
                const relationship = chain.relationships[index];
                return (
                  <li key={id}>
                    <button type="button" onClick={() => onSelect(id)} title={node.data.label}
                      className="flex min-h-11 w-full items-center gap-3 rounded-md px-2 py-1.5 text-left hover:bg-surface-elevated focus-visible:outline focus-visible:outline-2">
                      <Icon aria-hidden="true" className="h-4 w-4 shrink-0 text-ink-secondary" />
                      <span className="min-w-0 flex-1">
                        {/* Digest-style names stop at two lines; the full name stays in the text and the tooltip. */}
                        <span title={node.data.label} className="block line-clamp-2 break-words text-sm font-medium text-foreground [overflow-wrap:anywhere]">{node.data.label}</span>
                        <span className="block text-xs text-ink-secondary">{kindLabel(node.data)}</span>
                        {node.data.identityContext && <span className="block text-xs text-ink-secondary">{node.data.identityContext}</span>}
                        {node.data.evidenceFlowContext && <span className="block text-xs text-ink-secondary">{node.data.evidenceFlowContext}</span>}
                      </span>
                      {severity && <span className="shrink-0 rounded border border-outline px-1.5 py-0.5 text-xs uppercase text-ink-secondary">{severity}</span>}
                    </button>
                    {relationship !== undefined && index < chain.ids.length - 1 && (
                      <p className="flex items-center gap-1.5 py-0.5 pl-3.5 text-xs text-ink-tertiary">
                        <ArrowDown aria-hidden="true" className="h-3.5 w-3.5" />
                        {hopLabel(relationship, node, chain.ids[index + 1], edges)}
                      </p>
                    )}
                  </li>
                );
              })}
            </ol>
            {chain.hiddenHops > 0 && <p className="px-2 pt-1 text-xs text-ink-tertiary">+{chain.hiddenHops} more {chain.hiddenHops === 1 ? "hop" : "hops"} · open Graph to follow</p>}
          </li>
        ))}
      </ol>
    </section>
  );
}
