"use client";

import type { Edge, Node } from "@xyflow/react";
import { ArrowDown } from "lucide-react";

import type { LineageNodeData } from "@/components/lineage-nodes";
import { entityIcon } from "@/lib/entity-icons";
import { graphChains } from "@/lib/graph-chains";
import { LINEAGE_NODE_GRAPH_KIND, relationshipLegendItem } from "@/lib/graph-utils";
import { GRAPH_NODE_KIND_META } from "@/lib/graph-schema.generated";

function kindLabel(data: LineageNodeData): string {
  const kind = LINEAGE_NODE_GRAPH_KIND[data.nodeType];
  return (kind && GRAPH_NODE_KIND_META[kind]?.label) || data.entityType || data.nodeType;
}

const ratedSeverity = (severity: string | undefined) =>
  severity && !["none", "unknown", ""].includes(severity.toLowerCase()) ? severity : null;

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
  const { chains, truncated } = graphChains(nodes, edges);
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
                    <button type="button" onClick={() => onSelect(id)}
                      className="flex min-h-11 w-full items-center gap-3 rounded-md px-2 py-1.5 text-left hover:bg-surface-elevated focus-visible:outline focus-visible:outline-2">
                      <Icon aria-hidden="true" className="h-4 w-4 shrink-0 text-ink-secondary" />
                      <span className="min-w-0 flex-1">
                        <span className="block break-words text-sm font-medium text-foreground [overflow-wrap:anywhere]">{node.data.label}</span>
                        <span className="block text-xs text-ink-secondary">{kindLabel(node.data)}</span>
                      </span>
                      {severity && <span className="shrink-0 rounded border border-outline px-1.5 py-0.5 text-xs uppercase text-ink-secondary">{severity}</span>}
                    </button>
                    {relationship !== undefined && index < chain.ids.length - 1 && (
                      <p className="flex items-center gap-1.5 py-0.5 pl-3.5 text-xs text-ink-tertiary">
                        <ArrowDown aria-hidden="true" className="h-3.5 w-3.5" />
                        {relationship ? relationshipLegendItem(relationship).label : "linked to"}
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
