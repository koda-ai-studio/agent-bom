"use client";

import type { Edge, Node } from "@xyflow/react";

import type { LineageNodeData } from "@/components/lineage-nodes";
import { RelationshipIcon } from "@/components/relationship-edge";
import { entityIcon } from "@/lib/entity-icons";
import { accessEvidenceQualifier } from "@/lib/graph-access-evidence";
import { LINEAGE_NODE_GRAPH_KIND, relationshipLegendItem } from "@/lib/graph-utils";
import { GRAPH_NODE_KIND_META } from "@/lib/graph-schema.generated";

type Row = { id: string; label: string; kind: string; severity: string | undefined; nodeType: string };

function kindLabel(data: LineageNodeData): string {
  const kind = LINEAGE_NODE_GRAPH_KIND[data.nodeType];
  return (kind && GRAPH_NODE_KIND_META[kind]?.label) || data.entityType || data.nodeType;
}

/**
 * The phone reading of a root-centred investigation: the root, then each
 * relationship group it has, one row per connected entity. A row opens that
 * entity's details; the canvas stays one tap away.
 */
export function GraphConnectionsList({ rootId, nodes, edges, memberNodes, onSelect }: {
  rootId: string;
  nodes: Node<LineageNodeData>[];
  edges: Edge[];
  /** Every loaded entity, so a collapsed group lists its members individually. */
  memberNodes: Map<string, Node<LineageNodeData>>;
  onSelect: (nodeId: string) => void;
}) {
  const pills = new Map(nodes.filter(node => (node.data as { isCluster?: boolean }).isCluster).map(node => [node.id, node.data as unknown as { memberEdges?: Edge[] }]));
  const byId = new Map([...memberNodes, ...nodes.filter(node => !pills.has(node.id)).map(node => [node.id, node] as const)]);
  const root = byId.get(rootId);
  const groups = new Map<string, { outgoing: boolean; rows: Row[]; qualifiers: Set<string> }>();
  const others: Row[] = [];
  // A collapsed group stands for its member links; the list names each member.
  const listedEdges = edges.flatMap(edge => pills.has(edge.target) ? pills.get(edge.target)!.memberEdges ?? [] : pills.has(edge.source) ? [] : [edge]);
  const shown = new Set([rootId, ...listedEdges.flatMap(edge => [edge.source, edge.target]), ...nodes.filter(node => !pills.has(node.id)).map(node => node.id)]);
  for (const edge of listedEdges) {
    const relationship = typeof edge.data?.relationship === "string" ? edge.data.relationship : "";
    const outgoing = edge.source === rootId;
    const otherId = outgoing ? edge.target : edge.target === rootId ? edge.source : null;
    const other = otherId ? byId.get(otherId) : undefined;
    if (!other) continue;
    const key = `${outgoing ? "out" : "in"}:${relationship}`;
    const group = groups.get(key) ?? { outgoing, rows: [], qualifiers: new Set<string>() };
    group.qualifiers.add(accessEvidenceQualifier(relationship, edge.data as Record<string, unknown> | undefined) ?? "");
    if (!group.rows.some(row => row.id === other.id)) {
      group.rows.push({ id: other.id, label: other.data.label, kind: kindLabel(other.data), severity: other.data.severity, nodeType: other.data.nodeType });
    }
    groups.set(key, group);
  }
  const linked = new Set([rootId, ...[...groups.values()].flatMap(group => group.rows.map(row => row.id))]);
  for (const node of [...byId.values()].filter(node => shown.has(node.id))) {
    if (!linked.has(node.id)) others.push({ id: node.id, label: node.data.label, kind: kindLabel(node.data), severity: node.data.severity, nodeType: node.data.nodeType });
  }
  const RootIcon = entityIcon(root?.data.nodeType);
  const rowButton = (row: Row) => {
    const Icon = entityIcon(row.nodeType);
    const severity = row.severity && !["none", "unknown", ""].includes(row.severity.toLowerCase()) ? row.severity : null;
    return <li key={row.id}>
      <button type="button" onClick={() => onSelect(row.id)}
        className="flex min-h-11 w-full items-center gap-3 rounded-md px-3 py-2 text-left hover:bg-surface-elevated focus-visible:outline focus-visible:outline-2">
        <Icon aria-hidden="true" className="h-4 w-4 shrink-0 text-muted-foreground" />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-sm font-medium text-foreground">{row.label}</span>
          <span className="block text-xs text-muted-foreground">{row.kind}</span>
        </span>
        {severity && <span className="rounded border border-outline px-1.5 py-0.5 text-[11px] uppercase text-muted-foreground">{severity}</span>}
      </button>
    </li>;
  };

  return <section aria-label="Connections" data-testid="graph-connections-list" className="space-y-3 rounded-lg border border-outline bg-surface p-3">
    {root && <button type="button" onClick={() => onSelect(root.id)} className="flex min-h-11 w-full items-center gap-3 text-left">
      <RootIcon aria-hidden="true" className="h-5 w-5 shrink-0 text-foreground" />
      <span className="min-w-0">
        <span className="block truncate text-base font-semibold text-foreground">{root.data.label}</span>
        <span className="block text-xs text-muted-foreground">{kindLabel(root.data)}</span>
      </span>
    </button>}
    {[...groups.entries()].map(([key, group]) => {
      const relationship = key.slice(key.indexOf(":") + 1);
      return <div key={key}>
        <h3 className="flex items-center gap-2 px-3 text-xs font-medium text-muted-foreground">
          <RelationshipIcon relationship={relationship} />
          <span>{group.outgoing ? "" : "From "}{relationshipLegendItem(relationship).label}
            {/* Evidence stays with the verb: a bare relationship reads as observed fact. */}
            {group.qualifiers.size > 1 ? " · mixed evidence" : [...group.qualifiers][0] ? ` · ${[...group.qualifiers][0]}` : ""} · {group.rows.length}</span>
        </h3>
        <ul>{group.rows.map(rowButton)}</ul>
      </div>;
    })}
    {others.length > 0 && <div>
      <h3 className="px-3 text-xs font-medium text-muted-foreground">Also in this view · {others.length}</h3>
      <ul>{others.map(rowButton)}</ul>
    </div>}
  </section>;
}
