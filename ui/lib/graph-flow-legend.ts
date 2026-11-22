import type { Edge } from "@xyflow/react";

export type FlowLineStyle = "solid" | "dashed" | "runtime";
export interface FlowEdgeLegend {
  styles: FlowLineStyle[];
  relationships: { relationship: string; label: string; stroke: string; count: number }[];
  /** Relationship colours drawn but not listed. */
  more: number;
}

const STYLE_ORDER: FlowLineStyle[] = ["solid", "dashed", "runtime"];

/** What the drawn lines mean: their styles, and the relationship each colour stands for, most drawn first. */
export function flowEdgeLegend(edges: readonly Edge[]): FlowEdgeLegend {
  const styles = new Set<FlowLineStyle>();
  const byRelationship = new Map<string, FlowEdgeLegend["relationships"][number]>();
  for (const edge of edges) {
    if (edge.hidden || edge.data?.displayOnly) continue;
    styles.add(edge.style?.strokeDasharray ? "dashed" : "solid");
    if (edge.animated) styles.add("runtime");
    const relationship = typeof edge.data?.relationship === "string" ? edge.data.relationship : "";
    const stroke = typeof edge.style?.stroke === "string" ? edge.style.stroke : "";
    if (!relationship || !stroke) continue;
    const entry = byRelationship.get(relationship);
    if (entry) entry.count++;
    else byRelationship.set(relationship, {
      relationship, stroke, count: 1,
      label: typeof edge.data?.relationshipLabel === "string" ? edge.data.relationshipLabel : relationship.replaceAll("_", " "),
    });
  }
  const relationships = [...byRelationship.values()].sort((a, b) => b.count - a.count || a.relationship.localeCompare(b.relationship));
  return { styles: STYLE_ORDER.filter(style => styles.has(style)), relationships, more: 0 };
}
