import type { Edge } from "@xyflow/react";
import { edgeFamily, edgeFamilyColor, edgeIsDashed } from "@/lib/graph-edge-family";

export type FlowLineStyle = "solid" | "modeled" | "dashed" | "runtime";
export interface FlowEdgeLegend {
  styles: FlowLineStyle[];
  /** One entry per drawn colour, naming every relationship drawn in it, most drawn first. */
  relationships: { relationship: string; label: string; stroke: string; count: number }[];
  /** Relationship colours drawn but not listed. */
  more: number;
}

const STYLE_ORDER: FlowLineStyle[] = ["solid", "modeled", "dashed", "runtime"];

/** The colour and dash a line is actually drawn with: a compact link by its relationship family, any other by its style. */
function drawn(edge: Edge, relationship: string): { stroke: string; dashed: boolean } {
  if (edge.type === "compact") {
    const family = edgeFamily(relationship);
    return { stroke: edgeFamilyColor(family), dashed: edgeIsDashed(family, edge.data) };
  }
  return { stroke: typeof edge.style?.stroke === "string" ? edge.style.stroke : "", dashed: Boolean(edge.style?.strokeDasharray) };
}

/** Line style already carries the evidence (dashed for modeled), so the legend names the relationship alone. */
const plainLabel = (label: string) => label.replace(/\s*·.*$/, "");

/** What the drawn lines mean: their styles, and the relationships each colour stands for, most drawn first. */
export function flowEdgeLegend(edges: readonly Edge[]): FlowEdgeLegend {
  const styles = new Set<FlowLineStyle>();
  const byStroke = new Map<string, { stroke: string; count: number; labels: Map<string, number>; first: string }>();
  for (const edge of edges) {
    if (edge.hidden || edge.data?.displayOnly) continue;
    const relationship = typeof edge.data?.relationship === "string" ? edge.data.relationship : "";
    const { stroke, dashed } = drawn(edge, relationship);
    // A view whose every link is modeled draws them solid; the legend must still say they are modeled.
    styles.add(dashed ? "dashed" : edge.data?.uniformlyModeled === true ? "modeled" : "solid");
    if (edge.animated) styles.add("runtime");
    // Links on the exposure path are named once, by the legend's exposure entry.
    if (!relationship || !stroke || edge.data?.exposurePath === true) continue;
    const label = plainLabel(typeof edge.data?.relationshipLabel === "string" ? edge.data.relationshipLabel : relationship.replaceAll("_", " "));
    const entry = byStroke.get(stroke) ?? { stroke, count: 0, labels: new Map<string, number>(), first: relationship };
    entry.count++;
    entry.labels.set(label, (entry.labels.get(label) ?? 0) + 1);
    if (relationship.localeCompare(entry.first) < 0) entry.first = relationship;
    byStroke.set(stroke, entry);
  }
  const relationships = [...byStroke.values()].map(entry => ({
    relationship: entry.first, stroke: entry.stroke, count: entry.count,
    label: [...entry.labels].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([label]) => label).join(", "),
  })).sort((a, b) => b.count - a.count || a.relationship.localeCompare(b.relationship));
  return { styles: STYLE_ORDER.filter(style => styles.has(style)), relationships, more: 0 };
}
