"use client";

import { useMemo, useState } from "react";
import type { Edge } from "@xyflow/react";

type LabelVisibility = "auto" | "show" | "hide";

/** Presentation only: relationship records and selectable evidence stay intact. */
export function useRelationshipLabelControl(edges: Edge[]) {
  const [visibility, setVisibility] = useState<LabelVisibility>("auto");
  const labeledEdges = useMemo(() => visibility === "auto" ? edges : edges.map(edge => ({
    ...edge, data: { ...edge.data, labelVisibility: visibility },
  })), [edges, visibility]);
  const control = <label className="inline-flex min-h-9 items-center gap-2 text-xs text-ink-secondary">
    Relationship labels
    <select aria-label="Relationship labels" value={visibility}
      onChange={event => setVisibility(event.target.value as LabelVisibility)}
      className="rounded-md border border-outline bg-surface px-2 py-1 text-foreground">
      <option value="auto">Auto</option><option value="show">Show</option><option value="hide">Hide</option>
    </select>
  </label>;
  return { edges: labeledEdges, control };
}
