import type { Edge } from "@xyflow/react";
import type { UnifiedEdge, UnifiedNode } from "@/lib/graph-schema";

/** Inverse hosting is a reading projection, not a new permission or persisted edge. */
export function hostReading(edge: Edge, record: UnifiedEdge, nodes: ReadonlyMap<string, UnifiedNode>): Edge {
  if (record.relationship !== "hosted_on" || nodes.get(record.target)?.entity_type !== "container") return edge;
  return { ...edge, source: record.target, target: record.source, sourceHandle: null, targetHandle: null,
    ariaLabel: `${nodes.get(record.target)?.label} hosts ${nodes.get(record.source)?.label}; inverse of recorded hosted_on relationship`,
    data: { ...edge.data, relationship: "hosts", relationshipLabel: "Hosts", originalRelationship: "hosted_on",
      originalSource: record.source, originalTarget: record.target, inverseRecordedRelationship: true,
      sourceEntityType: nodes.get(record.target)?.entity_type, targetEntityType: nodes.get(record.source)?.entity_type,
      hoverDescription: `Hosts · ${edge.data?.evidenceLabel ?? "See recorded evidence"}. Inverse reading of hosted_on; original endpoints retained in relationship evidence.` },
  };
}
