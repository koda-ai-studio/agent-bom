import type { GraphRollupContainer, GraphRollupEdge } from "@/lib/api-types";
import { buildRollupFlowGraph } from "@/lib/graph-rollup-view";
import { severityRank } from "@/lib/severity";

const FINDINGS = new Set(["misconfiguration", "vulnerability", "finding", "iac_finding"]);

/** A bounded selection of recorded links, never a synthesized attack path. */
export function buildScopePreview(items: GraphRollupContainer[], edges: GraphRollupEdge[], rootId?: string) {
  const byId = new Map(items.map(item => [item.id, item]));
  const incident = new Map<string, GraphRollupEdge[]>();
  for (const edge of edges) {
    if (!byId.has(edge.source) || !byId.has(edge.target) || edge.source === edge.target) continue;
    for (const id of [edge.source, edge.target]) incident.set(id, [...(incident.get(id) ?? []), edge]);
  }
  const roots = items.filter(item => !FINDINGS.has(item.entity_type) && incident.has(item.id))
    .sort((a, b) => (incident.get(b.id)?.length ?? 0) - (incident.get(a.id)?.length ?? 0) || a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
  const root = rootId ? roots.find(item => item.id === rootId) : roots[0];
  if (!root) return null;
  const links = incident.get(root.id)!;
  const neighbors = [...new Set(links.map(edge => edge.source === root.id ? edge.target : edge.source))]
    .map(id => byId.get(id)!).sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || a.label.localeCompare(b.label) || a.id.localeCompare(b.id));
  const labels = new Set<string>();
  const diverse = neighbors.filter(item => { if (labels.has(item.label)) return false; labels.add(item.label); return true; });
  const chosen = [...diverse, ...neighbors.filter(item => !diverse.includes(item))].slice(0, 3);
  const ids = new Set(chosen.map(item => item.id));
  const selectedLinks = links.filter(edge => ids.has(edge.source === root.id ? edge.target : edge.source));
  const flow = buildRollupFlowGraph([root, ...chosen], { edges: selectedLinks });
  const nodes = flow.nodes.map((node, i) => ({ ...node,
    position: { x: i === 0 ? 0 : 460, y: i === 0 ? (chosen.length - 1) * 90 : (i - 1) * 180 },
    data: { ...node.data, rollup: undefined, rollupCompact: false, highlighted: false,
      attributes: { ...node.data.attributes, rollup_is_container: false },
    },
  }));
  return { root, roots, nodes,
    edges: flow.edges.map(edge => ({ ...edge,
      // Context handles face left/right without reversing stored relationship direction.
      sourceHandle: edge.source === root.id ? null : "context",
      targetHandle: edge.target === root.id ? "context" : null,
      data: { ...edge.data, quietLabel: true, boundedOverview: true },
    })),
    availableRelationships: links.reduce((sum, edge) => sum + edge.count, 0),
    shownRelationships: selectedLinks.reduce((sum, edge) => sum + edge.count, 0),
  };
}
