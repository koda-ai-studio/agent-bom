import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { INTERNET_ANCHOR_ID } from "@/lib/graph-internet-context";
import { semanticLayer } from "@/lib/graph-semantic-columns";

type Point = { x: number; y: number };
/** A bounded exposure story has stable reading lanes, not free-floating branches.
 * Geometry only: existing node IDs, edge direction and evidence are untouched. */
export function storyLanePlacement(nodes: Node<LineageNodeData>[], edges: Edge[], primary: readonly string[]) {
  if (nodes.length > 24 || primary[0] !== INTERNET_ANCHOR_ID || primary.length < 3) return undefined;
  edges = [...edges].sort((a, b) => a.source.localeCompare(b.source) || a.target.localeCompare(b.target) || a.id.localeCompare(b.id));
  const byId = new Map(nodes.map(node => [node.id, node]));
  const spine = new Set(primary.filter(id => byId.has(id) && semanticLayer(byId.get(id)!) !== "finding"));
  const layer = (id: string) => byId.has(id) ? semanticLayer(byId.get(id)!) : null;
  const access = new Set(nodes.filter(node => (layer(node.id) === "identity" || ["data_store", "dataStore", "dataset", "model"].includes(String(node.data.entityType ?? node.data.nodeType))) && !spine.has(node.id)).map(node => node.id));
  if (!access.size) return undefined;
  // Follow recorded access/data branches into resources whose generic asset kind
  // alone does not identify their role. Containment does not imply permission.
  for (let pass = 0; pass < nodes.length; pass++) for (const edge of edges) {
    if (access.has(edge.source) && !spine.has(edge.target) && layer(edge.target) !== "finding"
      && ["can_access", "has_permission", "assumes", "stores", "serves_model"].includes(String(edge.data?.relationship))) access.add(edge.target);
  }
  const owner = (id: string) => byId.get(id)?.data.displayTargetId ?? byId.get(id)?.data.readingOwner ?? edges.find(edge =>
    edge.target === id && ["vulnerable_to", "exhibits_drift", "has_finding"].includes(String(edge.data?.relationship)))?.source
    ?? edges.find(edge => edge.source === id && edge.data?.relationship === "affects")?.target;
  const band = (id: string) => spine.has(id) ? 0 : access.has(id) ? 1 : (layer(id) === "finding" || byId.get(id)?.type === "findingGroupNode") ? access.has(owner(id) ?? "") ? 2 : -1 : -1;
  return (positions: Map<string, Point>) => {
    // The reading spine uses equal hop spacing. Recorded side branches occupy
    // neighbouring columns rather than inheriting distant global type columns.
    const gap = 480;
    const placed = new Set<string>();
    [...spine].forEach((id, i) => { positions.set(id, { x: i * gap, y: 0 }); placed.add(id); });
    for (let pass = 0; pass < nodes.length; pass++) for (const edge of edges) {
      const from = positions.get(edge.source), to = positions.get(edge.target);
      if (placed.has(edge.source) && !placed.has(edge.target) && to && layer(edge.target) !== "finding" && byId.get(edge.target)?.type !== "findingGroupNode") {
        positions.set(edge.target, { ...to, x: from!.x + gap }); placed.add(edge.target);
      } else if (placed.has(edge.target) && !placed.has(edge.source) && from && layer(edge.source) !== "finding" && byId.get(edge.source)?.type !== "findingGroupNode") {
        positions.set(edge.source, { ...from, x: Math.max(gap, to!.x - gap) }); placed.add(edge.source);
      }
    }
    for (const node of nodes) {
      if (layer(node.id) !== "finding" && node.type !== "findingGroupNode") continue;
      const parent = positions.get(String(owner(node.id))), point = positions.get(node.id);
      if (parent && point) positions.set(node.id, { ...point, x: parent.x + gap });
    }
    const columns = new Map<number, string[]>();
    for (const node of nodes) {
      const point = positions.get(node.id);
      if (point) columns.set(point.x, [...(columns.get(point.x) ?? []), node.id]);
    }
    const rows = new Map<string, number>();
    const occupied = new Map<number, Set<number>>();
    const finding = (id: string) => layer(id) === "finding" || byId.get(id)?.type === "findingGroupNode";
    // Reserve the entry, infrastructure and access lanes first. Findings then
    // use the nearest free slot beside their owner, rather than forcing every
    // finding above the story and every identity finding below it.
    for (const [x, ids] of columns) {
      const used = new Set<number>(); occupied.set(x, used);
      for (const id of ids.filter(id => !finding(id)).sort((a, b) => Number(spine.has(b)) - Number(spine.has(a)) || Number(access.has(b)) - Number(access.has(a)) || a.localeCompare(b))) {
        let row = band(id);
        while (used.has(row)) row += row < 0 ? -1 : 1;
        used.add(row); rows.set(id, row);
      }
    }
    for (const [x, ids] of columns) {
      const used = occupied.get(x)!;
      for (const id of ids.filter(finding).sort((a, b) => Number(primary.includes(b)) - Number(primary.includes(a)) || a.localeCompare(b))) {
        const parentRow = rows.get(String(owner(id))) ?? 0;
        const candidates = [parentRow, ...Array.from({ length: nodes.length }, (_, i) => [parentRow - i - 1, parentRow + i + 1]).flat()];
        const row = candidates.find(row => !used.has(row))!;
        used.add(row); rows.set(id, row);
      }
    }
    for (const [id, row] of rows) positions.set(id, { x: positions.get(id)!.x, y: row * 260 });
  };
}
