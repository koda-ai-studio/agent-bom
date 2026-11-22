"use client";

import { useEffect, useState } from "react";
import type { components } from "@/lib/api-schema.generated";
import type { Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { get } from "@/lib/api-transport";

export type GraphNodeAggregate = components["schemas"]["GraphNodeAggregate"];
type Response = components["schemas"]["GraphNodeAggregatesResponse"];
const EMPTY: ReadonlyMap<string, GraphNodeAggregate> = new Map();

/** One bounded read per selected path or visible context. Missing or stale records have no badge. */
export function useGraphNodeAggregates(scanId: string | undefined, hops: readonly string[], generation?: string): ReadonlyMap<string, GraphNodeAggregate> {
  const ids = [...new Set(hops)];
  const params = new URLSearchParams();
  if (scanId) params.set("scan_id", scanId);
  if (generation) params.set("snapshot_generation", generation);
  for (const id of ids) params.append("node_id", id);
  const key = scanId && ids.length > 0 && ids.length <= 25 ? `/v1/graph/node-aggregates?${params}` : null;
  const [loaded, setLoaded] = useState<{ key: string; rows: ReadonlyMap<string, GraphNodeAggregate> } | null>(null);
  useEffect(() => {
    if (!key) return;
    const controller = new AbortController();
    void get<Response>(key, { signal: controller.signal }).then(response => {
      if (controller.signal.aborted || response.scan_id !== scanId || generation && response.snapshot_generation !== generation) return;
      const requested = new Set(new URLSearchParams(key.split("?")[1]).getAll("node_id"));
      const missing = new Set(response.missing_node_ids ?? []);
      const rows = new Map((response.aggregates ?? []).filter(row => requested.has(row.node_id) && !missing.has(row.node_id)).map(row => [row.node_id, row]));
      setLoaded({ key, rows });
    }).catch(() => { /* Failed evidence reads never become a locally counted badge. */ });
    return () => controller.abort();
  }, [generation, key, scanId]);
  return key && loaded?.key === key ? loaded.rows : EMPTY;
}

/** Missing records never become locally counted badges. */
export function withGraphNodeAggregates(nodes: Node<LineageNodeData>[], records: ReadonlyMap<string, GraphNodeAggregate>): Node<LineageNodeData>[] {
  return nodes.map(node => {
    const record = records.get(node.id);
    return record ? { ...node, data: { ...node.data, findingAggregate: record.aggregate } } : node;
  });
}
