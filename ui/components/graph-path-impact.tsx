"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { GraphImpactResponse } from "@/lib/api-types";
import { buildGraphInvestigationHref } from "@/lib/attack-paths";
import { prettifyReachabilityType } from "@/lib/graph-reachability";

export function GraphPathImpact({ nodeId, label, scanId, tenantId, snapshotGeneration }: {
  nodeId: string; label: string; scanId: string; tenantId: string;
  snapshotGeneration?: string | null | undefined;
}) {
  const scope = JSON.stringify([nodeId, scanId, tenantId, snapshotGeneration]);
  const [state, setState] = useState<{ scope: string; result?: GraphImpactResponse; error?: boolean } | null>(null);
  const [attempt, setAttempt] = useState(0);
  const current = state?.scope === scope ? state : null;
  useEffect(() => {
    const controller = new AbortController();
    setState(null);
    void api.getGraphImpact(nodeId, scanId, 4, { signal: controller.signal }).then(result => {
      if (controller.signal.aborted) return;
      if (result.node_id !== nodeId || result.scan_id !== scanId || result.tenant_id !== tenantId || !result.snapshot_generation
        || (snapshotGeneration && result.snapshot_generation !== snapshotGeneration)) throw new Error("Scope changed");
      setState({ scope, result });
    }).catch(() => { if (!controller.signal.aborted) setState({ scope, error: true }); });
    return () => controller.abort();
  }, [nodeId, scanId, tenantId, snapshotGeneration, scope, attempt]);
  const impact = current?.result;
  return <section aria-label="Path impact" className="rounded-xl border border-violet-500/30 bg-violet-500/5 p-4 text-sm text-foreground">
    <h3 className="font-semibold">Potential impact · {label}</h3>
    {!current && <p role="status" className="mt-2 text-ink-secondary">Reading upstream relationships…</p>}
    {current?.error && <div role="alert" className="mt-2 text-ink-secondary">Impact evidence is unavailable or the snapshot changed. Refresh the snapshot or <button type="button" className="underline" onClick={() => setAttempt(value => value + 1)}>retry impact</button>.</div>}
    {impact && <div className="mt-2 space-y-2">
      <p className="font-medium">{impact.completeness?.complete === true ? "" : "At least "}{impact.affected_count} upstream related node{impact.affected_count === 1 ? "" : "s"} · {impact.max_depth_reached} recorded hops</p>
      <div className="flex flex-wrap gap-2 text-xs">{Object.entries(impact.affected_by_type).map(([type, count]) => <span key={type} className="rounded border border-outline bg-surface px-2 py-1">{prettifyReachabilityType(type)} · {count}</span>)}</div>
      <p className="text-xs text-ink-secondary">Reverse graph connections within four hops, including links not enabled for traversal. They do not establish execution or compromise. Source collection coverage is unknown.{impact.completeness?.complete !== true && " This is a lower bound because the graph query is incomplete."}</p>
      <Link className="inline-flex rounded-lg border border-outline bg-surface px-3 py-2 text-xs font-medium hover:bg-surface-muted" href={buildGraphInvestigationHref({ rootId: nodeId, scanId: impact.scan_id, direction: "reverse" })}>Explore upstream relationships</Link>
    </div>}
  </section>;
}
