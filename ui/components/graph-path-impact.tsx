"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { GraphImpactResponse } from "@/lib/api-types";
import { buildGraphInvestigationHref } from "@/lib/attack-paths";
import { countLabel } from "@/lib/count-label";
import { GraphImpactGroups } from "@/components/graph-impact-groups";

const IMPACT_DEPTH = 4;
type Direction = "reverse" | "forward";
const COPY: Record<Direction, { noun: string; step: string; toggle: string; explore: string; reach: string }> = {
  reverse: { noun: "upstream related node", step: "reverse step", toggle: "Upstream · depends on this", explore: "Explore upstream relationships", reach: "" },
  forward: { noun: "downstream node this can reach", step: "forward step", toggle: "Downstream · what this can reach", explore: "Explore downstream relationships", reach: "can reach" },
};

export function GraphPathImpact({ nodeId, label, scanId, tenantId, snapshotGeneration }: {
  nodeId: string; label: string; scanId: string; tenantId: string;
  snapshotGeneration?: string | null | undefined;
}) {
  const [direction, setDirection] = useState<Direction>("reverse");
  const scope = JSON.stringify([nodeId, scanId, tenantId, snapshotGeneration, direction]);
  const [state, setState] = useState<{ scope: string; result?: GraphImpactResponse; error?: boolean } | null>(null);
  const [attempt, setAttempt] = useState(0);
  const current = state?.scope === scope ? state : null;
  useEffect(() => {
    const controller = new AbortController();
    setState(null);
    void api.getGraphImpact(nodeId, scanId, IMPACT_DEPTH, { signal: controller.signal }, direction).then(result => {
      if (controller.signal.aborted) return;
      if (result.node_id !== nodeId || result.scan_id !== scanId || result.tenant_id !== tenantId || !result.snapshot_generation
        || (snapshotGeneration && result.snapshot_generation !== snapshotGeneration)) throw new Error("Scope changed");
      setState({ scope, result });
    }).catch(() => { if (!controller.signal.aborted) setState({ scope, error: true }); });
    return () => controller.abort();
  }, [nodeId, scanId, tenantId, snapshotGeneration, scope, attempt, direction]);
  const impact = current?.result;
  const copy = COPY[direction];
  return <section aria-label="Path impact" className="rounded-xl border border-violet-500/30 bg-violet-500/5 p-4 text-sm text-foreground">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <h3 className="font-semibold">Potential impact · {label}</h3>
      <div role="radiogroup" aria-label="Impact direction" className="inline-flex rounded-lg border border-outline bg-surface p-0.5 text-xs">
        {(["reverse", "forward"] as const).map(value => <button key={value} type="button" role="radio" aria-checked={direction === value}
          onClick={() => setDirection(value)}
          className={`rounded-md px-2.5 py-1 font-medium ${direction === value ? "bg-violet-500/15 text-foreground" : "text-ink-secondary hover:text-foreground"}`}>
          {COPY[value].toggle}
        </button>)}
      </div>
    </div>
    {!current && <p role="status" className="mt-2 text-ink-secondary">Reading {direction === "reverse" ? "upstream" : "downstream"} relationships…</p>}
    {current?.error && <div role="alert" className="mt-2 text-ink-secondary">Impact evidence is unavailable or the snapshot changed. Refresh the snapshot or <button type="button" className="underline" onClick={() => setAttempt(value => value + 1)}>retry impact</button>.</div>}
    {impact && <div className="mt-2 space-y-2">
      <p className="font-medium">{impact.completeness?.complete === true ? "" : "At least "}{countLabel(impact.affected_count, copy.noun)} · up to {countLabel(impact.max_depth_reached, copy.step)} from this node</p>
      <GraphImpactGroups impact={impact} scanId={impact.scan_id ?? scanId} />
      <p className="text-xs text-ink-secondary">Traversal depth is counted from this node, not along the selected path. {direction === "reverse" ? "Reverse" : "Forward"} graph connections within four steps, including links not enabled for traversal. They do not establish execution or compromise. Source collection coverage is unknown.{impact.completeness?.complete !== true && " This is a lower bound because the graph query is incomplete."}</p>
      <Link className="inline-flex rounded-lg border border-outline bg-surface px-3 py-2 text-xs font-medium hover:bg-surface-muted"
        href={buildGraphInvestigationHref({ rootId: nodeId, scanId: impact.scan_id, direction, depth: IMPACT_DEPTH })}>{copy.explore}</Link>
    </div>}
  </section>;
}
