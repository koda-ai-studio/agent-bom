"use client";

import Link from "next/link";
import { useState } from "react";

import type { GraphImpactResponse } from "@/lib/api-types";
import { buildGraphInvestigationHref } from "@/lib/attack-paths";
import { prettifyReachabilityType } from "@/lib/graph-reachability";

type Detail = NonNullable<GraphImpactResponse["affected_nodes_detail"]>[number];

/** One chip per entity type; a chip opens the nodes behind its count. */
export function GraphImpactGroups({ impact, scanId }: { impact: GraphImpactResponse; scanId: string }) {
  const [open, setOpen] = useState<string | null>(null);
  const detail = impact.affected_nodes_detail ?? [];
  const nodes = open ? detail.filter((node) => node.entity_type === open) : [];
  const listed = open ? nodes.length : 0;
  const total = open ? impact.affected_by_type[open] ?? 0 : 0;
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap gap-2 text-xs">
        {Object.entries(impact.affected_by_type).map(([type, count]) => (
          <button key={type} type="button" aria-expanded={open === type} onClick={() => setOpen(open === type ? null : type)}
            className={`rounded border px-2 py-1 transition hover:bg-surface-muted ${open === type ? "border-violet-500/60 bg-violet-500/10" : "border-outline bg-surface"}`}>
            {prettifyReachabilityType(type)} · {count}
          </button>
        ))}
      </div>
      {open ? (
        <ul aria-label={`${prettifyReachabilityType(open)} nodes`} className="max-h-60 divide-y divide-outline overflow-y-auto rounded-lg border border-outline bg-surface">
          {nodes.map((node: Detail) => (
            <li key={node.id} className="flex items-center justify-between gap-3 px-3 py-2 text-xs">
              <Link className="min-w-0 truncate font-medium text-accent-mint hover:underline" title={node.id}
                href={buildGraphInvestigationHref({ rootId: node.id, rootLabel: node.label, scanId, direction: "both" })}>
                {node.label}
              </Link>
              <span className="shrink-0 text-ink-secondary">{node.depth} step{node.depth === 1 ? "" : "s"}</span>
            </li>
          ))}
          {listed < total ? <li className="px-3 py-2 text-xs text-ink-secondary">{total - listed} more not listed; open the full lineage to see them.</li> : null}
        </ul>
      ) : null}
    </div>
  );
}
