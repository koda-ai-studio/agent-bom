"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ListFilter, Network } from "lucide-react";

import { api } from "@/lib/api";
import type { UnifiedNode } from "@/lib/graph-schema";

const FINDING_TYPES = new Set(["misconfiguration", "vulnerability"]);

/** The asset node a CIS resource id names: an exact or containing label, assets before the finding nodes about them. */
export function bestResourceNode(resourceId: string, nodes: readonly Pick<UnifiedNode, "id" | "entity_type" | "label">[]) {
  const needle = resourceId.toLowerCase();
  const named = nodes.filter((node) => (node.label ?? "").toLowerCase().includes(needle) || node.id.toLowerCase().endsWith(needle));
  const rank = (node: (typeof named)[number]) =>
    (FINDING_TYPES.has(String(node.entity_type)) ? 2 : 0) + ((node.label ?? "").toLowerCase().startsWith(needle) ? 0 : 1);
  return [...named].sort((a, b) => rank(a) - rank(b))[0] ?? null;
}

export function resourceGraphHref(nodeId: string): string {
  return `/security-graph?${new URLSearchParams({ lens: "lineage", investigate: "1", root: nodeId, node: nodeId })}`;
}

type Resolution = { node: Pick<UnifiedNode, "id" | "label"> | null } | "loading";

function ResourceRow({ resourceId }: { resourceId: string }) {
  const [resolution, setResolution] = useState<Resolution>("loading");
  useEffect(() => {
    let cancelled = false;
    api.searchGraph(resourceId, { limit: 5 })
      .then((response) => { if (!cancelled) setResolution({ node: bestResourceNode(resourceId, response.results ?? []) }); })
      .catch(() => { if (!cancelled) setResolution({ node: null }); });
    return () => { cancelled = true; };
  }, [resourceId]);
  const node = resolution === "loading" ? null : resolution.node;
  const label = node?.label || resourceId;
  return (
    <li className="flex flex-wrap items-center gap-x-2 gap-y-1 py-1.5">
      <span className="min-w-0 truncate font-mono text-xs text-[color:var(--foreground)]" title={resourceId}>{resourceId}</span>
      <span className="ml-auto flex shrink-0 items-center gap-1">
        {node ? (
          <Link
            href={resourceGraphHref(node.id)}
            aria-label={`Open ${label} in the graph`}
            className="inline-flex items-center gap-1 rounded-md border border-[color:var(--border-subtle)] px-2 py-1 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
          >
            <Network className="h-3.5 w-3.5" />Graph
          </Link>
        ) : resolution === "loading" ? null : (
          <span className="text-xs text-[color:var(--text-tertiary)]">Not in the current graph</span>
        )}
        <Link
          href={`/findings?${new URLSearchParams({ q: resourceId })}`}
          aria-label={`Findings on ${resourceId}`}
          className="inline-flex items-center gap-1 rounded-md border border-[color:var(--border-subtle)] px-2 py-1 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]"
        >
          <ListFilter className="h-3.5 w-3.5" />Findings
        </Link>
      </span>
    </li>
  );
}

/** The resources a failing CIS check names, each resolved to its graph node when the current graph has it. */
export function CisCheckResources({ checkId, resourceIds }: { checkId: string; resourceIds: readonly string[] }) {
  if (resourceIds.length === 0) return null;
  return (
    <div>
      <p className="text-xs text-[color:var(--text-tertiary)]">Affected resource{resourceIds.length === 1 ? "" : "s"}</p>
      <ul aria-label={`Resources failing ${checkId}`} className="divide-y divide-[color:var(--border-subtle)]">
        {resourceIds.map((id) => <ResourceRow key={id} resourceId={id} />)}
      </ul>
    </div>
  );
}
