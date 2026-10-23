"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ListFilter, Network } from "lucide-react";

import { api } from "@/lib/api";
import type { UnifiedNode } from "@/lib/graph-schema";

const FINDING_TYPES = new Set(["misconfiguration", "vulnerability"]);
const VISIBLE_RESOURCES = 10;
const LINK_CLASS =
  "inline-flex items-center gap-1 rounded-md border border-[color:var(--border-subtle)] px-2 py-1 text-xs text-[color:var(--text-secondary)] transition hover:border-[color:var(--border-strong)] hover:text-[color:var(--foreground)]";

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

/** The exact finding when the graph recorded one on this resource, otherwise a search for it. */
function resourceFindingsHref(resourceId: string, findingIds: readonly string[] | undefined): string {
  const [first] = findingIds ?? [];
  return first ? `/findings?${new URLSearchParams({ finding: first })}` : `/findings?${new URLSearchParams({ q: resourceId })}`;
}

type Resolution = { node: Pick<UnifiedNode, "id" | "label"> | null } | "loading";

/** A scan-only resource id is a provider spelling; search the graph for the node it names. */
function useResolvedNode(resourceId: string, graphBacked: boolean): Resolution {
  const [resolution, setResolution] = useState<Resolution>(graphBacked ? { node: { id: resourceId, label: resourceId } } : "loading");
  useEffect(() => {
    if (graphBacked) return;
    let cancelled = false;
    api.searchGraph(resourceId, { limit: 5 })
      .then((response) => { if (!cancelled) setResolution({ node: bestResourceNode(resourceId, response.results ?? []) }); })
      .catch(() => { if (!cancelled) setResolution({ node: null }); });
    return () => { cancelled = true; };
  }, [resourceId, graphBacked]);
  return resolution;
}

function ResourceRow({ resourceId, graphBacked, findingIds }: { resourceId: string; graphBacked: boolean; findingIds?: readonly string[] | undefined }) {
  const resolution = useResolvedNode(resourceId, graphBacked);
  const node = resolution === "loading" ? null : resolution.node;
  const label = node?.label || resourceId;
  return (
    <li className="flex flex-wrap items-center gap-x-2 gap-y-1 py-1.5">
      <span className="min-w-0 truncate font-mono text-xs text-[color:var(--foreground)]" title={resourceId}>{resourceId}</span>
      <span className="ml-auto flex shrink-0 items-center gap-1">
        {node ? (
          <Link href={resourceGraphHref(node.id)} aria-label={`Open ${label} in the graph`} className={LINK_CLASS}>
            <Network className="h-3.5 w-3.5" />Graph
          </Link>
        ) : resolution === "loading" ? null : (
          <span className="text-xs text-[color:var(--text-tertiary)]">Not in the current graph</span>
        )}
        <Link href={resourceFindingsHref(resourceId, findingIds)} aria-label={`Findings on ${resourceId}`} className={LINK_CLASS}>
          <ListFilter className="h-3.5 w-3.5" />Findings
        </Link>
      </span>
    </li>
  );
}

/** The graph node that records this control's result, for the whole-control view. */
export function CisControlGraphLink({ checkId, nodeId }: { checkId: string; nodeId: string }) {
  return (
    <Link href={resourceGraphHref(nodeId)} aria-label={`Open control ${checkId} in the graph`} className={LINK_CLASS}>
      <Network className="h-3.5 w-3.5" />Open control in graph
    </Link>
  );
}

/**
 * The resources a failing CIS check names. Graph-backed ids are graph node ids and link directly;
 * a scan-only id is resolved to its graph node when the current graph has it.
 */
export function CisCheckResources({
  checkId,
  resourceIds,
  graphBacked = false,
  findingIds,
}: {
  checkId: string;
  resourceIds: readonly string[];
  graphBacked?: boolean;
  findingIds?: Readonly<Record<string, string[]>> | undefined;
}) {
  const [expanded, setExpanded] = useState(false);
  if (resourceIds.length === 0) return null;
  const shown = expanded ? resourceIds : resourceIds.slice(0, VISIBLE_RESOURCES);
  const hidden = resourceIds.length - shown.length;
  return (
    <div>
      <p className="text-xs text-[color:var(--text-tertiary)]">
        {resourceIds.length} affected resource{resourceIds.length === 1 ? "" : "s"}
        {graphBacked ? " in the current graph" : ""}
      </p>
      <ul aria-label={`Resources failing ${checkId}`} className="divide-y divide-[color:var(--border-subtle)]">
        {shown.map((id) => <ResourceRow key={id} resourceId={id} graphBacked={graphBacked} findingIds={findingIds?.[id]} />)}
      </ul>
      {hidden > 0 ? (
        <button type="button" onClick={() => setExpanded(true)} className="mt-1 text-xs text-[color:var(--text-secondary)] underline-offset-2 hover:underline">
          Show all {resourceIds.length} resources
        </button>
      ) : null}
    </div>
  );
}
