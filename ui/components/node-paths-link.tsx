"use client";

import Link from "next/link";
import { Route } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";

/**
 * How many ranked attack paths pass through a node, linking to the path queue
 * focused on it. A neighbourhood view stops at its depth; the path view shows
 * the whole recorded chain (e.g. Snowflake table → stage → integration → S3).
 */
export function NodePathsLink({ scanId, nodeId }: { scanId?: string | undefined; nodeId: string }) {
  const [count, setCount] = useState<{ total: number; complete: boolean } | null>(null);
  useEffect(() => {
    if (!nodeId) return;
    let cancelled = false;
    setCount(null);
    api.getGraphAttackPaths({ ...(scanId ? { scanId } : {}), nodeId, limit: 1 })
      .then(page => { if (!cancelled) setCount({ total: page.pagination?.total ?? 0, complete: page.focus?.covers_all_matches !== false }); })
      .catch(() => { if (!cancelled) setCount(null); });
    return () => { cancelled = true; };
  }, [nodeId, scanId]);
  if (!count || count.total === 0) return null;
  const params = new URLSearchParams({ node: nodeId, path_view: "path" });
  if (scanId) params.set("scan", scanId);
  const label = `${count.total.toLocaleString()}${count.complete ? "" : "+"} attack ${count.total === 1 ? "path" : "paths"} through this node`;
  return (
    <Link href={`/security-graph?${params.toString()}`} aria-label={label}
      className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-outline bg-surface-muted px-3 py-2 text-xs font-medium text-foreground hover:border-outline-strong">
      <Route className="h-3.5 w-3.5" aria-hidden />
      {label}
    </Link>
  );
}
