"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { SearchX } from "lucide-react";

import { unknownGraphViewParam } from "@/lib/graph-view-params";

const PARAM_NAMES: Record<string, string> = { lens: "view", flow: "flow", step: "investigation step", map_view: "map view" };

/** A graph link naming a view that does not exist says so, instead of quietly opening another view. */
export function GraphViewNotFound({ path }: { path?: string | undefined }) {
  const params = useSearchParams();
  const unknown = unknownGraphViewParam(params);
  const scan = params.get("scan");
  const keep = scan ? `&scan=${encodeURIComponent(scan)}` : "";
  const subject = unknown ? `${PARAM_NAMES[unknown.param] ?? unknown.param} “${unknown.value}”` : path ? `page ${path}` : "view";
  return (
    <section role="status" aria-labelledby="graph-view-not-found" data-testid="graph-view-not-found"
      className="mx-auto flex max-w-xl flex-col items-center gap-3 px-4 py-16 text-center">
      <SearchX className="h-10 w-10 text-ink-tertiary" aria-hidden="true" />
      <h1 id="graph-view-not-found" className="text-lg font-semibold text-foreground">This graph view does not exist</h1>
      <p className="text-sm text-ink-secondary">The link asks for the {subject}, which the investigation graph does not have. Nothing was opened in its place.</p>
      <div className="flex flex-wrap justify-center gap-2 pt-1">
        <Link href={`/security-graph?lens=attack-path${keep}`}
          className="rounded-md bg-[color:var(--accent)] px-4 py-2 text-sm font-medium text-[color:var(--accent-contrast)] hover:bg-[color:var(--accent-strong)]">
          Back to attack paths
        </Link>
        <Link href={`/security-graph?lens=estate&rollup=1${keep}`}
          className="rounded-md border border-outline px-4 py-2 text-sm font-medium text-foreground hover:bg-surface-elevated">
          Explore connections
        </Link>
      </div>
    </section>
  );
}
