"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { unknownGraphViewParam } from "@/lib/graph-view-params";

/** A graph link naming a view that does not exist says so, instead of quietly opening another view. */
export function GraphViewNotFound() {
  const params = useSearchParams();
  const unknown = unknownGraphViewParam(params);
  const scan = params.get("scan");
  const keep = scan ? `&scan=${encodeURIComponent(scan)}` : "";
  return (
    <section role="status" aria-labelledby="graph-view-not-found" data-testid="graph-view-not-found" className="mx-auto max-w-xl space-y-3 px-4 py-16 text-center text-sm">
      <h1 id="graph-view-not-found" className="text-lg font-semibold">This graph view does not exist</h1>
      <p className="text-ink-secondary">
        The link asks for {unknown ? <>{unknown.param} “{unknown.value}”</> : "a view"}, which the investigation graph does not have. Nothing was opened in its place.
      </p>
      <p className="flex flex-wrap justify-center gap-2">
        <Link href={`/security-graph?lens=attack-path${keep}`} className="graph-page-action">Back to attack paths</Link>
        <Link href={`/security-graph?lens=estate&rollup=1${keep}`} className="graph-page-action">Explore connections</Link>
      </p>
    </section>
  );
}
