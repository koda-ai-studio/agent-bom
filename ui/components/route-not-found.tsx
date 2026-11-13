"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ShieldAlert } from "lucide-react";

import { GraphViewNotFound } from "@/components/graph-view-not-found";

const GRAPH_ROUTE = /^\/(?:graph|security-graph)(?:\/|$)/;

/** An unknown address under the graph routes gets the graph's own way back; anything else, the overview. */
export function RouteNotFound() {
  const pathname = usePathname() ?? "";
  if (GRAPH_ROUTE.test(pathname)) return <GraphViewNotFound path={pathname} />;
  return (
    <div className="flex flex-col items-center justify-center h-[80vh] gap-4 text-center">
      <ShieldAlert className="w-12 h-12 text-[var(--text-tertiary)]" />
      <h1 className="text-lg font-semibold text-[var(--foreground)]">Page not found</h1>
      <p className="text-sm text-[var(--text-secondary)]">The page you are looking for does not exist.</p>
      <Link
        href="/"
        className="px-4 py-2 bg-[color:var(--accent)] hover:bg-[color:var(--accent-strong)] rounded-md text-sm text-[color:var(--accent-contrast)] transition-colors"
      >
        Back to Overview
      </Link>
    </div>
  );
}
