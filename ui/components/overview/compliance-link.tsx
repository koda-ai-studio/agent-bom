"use client";

import { ArrowRight } from "lucide-react";
import Link from "next/link";

import { isStaticDemoRoute, useStaticDemoRoutes } from "@/lib/static-demo-routes";

/**
 * "View all frameworks" leads to the compliance page. The read-only demo only
 * records some pages; when compliance is not one of them the link is replaced
 * by a short note rather than a page that says it is not part of the demo.
 */
export function ViewAllFrameworksLink() {
  const demoRoutes = useStaticDemoRoutes();
  if (demoRoutes === undefined) return null;
  if (demoRoutes && !isStaticDemoRoute(demoRoutes, "/compliance")) {
    return <span data-testid="view-all-frameworks-unavailable" className="text-xs text-ink-tertiary">Full framework library in the installed product</span>;
  }
  return (
    <Link href="/compliance" aria-label="View all frameworks" title="View all frameworks" className="inline-flex min-h-8 min-w-8 items-center justify-center gap-1 text-xs text-emerald-700 dark:text-emerald-300">
      <span className="hidden sm:inline">View all frameworks</span><ArrowRight className="h-4 w-4" aria-hidden="true" />
    </Link>
  );
}
