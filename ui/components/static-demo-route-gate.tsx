"use client";

import { isStaticDemoRoute, useStaticDemoRoutes } from "@/lib/static-demo-routes";
import { STATIC_DEMO_QUICKSTART_URL } from "@/lib/static-demo";

export const STATIC_DEMO_UNAVAILABLE_MESSAGE =
  "This page isn't part of the read-only demo — install agent-bom to see it on your own data";

/** In the public demo, pages without recorded sample data show this instead of an error or empty state. */
export function StaticDemoRouteGate({ pathname, children }: { pathname: string; children: React.ReactNode }) {
  const routes = useStaticDemoRoutes();
  if (routes === null) return <>{children}</>;
  if (routes === undefined) return null;
  if (isStaticDemoRoute(routes, pathname)) return <>{children}</>;
  return (
    <section
      aria-label="Not part of the demo"
      data-testid="static-demo-unavailable"
      className="mx-auto mt-6 max-w-xl rounded-xl border border-outline bg-surface p-6 text-center [overflow-wrap:anywhere]"
    >
      <h1 className="text-lg font-semibold text-foreground">{STATIC_DEMO_UNAVAILABLE_MESSAGE}</h1>
      <p className="mt-2 text-sm text-ink-secondary">
        The pages in the navigation are the ones with labelled sample data.
      </p>
      <a href={STATIC_DEMO_QUICKSTART_URL} className="mt-4 inline-block font-semibold text-[color:var(--accent)] underline underline-offset-2">
        Open the quick start
      </a>
    </section>
  );
}
