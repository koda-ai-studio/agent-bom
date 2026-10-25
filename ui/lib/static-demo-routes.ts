import { useEffect, useState } from "react";

import { isStaticDemo, staticDemoBasePath } from "./static-demo";

/** Routes the generator recorded complete sample data for (`demo-data/routes.json`). */
export type StaticDemoRoutes = ReadonlySet<string>;

let pending: Promise<StaticDemoRoutes | null> | null = null;

function normalize(path: string): string {
  const pathname = path.split(/[?#]/)[0] || "/";
  return pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
}

/** Null when the manifest cannot be read; the demo then renders pages as built. */
export function loadStaticDemoRoutes(): Promise<StaticDemoRoutes | null> {
  pending ??= fetch(`${staticDemoBasePath()}/demo-data/routes.json`, { credentials: "same-origin" })
    .then(async (res) => {
      if (!res.ok) return null;
      const body = (await res.json()) as { routes?: unknown };
      return Array.isArray(body.routes) ? new Set(body.routes.filter((r): r is string => typeof r === "string").map(normalize)) : null;
    })
    .catch(() => null);
  return pending;
}

export function isStaticDemoRoute(routes: StaticDemoRoutes, path: string): boolean {
  return routes.has(normalize(path));
}

/** `undefined` while loading, `null` outside the demo or without a manifest. */
export function useStaticDemoRoutes(): StaticDemoRoutes | null | undefined {
  const demo = isStaticDemo();
  const [routes, setRoutes] = useState<StaticDemoRoutes | null | undefined>(demo ? undefined : null);
  useEffect(() => {
    if (!demo) return;
    let active = true;
    void loadStaticDemoRoutes().then((value) => { if (active) setRoutes(value); });
    return () => { active = false; };
  }, [demo]);
  return routes;
}
