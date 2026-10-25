import { useEffect, useState } from "react";

import { nowForRelativeTime, setDemoSnapshotAt } from "./relative-clock";
import { isStaticDemo, staticDemoBasePath } from "./static-demo";

/** Routes the generator recorded complete sample data for (`demo-data/routes.json`). */
export type StaticDemoRoutes = ReadonlySet<string>;

type StaticDemoManifest = { routes: StaticDemoRoutes; snapshotAt: number | null };

let pending: Promise<StaticDemoManifest | null> | null = null;

function normalize(path: string): string {
  const pathname = path.split(/[?#]/)[0] || "/";
  return pathname.length > 1 ? pathname.replace(/\/+$/, "") : pathname;
}

function loadManifest(): Promise<StaticDemoManifest | null> {
  pending ??= fetch(`${staticDemoBasePath()}/demo-data/routes.json`, { credentials: "same-origin" })
    .then(async (res) => {
      if (!res.ok) return null;
      const body = (await res.json()) as { routes?: unknown; snapshot_at?: unknown };
      if (!Array.isArray(body.routes)) return null;
      const snapshotAt = typeof body.snapshot_at === "string" ? Date.parse(body.snapshot_at) : Number.NaN;
      setDemoSnapshotAt(Number.isNaN(snapshotAt) ? null : snapshotAt);
      return {
        routes: new Set(body.routes.filter((r): r is string => typeof r === "string").map(normalize)),
        snapshotAt: Number.isNaN(snapshotAt) ? null : snapshotAt,
      };
    })
    .catch(() => null);
  return pending;
}

/** Null when the manifest cannot be read; the demo then renders pages as built. */
export async function loadStaticDemoRoutes(): Promise<StaticDemoRoutes | null> {
  return (await loadManifest())?.routes ?? null;
}

/**
 * The clock for relative ages: the sample snapshot's time in the static demo
 * (its data is dated then), the wall clock everywhere else.
 */
export function demoNow(snapshotAt: number | null | undefined): number {
  return snapshotAt ?? nowForRelativeTime();
}

/** Snapshot time in the demo; `undefined` while loading, `null` outside the demo or without one. */
export function useStaticDemoSnapshotAt(): number | null | undefined {
  const demo = isStaticDemo();
  const [snapshotAt, setSnapshotAt] = useState<number | null | undefined>(demo ? undefined : null);
  useEffect(() => {
    if (!demo) return;
    let active = true;
    void loadManifest().then((manifest) => { if (active) setSnapshotAt(manifest?.snapshotAt ?? null); });
    return () => { active = false; };
  }, [demo]);
  return snapshotAt;
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
