"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api } from "@/lib/api";
import type { GatewayActivity } from "@/lib/gateway-activity";
import { policySetup, profileSetup, receiptStatus } from "@/lib/runtime-connection-status";
import { nowForRelativeTime } from "@/lib/relative-clock";

export function RuntimeConnectionStatus({ tenantId, streamState, events, onBlocked }: {
  tenantId: string | undefined; streamState: string; events: GatewayActivity[]; onBlocked: () => void;
}) {
  const [setup, setSetup] = useState<{ profiles: string; policy: string; readAt: string } | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [now, setNow] = useState(nowForRelativeTime);
  useEffect(() => {
    let active = true;
    const timer = setTimeout(() => {
      void Promise.allSettled([
        Promise.resolve().then(() => api.listRuntimeProfiles()),
        Promise.resolve().then(() => api.getGatewayStats(true)),
      ]).then(([profiles, stats]) => {
        if (active) setSetup({
          profiles: profileSetup(profiles.status === "fulfilled" ? profiles.value : null, tenantId, nowForRelativeTime()),
          policy: policySetup(stats.status === "fulfilled" ? stats.value : null), readAt: new Date(nowForRelativeTime()).toISOString(),
        });
      });
    }, 0);
    const clock = setInterval(() => setNow(nowForRelativeTime()), 15000);
    return () => { active = false; clearTimeout(timer); clearInterval(clock); };
  }, [tenantId, refresh]);
  const blocked = events.filter(event => event.decision === "deny").length;
  const cards = [
    ["Configured", setup?.profiles ?? "Loading setup…", "Saved setup snapshot; client installation is not verified."],
    ["Connected", streamState === "live" ? "Browser stream connected" : streamState === "connecting" ? "Connecting evidence stream" : "Evidence stream interrupted", "This is the browser-to-platform connection."],
    ["Enforcement", setup?.policy ?? "Loading policy setup…", "Application to endpoints is unverified. Inspect recorded decisions below."],
    ["Recently received", receiptStatus(events[0]?.ingested_at, now), "Receipt freshness is not proof of complete endpoint coverage."],
  ];
  return <section aria-label="Runtime connection status" className="my-4 rounded-lg border border-[var(--border-subtle)] p-3">
    <h4 className="mb-3 text-sm font-semibold">Runtime connection status</h4>
    <dl className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {cards.map(([label, value, hint]) => <div key={label} className="min-w-0"><dt className="text-xs text-[var(--text-secondary)]">{label}</dt><dd className="mt-1 break-words text-sm font-medium">{value}</dd><p className="mt-1 text-xs text-[var(--text-secondary)]">{hint}</p></div>)}
    </dl>
    <div className="mt-3 flex flex-wrap gap-2 text-xs">
      <Link className="graph-page-action" href="/runtime?tab=gateway">Configure clients and gateway</Link>
      <button className="graph-page-action" disabled={setup === null} onClick={() => { setSetup(null); setRefresh(value => value + 1); }}>Refresh setup</button>
      {blocked > 0 && <button className="graph-page-action" onClick={onBlocked}>Inspect {blocked} blocked {blocked === 1 ? "decision" : "decisions"}</button>}
    </div>
    <details className="mt-3 text-xs text-[var(--text-secondary)]"><summary className="cursor-pointer">Connection and coverage details</summary>
      <p className="mt-2">Opening this page does not install a proxy or enable enforcement. Configure the local client or shared gateway, send a permitted test call, then inspect its origin, profile and decision here. Scanning an endpoint or cloud account alone does not route its calls through the gateway.</p>
      <p className="mt-2">These links stay in the platform. A CLI HTML report opens in a browser only with --open. Setup is a control-plane snapshot{setup ? ` read at ${setup.readAt}` : ""}; activity counts cover the received buffer. No per-endpoint installation acknowledgement is available in this view.</p>
    </details>
  </section>;
}
