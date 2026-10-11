"use client";

import Link from "next/link";
import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { GatewayFeedPanel } from "@/app/gateway/GatewayFeedPanel";

function ActivityPageContent() {
  const params = useSearchParams();
  return <div className="mx-auto max-w-7xl space-y-5">
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div><h1 className="text-2xl font-semibold tracking-tight">Live Activity</h1><p className="mt-2 text-sm text-[var(--text-secondary)]">Review runtime decisions. Select an event to inspect its evidence and investigate.</p></div>
      <div className="flex flex-wrap gap-2"><Link className="graph-page-action" href="/runtime?tab=gateway">Runtime controls</Link><Link className="graph-page-action" href="/traces">Trace explorer</Link></div>
    </header>
    <GatewayFeedPanel initialFilter={params.get("filter") ?? ""} initialSearch={params.get("q") ?? ""} />
  </div>;
}
export default function ActivityPage() {
  return <Suspense fallback={<p>Loading activity…</p>}><ActivityPageContent /></Suspense>;
}
