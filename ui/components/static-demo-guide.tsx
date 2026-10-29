"use client";

import Link from "next/link";
import { ArrowRight, Boxes, GitBranch, ListChecks, Plug } from "lucide-react";
import { securityGraphHref } from "@/lib/page-links";
import { STATIC_DEMO_QUICKSTART_URL } from "@/lib/static-demo";

const STEPS = [
  { title: "Start with sources", icon: Plug, detail: "Inspect the sample cloud account and repository source, then follow their recorded scan handoffs.", label: "Inspect sample sources", href: "/connections?tab=sources" },
  { title: "Explore inventory", icon: Boxes, detail: "Browse collected assets and packages. Open an asset to inspect its recorded context.", label: "Explore sample inventory", href: "/inventory" },
  { title: "Prioritize findings", icon: ListChecks, detail: "Filter the sample findings by severity and scope, then inspect the affected components and remediation.", label: "Review sample findings", href: "/findings?lane=all&scan=scan-proof-ai-platform" },
  { title: "Follow the evidence", icon: GitBranch, detail: "Explore relationships and paths across agents, packages, identities and cloud resources. Recorded reachability does not establish exploitation.", label: "Investigate sample relationships", href: securityGraphHref({ scan: "scan-proof-ai-platform" }) },
];

/** A usable guide for the bundled estate; the live demo service is not part of the export. */
export function StaticDemoGuide() {
  return <section className="space-y-6">
    <header className="space-y-2">
      <p className="text-xs font-medium uppercase tracking-widest text-ink-secondary">Demo walkthrough</p>
      <h1 className="text-2xl font-semibold text-foreground">Explore the sample estate</h1>
      <p className="max-w-3xl text-sm leading-6 text-ink-secondary">Follow the same evidence from source to inventory, finding and graph. This snapshot contains labelled sample data; collecting your own evidence requires a self-hosted installation.</p>
    </header>
    <ol className="grid gap-4 md:grid-cols-2">
      {STEPS.map(({ title, icon: Icon, detail, label, href }, index) => <li key={href} className="flex flex-col gap-3 rounded-xl border border-outline bg-surface p-5">
        <div className="flex items-center gap-3"><Icon className="h-5 w-5 text-emerald-600 dark:text-emerald-400" /><h2 className="font-semibold">{index + 1}. {title}</h2></div>
        <p className="flex-1 text-sm leading-6 text-ink-secondary">{detail}</p>
        <Link href={href} className="inline-flex items-center gap-2 text-sm font-medium text-emerald-700 dark:text-emerald-300">{label}<ArrowRight className="h-4 w-4" /></Link>
      </li>)}
    </ol>
    <a href={STATIC_DEMO_QUICKSTART_URL} className="inline-flex items-center gap-2 text-sm font-medium underline underline-offset-4">Run agent-bom on your environment<ArrowRight className="h-4 w-4" /></a>
  </section>;
}
