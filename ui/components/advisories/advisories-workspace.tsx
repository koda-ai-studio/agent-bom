"use client";

import { useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Crosshair, ShieldAlert } from "lucide-react";

import { PageLaneHeader } from "@/components/page-lane";

import { AdvisoryAffectedView } from "./advisory-affected-view";
import { AdvisoryDeclareForm } from "./advisory-declare-form";
import { OperatorAdvisoryList } from "./operator-advisory-list";

type Tab = "affected" | "declare";

const TABS: { key: Tab; label: string; icon: typeof Crosshair }[] = [
  { key: "affected", label: "Affected assets", icon: Crosshair },
  { key: "declare", label: "Emergency advisories", icon: ShieldAlert },
];

function DeclareTab() {
  const [refreshKey, setRefreshKey] = useState(0);
  return (
    <div className="grid min-w-0 gap-6 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
      <section aria-labelledby="declare-heading" className="min-w-0 space-y-3">
        <div>
          <h2 id="declare-heading" className="text-base font-semibold text-foreground">Declare an emergency advisory</h2>
          <p className="mt-1 text-sm text-ink-secondary">Act on a disclosure before a feed publishes it. Matches carry operator-advisory provenance; once a feed record with the same id or alias arrives, the feed record wins.</p>
        </div>
        <AdvisoryDeclareForm onDeclared={() => setRefreshKey(key => key + 1)} />
      </section>
      <section aria-labelledby="declared-heading" className="min-w-0 space-y-3">
        <h2 id="declared-heading" className="text-base font-semibold text-foreground">Declared advisories</h2>
        <OperatorAdvisoryList refreshKey={refreshKey} />
      </section>
    </div>
  );
}

/** Advisories: per-asset "am I affected?" answers and operator-declared emergency advisories. */
export function AdvisoriesWorkspace() {
  const router = useRouter();
  const pathname = usePathname() || "/advisories";
  const searchParams = useSearchParams();
  const tab: Tab = searchParams.get("tab") === "declare" ? "declare" : "affected";

  return (
    <div className="min-w-0 space-y-5">
      <PageLaneHeader
        lane="command"
        title="Advisories"
        subtitle="Which assets does a CVE or emergency advisory affect? Answered from stored scans, per asset, with the patch target. Nothing is rescanned."
      />
      <div role="tablist" aria-label="Advisory views" className="flex flex-wrap gap-2 border-b border-outline pb-3">
        {TABS.map(item => {
          const Icon = item.icon;
          const selected = item.key === tab;
          return (
            <button key={item.key} type="button" role="tab" aria-selected={selected}
              onClick={() => router.replace(item.key === "affected" ? pathname : `${pathname}?tab=declare`, { scroll: false })}
              className={`inline-flex items-center gap-2 rounded-xl border px-3 py-1.5 text-sm font-medium transition-colors ${selected
                ? "border-[color:var(--accent-border)] bg-[color:var(--accent-soft)] text-[color:var(--accent)]"
                : "border-outline bg-surface-muted text-ink-secondary hover:border-outline-strong hover:text-foreground"}`}>
              <Icon className="h-4 w-4" aria-hidden />
              {item.label}
            </button>
          );
        })}
      </div>
      <div role="tabpanel" aria-label={tab === "affected" ? "Affected assets" : "Emergency advisories"}>
        {tab === "affected" ? <AdvisoryAffectedView /> : <DeclareTab />}
      </div>
    </div>
  );
}
