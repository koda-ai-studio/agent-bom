"use client";

import Link from "next/link";
import { useState } from "react";
import type { ScanResult } from "@/lib/api";
import { FirstScanGuide } from "@/components/first-scan-guide";
import { OverviewDashboard } from "@/components/overview-dashboard";

export default function GetStartedPage() {
  // Local previews live only on this page. They never become retained evidence.
  const [report, setReport] = useState<ScanResult | null>(null);
  if (report) return <OverviewDashboard initialReport={report} onExitReport={() => setReport(null)} />;
  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">Get started</h1>
        <Link href="/" className="text-sm text-emerald-800 dark:text-emerald-300">Back to Overview</Link>
      </header>
      <FirstScanGuide onImport={setReport} />
    </div>
  );
}
