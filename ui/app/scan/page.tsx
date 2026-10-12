"use client";

/**
 * Scan page — slim router that delegates to extracted components.
 * Previously 1,944 lines; now ~30 lines.
 */

import { Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { Loader2 } from "lucide-react";
import { ScanForm } from "@/components/scan-form";
import { ScanResultView } from "@/components/scan-result";
import { ScanInvestigationEntry } from "@/components/scan-investigation-entry";

function ScanRouter() {
  const searchParams = useSearchParams();
  const id = searchParams.get("id") || "";
  const view = searchParams.get("view") || "";

  if (id && (view === "attack-flow" || view === "mesh")) return <ScanInvestigationEntry id={id} path={view === "attack-flow"} />;
  if (id) return <ScanResultView id={id} />;
  return (
    <ScanForm
      initialConnectionId={searchParams.get("connection") || undefined}
      initialPreset={searchParams.get("preset") || undefined}
    />
  );
}

export default function ScanPage() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center h-[50vh] text-[var(--text-secondary)]">
          <Loader2 className="w-5 h-5 animate-spin mr-2" />Loading...
        </div>
      }
    >
      <ScanRouter />
    </Suspense>
  );
}
