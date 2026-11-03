"use client";

import { Suspense } from "react";
import dynamic from "next/dynamic";
import { useSearchParams } from "next/navigation";
import { Loader2 } from "lucide-react";
import { useAuthState } from "@/components/auth-provider";
import { GraphSurface } from "@/app/graph/graph-surface";
import { GraphPanelSkeleton } from "@/components/graph-state-panels";
import { resolveSecurityGraphSurface } from "@/lib/security-graph-route";

// Inventory navigation must not download the separate attack-path workspace.
const AttackPathInvestigationContent = dynamic(() => import("./attack-path-content"), {
  ssr: false,
  loading: () => <GraphPanelSkeleton title="Loading attack paths" detail="Preparing the recorded path investigation." />,
});

function SecurityGraphPageContent() {
  const { session } = useAuthState();
  const searchParams = useSearchParams();
  return resolveSecurityGraphSurface(searchParams) === "attack-path"
    ? <AttackPathInvestigationContent key={JSON.stringify(session)} />
    : <GraphSurface />;
}

export default function SecurityGraphPage() {
  return (
    <Suspense fallback={<div className="flex min-h-[40vh] items-center justify-center"><Loader2 className="h-8 w-8 animate-spin text-[color:var(--text-secondary)]" /></div>}>
      <SecurityGraphPageContent />
    </Suspense>
  );
}
