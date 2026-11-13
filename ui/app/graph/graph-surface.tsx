"use client";

import { FindingInvestigationContext } from "@/components/finding-investigation-context";
import { GraphSnapshotUpdates } from "@/components/graph-snapshot-updates";
import { useSearchParams } from "next/navigation";
import { useAuthState } from "@/components/auth-provider";
import { GraphViewNotFound } from "@/components/graph-view-not-found";
import { unknownGraphViewParam } from "@/lib/graph-view-params";
import GraphPageClient from "./graph-page-client";

/** All graph entry points use one canvas, scope model and evidence inspector. */
export function GraphSurface() {
  const { session } = useAuthState();
  const params = useSearchParams();
  if (unknownGraphViewParam(params)) return <GraphViewNotFound />;
  if (!session) return <p role="status" className="p-4">Resolving access to investigation evidence…</p>;
  // Preserve the canvas during token refresh, but never carry loaded evidence
  // into another authenticated owner or across logout.
  const owner = JSON.stringify([session.tenant_id, session.subject, session.auth_method]);
  return <div key={owner}><FindingInvestigationContext /><GraphSnapshotUpdates /><GraphPageClient /></div>;
}
